#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/common/base64.h"
#include "source/common/config/datasource.h"
#include "source/common/config/utility.h"

#include "contrib/sgx/private_key_providers/source/sgx_private_key_provider.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

void SgxPrivateKeyMethodProvider::initializeRpc(const SgxPrivateKeyMethodConfig& config,
                                                TransportSocketFactoryContext& context) {
  const envoy::config::core::v3::ApiConfigSource& api_config_source =
      config.sds_config().api_config_source();

  // Create async client
  // TODO: change the value
  const std::string& sds_config_name = "sgx_config_name";
  Stats::Store& stats = context.stats();
  Stats::ScopeSharedPtr scope = stats.createScope(absl::StrCat("sds.", sds_config_name, "."));
  Grpc::AsyncClientFactoryPtr async_client_factory = Config::Utility::factoryForGrpcApiConfigSource(
      context.clusterManager().grpcAsyncClientManager(), api_config_source, *scope, true);
  ENVOY_LOG(trace, "sgx private key provider: async_client_factory has been created");

  Grpc::RawAsyncClientSharedPtr async_client = async_client_factory->createUncachedRawAsyncClient();
  ENVOY_LOG(trace, "sgx private key provider: async_client has been created");

  client_ = std::make_unique<SgxRpcStreamImpl>(async_client, *std::make_unique<SgxRpcCallbacks>());
  auto stream = client_->start();
  // TODO: support retrying
  if (stream == nullptr) {
    throw EnvoyException("Unable to establish new stream");
  }

  ENVOY_LOG(debug, "sgx private key provider: grpc channel has been established");
}

void SgxPrivateKeyMethodProvider::initializeSgxEnclave() {
  CK_RV status = sgx_context_->sgxInit();
  if (status != CKR_OK) {
    throw EnvoyException("Failed to initialize sgx enclave.");
  }
}

void SgxPrivateKeyMethodProvider::initializeKeypair() {
  CK_RV status = CKR_OK;

  CK_ULONG object_count = 0;
  status = sgx_context_->findKeyPair(&private_key_, &public_key_, key_label_, object_count);

  if (status != CKR_OK || object_count != 1) {
    if (stage_ == "cert") {
      throw EnvoyException("Failed to find keypair in sgx.");
    }

    // stage_ == "init"
    if (object_count == 0) {
      if (key_type_ == "rsa") {
        int key_size = stoi(rsa_key_size_);
        status = sgx_context_->createRsaKeyPair(&private_key_, &public_key_, key_label_, key_size);
        if (status != CKR_OK) {
          throw EnvoyException("Failed to create RSA keypair.");
        }
      } else if (key_type_ == "ecdsa") {
        status = sgx_context_->createEcdsaKeyPair(&private_key_, &public_key_, key_label_,
                                                  ecdsa_key_param_);
        if (status != CKR_OK) {
          throw EnvoyException("Failed to create ECDSA keypair.");
        }
      }
    }
  }
}

void SgxPrivateKeyMethodProvider::createCSR() {
  CK_RV status = CKR_OK;

  std::string csr_config_filename = "/etc/sgx/";
  if (::access(csr_config_filename.c_str(), 0) != 0) {
    if (::mkdir(csr_config_filename.c_str(), 0) != 0) {
      throw EnvoyException("Failed to create path in " + csr_config_filename);
    } else {
      ENVOY_LOG(debug, "sgx private key provider: created dir " + csr_config_filename);
    }
  }
  csr_config_filename += "pkcs11.conf";
  std::ofstream output_file(csr_config_filename, std::ios::trunc);
  if (!output_file.is_open()) {
    throw EnvoyException("Failed to open openssl config in " + csr_config_filename);
  }
  std::string v3_req = "[v3_req]";
  std::size_t pos = csr_config_.find(v3_req);
  if (pos == std::string::npos) {
    throw EnvoyException("Failed to search v3_req filed in openssl config: " + csr_config_filename);
  } else {
    pos += v3_req.size();
    std::string new_csr_config = csr_config_.substr(0, pos) + "\n";
    std::string value = Base64::encode(quote_.c_str(), quote_.size());
    ENVOY_LOG(debug, "The quote: {}", value);
    new_csr_config += quote_key_ + " = ASN1:UTF8String:" + value + "\n";
    value = Base64::encode(quotepub_.c_str(), quotepub_.size());
    ENVOY_LOG(debug, "The quote public key: {}", value);
    new_csr_config += quotepub_key_ + " = ASN1:UTF8String:" + value + csr_config_.substr(pos);
    output_file << new_csr_config;
  }
  output_file.close();

  std::string csr_filename = "/etc/sgx/pkcs11.csr";

  std::string subj = "/CN=";

  ENVOY_LOG(debug, "sgx private key provider: the CSR file does not exist. Now create it.");

  status = sgx_context_->createCSR(subj, key_label_, csr_filename);
  if (status != CKR_OK) {
    throw EnvoyException("Failed to create CSR.");
  }

  std::remove(csr_config_filename.c_str());
}

void SgxPrivateKeyMethodProvider::createQuote() {
  CK_RV status = CKR_OK;
  std::string quotekey = "quote";
  CK_OBJECT_HANDLE private_key_temp;
  CK_OBJECT_HANDLE public_key_temp;
  status = sgx_context_->createRsaKeyPair(&private_key_temp, &public_key_temp, quotekey,
                                          stoi(rsa_key_size_), false);
  if (status != CKR_OK) {
    throw EnvoyException("Failed to create tmp rsa keypair.");
  }

  ByteString quote;
  ByteString quotepub;
  status = sgx_context_->createQuote(public_key_temp, &quote, &quotepub);
  if (status != CKR_OK) {
    throw EnvoyException("Failed to create Quote.");
  }

  quote_ = quote.to_str();
  quotepub_ = quotepub.to_str();
  free(quotepub.bytes);
  free(quote.bytes);
}

void SgxPrivateKeyMethodProvider::sendCSRandQuote() {
  CsrAndQuoteRequest req;
  std::string csr_filename = "/etc/sgx/pkcs11.csr";

  std::ifstream csr_file(csr_filename, std::ios::in | std::ios::binary);
  if (!csr_file) {
    throw EnvoyException("sgx private key provider: open CSR file error");
  }

  ENVOY_LOG(debug, "sgx private key provider: read CSR file from disk");

  std::stringstream buf;
  buf << csr_file.rdbuf();
  csr_file.close();

  req.set_csr(buf.str());

  client_->send(std::move(req), false);
}

void SgxPrivateKeyMethodProvider::initialize(
    const envoy::extensions::private_key_providers::sgx::v3alpha::SgxPrivateKeyMethodConfig& config,
    Server::Configuration::TransportSocketFactoryContext& context) {

  initializeSgxEnclave();
  ENVOY_LOG(debug, "sgx private key provider: initializeSgxEnclave() finished");

  initializeKeypair();
  ENVOY_LOG(debug, "sgx private key provider: initializeKeypair() finished");

  if (stage_ == "init") {

    std::string csr_filename = "/etc/sgx/pkcs11.csr";

    std::ifstream csr_file(csr_filename, std::ios::in | std::ios::binary);
    if (!csr_file.is_open()) {
      createQuote();
      ENVOY_LOG(debug, "sgx private key provider: createQuote() finished");

      createCSR();
      ENVOY_LOG(debug, "sgx private key provider: createCSR() finished");
    } else {
      ENVOY_LOG(debug, "sgx private key provider: the CSR file already exists. Skip.");
    }
    csr_file.close();

    initializeRpc(config, context);
    ENVOY_LOG(debug, "sgx private key provider: initializeRpc() finished");

    sendCSRandQuote();
    ENVOY_LOG(debug, "sgx private key provider: sendCSRandQuote() finished");
  }
}

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy

#include "contrib/transport_sockets/tls/cert_validator/extension/source/extension_validator.h"

#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/extensions/transport_sockets/tls/cert_validator/factory.h"
#include "source/extensions/transport_sockets/tls/stats.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include "contrib/envoy/extensions/transport_sockets/tls/cert_validator/extension/v3alpha/tls_extension_validator_config.pb.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using ExtensionConfig = envoy::extensions::transport_sockets::tls::v3::ExtensionCertValidatorConfig;

ExtensionValidator::ExtensionValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                       SslStats& stats, TimeSource& time_source)
    : stats_(stats), time_source_(time_source) {
  ASSERT(config != nullptr);

  auto default_cert_validator_name = "envoy.tls.cert_validator.default";
  auto default_cert_validator_factory =
      Registry::FactoryRegistry<CertValidatorFactory>::getFactory(default_cert_validator_name);

  if (!default_cert_validator_factory) {
    throw EnvoyException("Failed to get certificate validator factory for default cert validator");
  }
  default_cert_validator_ =
      default_cert_validator_factory->createCertValidator(config, stats_, time_source_);
  ASSERT(default_cert_validator_ != nullptr);

  ExtensionConfig message;
  Config::Utility::translateOpaqueConfig(config->customValidatorConfig().value().typed_config(),
                                         ProtobufMessage::getStrictValidationVisitor(), message);

  if (message.extensions().size() != 1) {
    // TODO: support multiple extensions
    throw EnvoyException("Currently extension validator can only be used to verify one extension "
                         "in peer certificate");
  }
  for (auto& extension : message.extensions()) {
    extension_key_ = extension.key();
    extension_value_ = extension.value();
    break;
  }
}

void ExtensionValidator::addClientValidationContext(SSL_CTX* ctx, bool require_client_cert) {
  default_cert_validator_->addClientValidationContext(ctx, require_client_cert);
}

void ExtensionValidator::updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md,
                                                  uint8_t hash_buffer[EVP_MAX_MD_SIZE],
                                                  unsigned hash_length) {
  default_cert_validator_->updateDigestForSessionId(md, hash_buffer, hash_length);
}

int ExtensionValidator::initializeSslContexts(std::vector<SSL_CTX*> contexts,
                                              bool handshaker_provides_certificates) {
  return default_cert_validator_->initializeSslContexts(contexts, handshaker_provides_certificates);
}

int ExtensionValidator::doSynchronousVerifyCertChain(
    X509_STORE_CTX* store_ctx, Ssl::SslExtendedSocketInfo* ssl_extended_info, X509& leaf_cert,
    const Network::TransportSocketOptions* transport_socket_options) {

  if (!extension_key_.empty()) {
    bool extension_exists = false;
    auto value_from_cert =
        getCertificateExtensionUTF8StringValue(leaf_cert, extension_key_, &extension_exists);
    if (!extension_exists || extension_value_ != value_from_cert) {
      // Envoy::Ssl::ClientValidationStatus::Failed
      ENVOY_LOG_TO_LOGGER(
          Logger::Registry::getLog(Logger::Id::connection), info,
          "There is no customized certificate extension in peer certificate or it's invalid");
      return 0;
    }
  } else {
    // Envoy::Ssl::ClientValidationStatus::Failed
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::connection), info,
                        "The value of key cannot be empty");
    return 0;
  }

  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::connection), info,
                      "The customized certificate extension has been verified");

  return default_cert_validator_->doSynchronousVerifyCertChain(store_ctx, ssl_extended_info, leaf_cert,
                                                    transport_socket_options);
}

absl::optional<uint32_t> ExtensionValidator::daysUntilFirstCertExpires() const {
  return default_cert_validator_->daysUntilFirstCertExpires();
}

Envoy::Ssl::CertificateDetailsPtr ExtensionValidator::getCaCertInformation() const {
  return default_cert_validator_->getCaCertInformation();
};

std::string ExtensionValidator::getCaFileName() const {
  return default_cert_validator_->getCaFileName();
}

std::string ExtensionValidator::getCertificateExtensionUTF8StringValue(
    X509& cert, const std::string& extension_name, bool* extension_exists) {
  std::string output{};
  *extension_exists = false;
  bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj(extension_name.c_str(), 1 /* don't search names */));
  if (oid == nullptr) {
    return output;
  }

  int pos = X509_get_ext_by_OBJ(&cert, oid.get(), -1);
  if (pos < 0) {
    return output;
  }

  X509_EXTENSION* extension = X509_get_ext(&cert, pos);
  if (extension == nullptr) {
    return output;
  }

  const ASN1_OCTET_STRING* octet_string = X509_EXTENSION_get_data(extension);
  RELEASE_ASSERT(octet_string != nullptr, "");

  const auto* asn1_string = reinterpret_cast<const ASN1_STRING*>(octet_string);
  bssl::UniquePtr<ASN1_UTF8STRING> utf8_string(static_cast<ASN1_UTF8STRING*>(
      ASN1_item_unpack(asn1_string, ASN1_ITEM_rptr(ASN1_UTF8STRING))));
  if (utf8_string == nullptr) {
    return output;
  }

  *extension_exists = true;
  return reinterpret_cast<char*>(utf8_string->data);
}

class ExtensionValidatorFactory : public CertValidatorFactory {
public:
  CertValidatorPtr createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                       SslStats& stats, TimeSource& time_source) override {

    return std::make_unique<ExtensionValidator>(config, stats, time_source);
  }

  std::string name() const override { return "envoy.tls.cert_validator.extension"; }
};

REGISTER_FACTORY(ExtensionValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

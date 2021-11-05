#include "contrib/sgx/private_key_providers/source/sgx_private_key_provider.h"

#include <memory>
#include <string>
#include <utility>

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/config/datasource.h"

#include "openssl/ec.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

SINGLETON_MANAGER_REGISTRATION(sgx_context_singleton);

SgxPrivateKeyConnection::SgxPrivateKeyConnection(Ssl::PrivateKeyConnectionCallbacks& cb,
                                                 Event::Dispatcher& dispatcher,
                                                 SgxContextSharedPtr sgx_context,
                                                 bssl::UniquePtr<EVP_PKEY> pkey,
                                                 CK_OBJECT_HANDLE private_key,
                                                 CK_OBJECT_HANDLE public_key)
    : dispatcher_(dispatcher), cb_(cb), pkey_(std::move(pkey)) {
  sgx_context_ = std::move(sgx_context);
  private_key_ = private_key;
  public_key_ = public_key;
}

void SgxPrivateKeyMethodProvider::registerPrivateKeyMethod(SSL* ssl,
                                                           Ssl::PrivateKeyConnectionCallbacks& cb,
                                                           Event::Dispatcher& dispatcher) {

  if (SSL_get_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex()) != nullptr) {
    throw EnvoyException("Registering the Sgx provider twice for same context "
                         "is not yet supported.");
  }

  //    ASSERT(tls_->currentThreadRegistered(), "Current thread needs to be registered.");

  auto* ops = new SgxPrivateKeyConnection(cb, dispatcher, sgx_context_, bssl::UpRef(pkey_),
                                          private_key_, public_key_);
  SSL_set_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex(), ops);

  ENVOY_LOG(debug,
            "sgx private key provider: PrivateKeyMethod has been registered to dispatcher: {}",
            dispatcher.name());
}

bool SgxPrivateKeyMethodProvider::checkFips() { return true; }

Ssl::BoringSslPrivateKeyMethodSharedPtr
SgxPrivateKeyMethodProvider::getBoringSslPrivateKeyMethod() {
  return method_;
}

void SgxPrivateKeyMethodProvider::unregisterPrivateKeyMethod(SSL* ssl) {
  auto* ops = static_cast<SgxPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex()));
  SSL_set_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex(), nullptr);

  delete ops;

  ENVOY_LOG(debug, "sgx private key provider: PrivateKeyMethod has been unregistered");
}

SgxPrivateKeyMethodProvider::SgxPrivateKeyMethodProvider(
    const envoy::extensions::private_key_providers::sgx::v3alpha::SgxPrivateKeyMethodConfig& config,
    Server::Configuration::TransportSocketFactoryContext& factory_context, const SgxSharedPtr& sgx)
    : api_(factory_context.api()),
      tls_(ThreadLocal::TypedSlot<ThreadLocalData>::makeUnique(factory_context.threadLocal())),
      sgx_library_(config.sgx_library()), key_label_(config.key_label()),
      usr_pin_(config.usr_pin()), so_pin_(config.so_pin()), token_label_(config.token_label()),
      stage_(config.stage()), key_type_(config.key_type()), rsa_key_size_(config.rsa_key_size()),
      ecdsa_key_param_(config.ecdsa_key_param()), csr_config_(config.csr_config()),
      quote_key_(config.quote_key()), quotepub_key_(config.quotepub_key()) {

  private_key_ = 0;
  public_key_ = 0;

  ENVOY_LOG(debug,
            "sgx private key provider: Configurations:"
            "sgx_library_({}), "
            "key_label_({}), "
            "usr_pin_({}), "
            "so_pin_({}), "
            "token_label_({}), "
            "stage_({}), "
            "key_type_({}), "
            "rsa_key_size_({}), "
            "ecdsa_key_param_({}), "
            "csr_config_({}), "
            "quote_key_({}), "
            "quotepub_key_({}), ",
            sgx_library_, key_label_, usr_pin_, so_pin_, token_label_, stage_, key_type_,
            rsa_key_size_, ecdsa_key_param_, csr_config_, quote_key_, quotepub_key_);

  if (!isValidString(key_label_) || !isValidString(usr_pin_) || !isValidString(so_pin_) ||
      !isValidString(token_label_) || !isValidString(stage_) || !isValidString(key_type_) ||
      !isValidString(rsa_key_size_) || !isValidString(ecdsa_key_param_)) {
    throw EnvoyException("The configs can only contain 'a-zA-Z0-9', '-', '_', '/' or '='.");
  }

  method_ = std::make_shared<SSL_PRIVATE_KEY_METHOD>();
  if (key_type_ == "rsa") {
    method_->sign = rsaSignWithSgx;
    method_->decrypt = rsaDecryptWithSgx;
    method_->complete = completeWithSgx;
  } else if (key_type_ == "ecdsa") {
    method_->sign = ecdsaSignWithSgx;
    method_->decrypt = ecdsaDecryptWithSgx;
    method_->complete = completeWithSgx;
  } else {
    throw EnvoyException("Not supported key type, only RSA and ECDSA are supported.");
  }

  sgx_context_ = factory_context.singletonManager().getTyped<SGXContext>(
      SINGLETON_MANAGER_REGISTERED_NAME(sgx_context_singleton), [this] {
        return std::make_shared<SGXContext>(sgx_library_, token_label_, so_pin_, usr_pin_);
      });

  initialize(config, factory_context);
  ENVOY_LOG(debug, "sgx private key provider: {} has been Created", sgx->name());
}

namespace {
int createIndex() {
  int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  RELEASE_ASSERT(index >= 0, "Failed to get SSL user data index.");
  return index;
}
} // namespace

int SgxPrivateKeyMethodProvider::connectionIndex() { CONSTRUCT_ON_FIRST_USE(int, createIndex()); }

SgxPrivateKeyMethodProvider::ThreadLocalData::ThreadLocalData(std::chrono::milliseconds,
                                                              enum KeyType, int,
                                                              const SgxSharedPtr&,
                                                              Event::Dispatcher&) {}

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy

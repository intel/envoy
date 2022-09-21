#pragma once

#include <string>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/common/c_smart_ptr.h"
#include "source/common/common/matchers.h"
#include "source/extensions/transport_sockets/tls/cert_validator/cert_validator.h"
#include "source/extensions/transport_sockets/tls/stats.h"

#include "openssl/ssl.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using X509StorePtr = CSmartPtr<X509_STORE, X509_STORE_free>;

class ExtensionValidator : public CertValidator {
public:
  ExtensionValidator(SslStats& stats, TimeSource& time_source)
      : stats_(stats), time_source_(time_source){};

  ExtensionValidator(const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
                     TimeSource& time_source);

  ~ExtensionValidator() override = default;

  // Tls::CertValidator
  void addClientValidationContext(SSL_CTX* context, bool require_client_cert) override;

  int doSynchronousVerifyCertChain(X509_STORE_CTX* store_ctx, Ssl::SslExtendedSocketInfo* ssl_extended_info,
                        X509& leaf_cert,
                        const Network::TransportSocketOptions* transport_socket_options) override;

  int initializeSslContexts(std::vector<SSL_CTX*> contexts, bool provides_certificates) override;

  void updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t hash_buffer[EVP_MAX_MD_SIZE],
                                unsigned hash_length) override;

  absl::optional<uint32_t> daysUntilFirstCertExpires() const override;

  std::string getCaFileName() const override;

  Envoy::Ssl::CertificateDetailsPtr getCaCertInformation() const override;

private:
  static std::string getCertificateExtensionUTF8StringValue(X509& cert,
                                                            const std::string& extension_name,
                                                            bool* extension_exists);

  SslStats& stats_;
  TimeSource& time_source_;

  CertValidatorPtr default_cert_validator_;
  std::string extension_key_;
  std::string extension_value_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

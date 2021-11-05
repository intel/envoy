#include <string>

#include "envoy/server/transport_socket_config.h"

#include "contrib/sgx/private_key_providers/source/sgx.h"
#include "contrib/sgx/private_key_providers/source/sgx_private_key_provider.h"
#include "openssl/ec.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

ssl_private_key_result_t rsaSignWithSgx(SSL* ssl, uint8_t* out, size_t* out_len, size_t,
                                        uint16_t signature_algorithm, const uint8_t* in,
                                        size_t in_len) {

  auto* ops = static_cast<SgxPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex()));
  if (!ops) {
    return ssl_private_key_failure;
  }

  int hash;
  bool is_pss;

  if (signature_algorithm == SSL_SIGN_RSA_PSS_RSAE_SHA256) {
    hash = 256;
    is_pss = true;
  } else if (signature_algorithm == SSL_SIGN_RSA_PSS_RSAE_SHA384) {
    hash = 384;
    is_pss = true;
  } else if (signature_algorithm == SSL_SIGN_RSA_PSS_RSAE_SHA512) {
    hash = 512;
    is_pss = true;
  } else if (signature_algorithm == SSL_SIGN_RSA_PKCS1_SHA256) {
    hash = 256;
    is_pss = false;
  } else if (signature_algorithm == SSL_SIGN_RSA_PKCS1_SHA384) {
    hash = 384;
    is_pss = false;
  } else if (signature_algorithm == SSL_SIGN_RSA_PKCS1_SHA512) {
    hash = 512;
    is_pss = false;
  } else {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), error,
                        "sgx private key provider: cannot handle signature_algorithm {}",
                        signature_algorithm);
    return ssl_private_key_failure;
  }

  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "sgx private key provider: signature_algorithm {}", signature_algorithm);

  CK_RV status = CKR_OK;
  ByteString signature;

  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    status = ops->sgx_context_->rsaSign(ops->private_key_, ops->public_key_, is_pss, hash, in,
                                        in_len, &signature);
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider: rsa_pss: true");

    if (status != CKR_OK) {
      ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                          "sgx private key provider: RSA sign failed: {}", status);
      return ssl_private_key_failure;
    } else {
      ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                          "sgx private key provider: RSA sign successfully");
    }
  } else {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider: rsa_pss: false");
  }

  memcpy(out, signature.bytes, signature.byte_size); // NOLINT(safe-memcpy)
  free(signature.bytes);
  *out_len = signature.byte_size;

  return ssl_private_key_success;
}

ssl_private_key_result_t rsaDecryptWithSgx(SSL* ssl, uint8_t* out, size_t* out_len, size_t,
                                           const uint8_t* in, size_t in_len) {
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "sgx private key provider: rsaDecryptWithSgx()");

  auto* ops = static_cast<SgxPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex()));
  if (!ops) {
    return ssl_private_key_failure;
  }

  CK_RV status = CKR_OK;
  ByteString decrypted;

  status = ops->sgx_context_->rsaDecrypt(ops->private_key_, in, in_len, &decrypted);
  if (status != CKR_OK) {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider: rsaDecryptWithSgx failed: {}", status);
    return ssl_private_key_failure;
  } else {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider:: rsaDecryptWithSgx successfully, size: {}",
                        decrypted.byte_size);
  }

  memcpy(out, decrypted.bytes, decrypted.byte_size); // NOLINT(safe-memcpy)
  free(decrypted.bytes);
  *out_len = decrypted.byte_size;

  return ssl_private_key_success;
}

static int calculateDigest(const EVP_MD* md, const uint8_t* in, size_t in_len, unsigned char* hash,
                           unsigned int* hash_len) {
  bssl::ScopedEVP_MD_CTX ctx;

  // Calculate the message digest for signing.
  if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), in, in_len) ||
      !EVP_DigestFinal_ex(ctx.get(), hash, hash_len)) {
    return 0;
  }
  return 1;
}

ssl_private_key_result_t ecdsaSignWithSgx(SSL* ssl, uint8_t* out, size_t* out_len, size_t max_out,
                                          uint16_t signature_algorithm, const uint8_t* in,
                                          size_t in_len) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  CK_RV status;
  ByteString signature;

  auto* ops = static_cast<SgxPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, SgxPrivateKeyMethodProvider::connectionIndex()));

  if (ops == nullptr) {
    return ssl_private_key_failure;
  }

  const EVP_MD* md = SSL_get_signature_algorithm_digest(signature_algorithm);
  if (md == nullptr) {
    return ssl_private_key_failure;
  }
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "sgx private key provider: md: {}", EVP_MD_type(md));
  if (!calculateDigest(md, in, in_len, hash, &hash_len)) {
    return ssl_private_key_failure;
  }

  status =
      ops->sgx_context_->ecdsaSign(ops->private_key_, ops->public_key_, hash, hash_len, &signature);

  if (status != CKR_OK) {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider: ECDSA sign failed");
    return ssl_private_key_failure;
  } else {
    ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                        "sgx private key provider: ECDSA sign successfully, size: {}",
                        signature.byte_size);
  }

  int len = int(signature.byte_size / 2);

  BIGNUM* r = BN_bin2bn(signature.bytes, len, nullptr);
  BIGNUM* s = BN_bin2bn(signature.bytes + len, len, nullptr);

  free(signature.bytes);

  ECDSA_SIG* sig = ECDSA_SIG_new();
  if (sig == nullptr) {
    return ssl_private_key_failure;
  }
  ECDSA_SIG_set0(sig, r, s);

  signature.bytes = nullptr;
  signature.byte_size = i2d_ECDSA_SIG(sig, &signature.bytes);

  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "sgx private key provider: SGX ecdsa sign der size: {}", signature.byte_size);

  if (signature.byte_size > max_out) {
    return ssl_private_key_failure;
  }
  memcpy(out, signature.bytes, signature.byte_size); // NOLINT(safe-memcpy)
  *out_len = signature.byte_size;

  ECDSA_SIG_free(sig);

  return ssl_private_key_success;
}

ssl_private_key_result_t ecdsaDecryptWithSgx(SSL*, uint8_t*, size_t*, size_t, const uint8_t*,
                                             size_t) {
  // Expecting to get only signing requests.
  return ssl_private_key_failure;
}

ssl_private_key_result_t completeWithSgx(SSL*, uint8_t*, size_t*, size_t) {
  return ssl_private_key_success;
}

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy

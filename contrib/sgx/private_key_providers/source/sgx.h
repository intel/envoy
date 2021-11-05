#pragma once

#include <cryptoki.h>
#include <dlfcn.h>
#include <sgx_pce.h>

#include <cstring>
#include <string>

#include "envoy/common/pure.h"
#include "envoy/singleton/manager.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"

#include "contrib/sgx/private_key_providers/source/utility.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

class Sgx {
public:
  ~Sgx() = default;

  static std::string name() { return "sgx"; };
};

using SgxSharedPtr = std::shared_ptr<Sgx>;

const int defaultRSAKeySize = 3072;
const int maxTokenLabelSize = 32;
const int maxKeyLabelSize = 32;
const int maxSignatureSize = 2048;
const std::string osslCsrCmd =
    "OPENSSL_CONF=/etc/sgx/pkcs11.conf openssl req -new -engine pkcs11 -keyform engine -sha256";

struct ByteString {
  CK_ULONG byte_size;
  CK_BYTE_PTR bytes;

  ByteString() {
    bytes = NULL_PTR;
    byte_size = 0;
  }

  std::string to_str() const {
    return std::string(reinterpret_cast<const char*>(bytes), byte_size);
  }
};

/**
 * Represents a single SGX operation context.
 */
class SGXContext : public Logger::Loggable<Logger::Id::secret>, public Singleton::Instance {
public:
  SGXContext(std::string libpath, std::string token_label, std::string sopin, std::string user_pin);

  ~SGXContext() override;

  CK_RV sgxInit();

  CK_RV createRsaKeyPair(CK_OBJECT_HANDLE_PTR private_key, CK_OBJECT_HANDLE_PTR pubkey,
                         std::string& key_label, int key_size = defaultRSAKeySize,
                         bool on_token = true);

  CK_RV findKeyPair(CK_OBJECT_HANDLE_PTR private_key, CK_OBJECT_HANDLE_PTR pubkey,
                    std::string& key_label, CK_ULONG& object_count, bool verbose = true);

  //  CK_RV deleteKeyPair(std::string &key_label);

  CK_RV rsaSign(CK_OBJECT_HANDLE private_key, CK_OBJECT_HANDLE pubkey, bool is_pss, int hash,
                const uint8_t* in, size_t in_len, ByteString* signature);

  CK_RV rsaDecrypt(CK_OBJECT_HANDLE private_key, const uint8_t* in, size_t in_len,
                   ByteString* decrypted);

  //  CK_RV rsaEncrypt(CK_OBJECT_HANDLE pubkey, const uint8_t *in, size_t inlen, ByteString
  //  *encrypted);

  CK_RV createCSR(std::string& subj, std::string& key_label, std::string& out) const;

  CK_RV createQuote(CK_OBJECT_HANDLE pubkey, ByteString* quote, ByteString* quote_pub);

  CK_RV
  createEcdsaKeyPair(CK_OBJECT_HANDLE_PTR private_key, CK_OBJECT_HANDLE_PTR pubkey,
                     std::string& key_label, std::string& curve);

  CK_RV ecdsaSign(CK_OBJECT_HANDLE private_key, CK_OBJECT_HANDLE pubkey, const uint8_t* in,
                  size_t in_len, ByteString* signature);

private:
  Thread::MutexBasicLockable lock_{};

  CK_RV getP11FunctionListFromLib();

  CK_RV findKey(CK_OBJECT_HANDLE_PTR objecthandle, CK_ATTRIBUTE* templateattribs,
                CK_ULONG attribscount, CK_ULONG& object_count);

  CK_RV initToken();

  static CK_ULONG quoteOffset(CK_BYTE_PTR bytes);

  static void logQuote(CK_BYTE_PTR bytes);

  // CK_RV generatequote();

  static CK_RV allocAndCopyBytes(CK_BYTE_PTR* dest, CK_BYTE_PTR src, CK_ULONG size);

  std::string libpath_;
  std::string tokenlabel_;
  std::string sopin_;
  std::string userpin_;
  CK_SLOT_ID slotid_;
  CK_SESSION_HANDLE sessionhandle_;
  CK_FUNCTION_LIST_PTR p11_;
  //  ByteString *quote_;
  //  ByteString *quotepub_;

  bool initialized_;
};

// class SgxImpl : public virtual Sgx {
// public:
//     std::string name() const { return "sgx"; } ;
// };

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy

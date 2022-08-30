#include "contrib/sgx/private_key_providers/source/sgx.h"

#include "QuoteGeneration.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

#define ERROR_CODE_TO_STRING(x) #x
#define DIM(x) (sizeof(x) / sizeof((x)[0]))

SGXContext::SGXContext(std::string libpath, std::string token_label, std::string sopin,
                       std::string user_pin)
    : libpath_(std::move(libpath)), tokenlabel_(std::move(token_label)), sopin_(std::move(sopin)),
      userpin_(std::move(user_pin)), slotid_(0), sessionhandle_(CK_INVALID_HANDLE), p11_(NULL_PTR),
      initialized_(false) {}

SGXContext::~SGXContext() {
  if (p11_ != NULL_PTR && sessionhandle_ != CK_INVALID_HANDLE) {
    CK_RV ret = p11_->C_CloseSession(sessionhandle_);
    if (ret != CKR_OK) {
      ENVOY_LOG(debug, "Error during p11->C_CloseSession: {}.\n", ERROR_CODE_TO_STRING(ret));
    }
  }

  if (p11_ != NULL_PTR) {
    CK_RV ret = p11_->C_Finalize(NULL_PTR);
    if (ret != CKR_OK) {
      ENVOY_LOG(debug, "Error during p11->C_Finalize: {}.\n", ERROR_CODE_TO_STRING(ret));
    }
  }
}

CK_RV SGXContext::sgxInit() {
  Thread::LockGuard handle_lock(lock_);

  CK_RV status = CKR_OK;

  if (initialized_) {
    ENVOY_LOG(debug, "sgx: The enclave has already been initialized. Return directly.");
    return status;
  }
  ENVOY_LOG(debug, "sgx: The enclave has not been initialized. Now we are going to initialize it.");

  if (libpath_.empty() || tokenlabel_.empty() || sopin_.empty() || userpin_.empty() ||
      tokenlabel_.size() > maxTokenLabelSize) {
    ENVOY_LOG(debug, "SGXContext parameters error.\n");
    status = CKR_ARGUMENTS_BAD;
    return status;
  }

  status = getP11FunctionListFromLib();
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Could not initialize p11 function pointer.\n");
    return status;
  }

  status = p11_->C_Initialize(NULL_PTR);

  if (status != CKR_OK) {

    ENVOY_LOG(debug, "Error during p11->C_Initialize: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = initToken();
  if (status != CKR_OK) {

    ENVOY_LOG(debug, "Could not initialize token: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_OpenSession(slotid_, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
                               &sessionhandle_);
  if (status != CKR_OK) {

    ENVOY_LOG(debug, "Error during C_OpenSession: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_Login(sessionhandle_, CKU_USER, CK_UTF8CHAR_PTR(userpin_.c_str()),
                         strnlen(userpin_.c_str(), maxKeyLabelSize));

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during C_Login: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  initialized_ = true;

  return status;
}

CK_RV SGXContext::getP11FunctionListFromLib() {
  void* p11_provider_handle = NULL_PTR;
  CK_FUNCTION_LIST_PTR* p11 = &p11_;
  const char* p11_library_path = libpath_.c_str();
  p11_provider_handle = dlopen(p11_library_path, RTLD_NOW | RTLD_LOCAL);
  if (p11_provider_handle == NULL_PTR) {
    ENVOY_LOG(debug, "Could not open dlhandle with path '{}'.\n", p11_library_path);
    char* err_msg = dlerror();
    if (err_msg != NULL_PTR) {
      ENVOY_LOG(debug, "dlerror: {}.\n", err_msg);
    }
    return CKR_GENERAL_ERROR;
  }

  CK_C_GetFunctionList p_get_function_list =
      CK_C_GetFunctionList(dlsym(p11_provider_handle, "C_GetFunctionList"));
  char* err_msg = dlerror();
  if (p_get_function_list == NULL_PTR || err_msg != NULL_PTR) {
    ENVOY_LOG(debug, "Failed during C_GetFunctionList.\n");
    if (err_msg != NULL_PTR) {
      ENVOY_LOG(debug, "dlerror: {}\n", err_msg);
    }

    dlclose(p11_provider_handle);
    return CKR_GENERAL_ERROR;
  }

  (*p_get_function_list)(p11);

  if (p11 == NULL_PTR) {
    ENVOY_LOG(debug, "Could not initialize p11 function pointer.\n");

    dlclose(p11_provider_handle);
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}

CK_RV SGXContext::initToken() {
  CK_BBOOL token_present = CK_TRUE;
  CK_ULONG slot_count = 0;
  CK_SLOT_ID_PTR p_slot_list;
  char padded_token_label[maxTokenLabelSize];
  CK_RV status = CKR_OK;

  status = p11_->C_GetSlotList(token_present, NULL_PTR, &slot_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to get slot list: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  p_slot_list = static_cast<CK_SLOT_ID_PTR>(calloc(slot_count, sizeof(CK_SLOT_ID)));
  if (!p_slot_list) {
    ENVOY_LOG(debug, "Failed to allocate memory of slot list.\n");
    status = CKR_HOST_MEMORY;
    return status;
  }

  status = p11_->C_GetSlotList(token_present, p_slot_list, &slot_count);
  if (CKR_OK != status) {
    ENVOY_LOG(debug, "Failed to get slot list: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  memset(padded_token_label, ' ', maxTokenLabelSize);

  memcpy(padded_token_label, tokenlabel_.c_str(), // NOLINT(safe-memcpy)
         strnlen(tokenlabel_.c_str(), maxTokenLabelSize));

  CK_BBOOL slot_found = CK_FALSE;

  for (CK_ULONG i = 0; i < slot_count; i++) {
    CK_TOKEN_INFO tokenInfo;
    status = p11_->C_GetTokenInfo(p_slot_list[i], &tokenInfo);
    if (CKR_OK != status) {
      ENVOY_LOG(debug, "Failed to get slot token info: {}.\n", ERROR_CODE_TO_STRING(status));
      return status;
    }

    if (strncmp(reinterpret_cast<const char*>(const_cast<unsigned char*>(tokenInfo.label)),
                padded_token_label, maxTokenLabelSize) == 0) {
      slot_found = CK_TRUE;
      slotid_ = p_slot_list[i];
      break;
    }
  }

  if (slot_found) {
    ENVOY_LOG(debug, "INFO: Token found. slot id: {}\n", slotid_);
    return status;
  }
  ENVOY_LOG(debug, "INFO: Token not found.\n");

  for (CK_ULONG i = 0; i < slot_count; i++) {
    CK_TOKEN_INFO tokenInfo;
    status = p11_->C_GetTokenInfo(p_slot_list[i], &tokenInfo);
    if (CKR_OK != status) {
      ENVOY_LOG(debug, "Failed to get slot token info: {}.\n", ERROR_CODE_TO_STRING(status));
      return status;
    }
    if (!(CKF_TOKEN_INITIALIZED & tokenInfo.flags)) {
      slotid_ = p_slot_list[i];
      slot_found = CK_TRUE;
      ENVOY_LOG(debug, "INFO: Using free slot id: {}\n", slotid_);
    }
  }

  free(p_slot_list);

  if (!slot_found) {
    ENVOY_LOG(debug, "Could not find a free slot.\n");
    status = CKR_SLOT_ID_INVALID;
    return status;
  }

  const char* so_pin_str = sopin_.c_str();

  status =
      p11_->C_InitToken(slotid_, CK_UTF8CHAR_PTR(so_pin_str), strnlen(so_pin_str, maxKeyLabelSize),
                        CK_UTF8CHAR_PTR(padded_token_label));
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to create token: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_OpenSession(slotid_, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
                               &sessionhandle_);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed during C_OpenSession: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_Login(sessionhandle_, CKU_SO, CK_UTF8CHAR_PTR(so_pin_str),
                         strnlen(so_pin_str, maxKeyLabelSize));
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to login into so session(probably because of bad password).\n");
    return status;
  }

  const char* user_pin_str = userpin_.c_str();
  status = p11_->C_InitPIN(sessionhandle_, CK_UTF8CHAR_PTR(user_pin_str),
                           strnlen(user_pin_str, maxKeyLabelSize));
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to init user pin: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_Logout(sessionhandle_);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to logout: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_CloseSession(sessionhandle_);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_CloseSession: {}.\n", ERROR_CODE_TO_STRING(status));
  }

  status = p11_->C_Finalize(NULL_PTR);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Finalize: {}.\n", ERROR_CODE_TO_STRING(status));
  }

  status = p11_->C_Initialize(NULL_PTR);
  if (status != CKR_OK) {

    ENVOY_LOG(debug, "Error during p11->C_Initialize: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_GetSlotList(token_present, NULL_PTR, &slot_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to get slot list: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  p_slot_list = static_cast<CK_SLOT_ID_PTR>(calloc(slot_count, sizeof(CK_SLOT_ID)));
  if (!p_slot_list) {
    ENVOY_LOG(debug, "Failed to allocate memory of slot list.\n");
    status = CKR_HOST_MEMORY;
    return status;
  }

  status = p11_->C_GetSlotList(token_present, p_slot_list, &slot_count);
  if (CKR_OK != status) {
    ENVOY_LOG(debug, "Failed to get slot list: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  for (CK_ULONG i = 0; i < slot_count; i++) {
    CK_TOKEN_INFO tokenInfo;
    status = p11_->C_GetTokenInfo(p_slot_list[i], &tokenInfo);
    if (CKR_OK != status) {
      ENVOY_LOG(debug, "Failed to get slot token info: {}.\n", ERROR_CODE_TO_STRING(status));
      return status;
    }

    if (strncmp(reinterpret_cast<const char*>(const_cast<unsigned char*>(tokenInfo.label)),
                padded_token_label, maxTokenLabelSize) == 0) {
      slot_found = CK_TRUE;
      slotid_ = p_slot_list[i];
      break;
    }
  }

  free(p_slot_list);

  if (!slot_found) {
    ENVOY_LOG(debug, "Error: Token not found.\n");
    status = CKR_TOKEN_NOT_PRESENT;
    return status;
  }

  ENVOY_LOG(debug, "INFO: Token found. slot id {}\n", slotid_);
  ENVOY_LOG(debug, "Init Token successfully\n");
  return status;
}

CK_RV SGXContext::createRsaKeyPair(CK_OBJECT_HANDLE_PTR privkey, CK_OBJECT_HANDLE_PTR pubkey,
                                   std::string& keylabel, int key_size, bool ontoken) {
  CK_RV status = CKR_OK;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

  CK_BBOOL b_true = CK_TRUE;
  CK_KEY_TYPE rsa_key_type = CKK_RSA;
  CK_OBJECT_CLASS rsa_public_key_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS rsa_private_key_class = CKO_PRIVATE_KEY;
  CK_ULONG key_length = key_size;
  CK_BBOOL cka_token_state = ontoken ? CK_TRUE : CK_FALSE;

  const char* label = keylabel.c_str();

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE) || key_size > 16384 ||
      key_size < 2048 || key_size % 1024 != 0) {
    ENVOY_LOG(debug, "createRsaKeyPair parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  const size_t label_size = strnlen(label, maxKeyLabelSize);

  CK_ATTRIBUTE asym_public_key_attribs[] = {
      {CKA_ENCRYPT, &b_true, sizeof(b_true)},
      {CKA_VERIFY, &b_true, sizeof(b_true)},
      {CKA_WRAP, &b_true, sizeof(b_true)},
      {CKA_MODULUS_BITS, &key_length, sizeof(key_length)},
      {CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type)},
      {CKA_CLASS, &rsa_public_key_class, sizeof(rsa_public_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
      {CKA_TOKEN, &cka_token_state, sizeof(CK_BBOOL)},

  };

  CK_ATTRIBUTE asym_private_key_attribs[] = {
      {CKA_EXTRACTABLE, &b_true, sizeof(b_true)},
      {CKA_DECRYPT, &b_true, sizeof(b_true)},
      {CKA_SIGN, &b_true, sizeof(b_true)},
      {CKA_UNWRAP, &b_true, sizeof(b_true)},
      {CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type)},
      {CKA_CLASS, &rsa_private_key_class, sizeof(rsa_private_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
      {CKA_TOKEN, &cka_token_state, sizeof(CK_BBOOL)},
  };

  status = p11_->C_GenerateKeyPair(sessionhandle_, &mechanism, asym_public_key_attribs,
                                   DIM(asym_public_key_attribs), asym_private_key_attribs,
                                   DIM(asym_private_key_attribs), pubkey, privkey);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_GenerateKeyPair: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  } else {
    ENVOY_LOG(debug, "Create RSA keypair successfully!\n");
  }
  return status;
}

CK_RV SGXContext::createEcdsaKeyPair(CK_OBJECT_HANDLE_PTR private_key, CK_OBJECT_HANDLE_PTR pubkey,
                                     std::string& keylabel, std::string& curve) {
  CK_RV status = CKR_OK;
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BYTE oidP256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

  CK_BBOOL b_true = CK_TRUE;
  CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
  CK_BBOOL cka_token_state = CK_TRUE;

  const char* label = keylabel.c_str();

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE)) {
    ENVOY_LOG(debug, "createEcdsaKeyPair parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  const size_t label_size = strnlen(label, maxKeyLabelSize);

  CK_ATTRIBUTE asym_public_key_attribs[] = {
      {CKA_EC_PARAMS, NULL_PTR, 0},
      {CKA_ENCRYPT, &b_true, sizeof(b_true)},
      {CKA_VERIFY, &b_true, sizeof(b_true)},
      {CKA_WRAP, &b_true, sizeof(b_true)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_CLASS, &public_key_class, sizeof(public_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
      {CKA_TOKEN, &cka_token_state, sizeof(CK_BBOOL)},
  };

  CK_ATTRIBUTE asym_private_key_attribs[] = {
      {CKA_EXTRACTABLE, &b_true, sizeof(b_true)},
      {CKA_DECRYPT, &b_true, sizeof(b_true)},
      {CKA_SIGN, &b_true, sizeof(b_true)},
      {CKA_UNWRAP, &b_true, sizeof(b_true)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_CLASS, &private_key_class, sizeof(private_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
      {CKA_TOKEN, &cka_token_state, sizeof(CK_BBOOL)},
  };

  // We only support P256 ECDSA curves today.
  if (curve != "P-256") {
    ENVOY_LOG(debug, "createEcdsaKeyPair parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  asym_public_key_attribs[0].pValue = oidP256;
  asym_public_key_attribs[0].ulValueLen = sizeof(oidP256);

  status = p11_->C_GenerateKeyPair(sessionhandle_, &mechanism, asym_public_key_attribs,
                                   DIM(asym_public_key_attribs), asym_private_key_attribs,
                                   DIM(asym_private_key_attribs), pubkey, private_key);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_GenerateKeyPair: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  } else {
    ENVOY_LOG(debug, "Create ECDSA keypair successfully!\n");
  }
  return status;
}

CK_RV SGXContext::findKeyPair(CK_OBJECT_HANDLE_PTR privkey, CK_OBJECT_HANDLE_PTR pubkey,
                              std::string& keylabel, CK_ULONG& object_count, bool verbose) {
  CK_RV status = CKR_OK;
  CK_OBJECT_CLASS rsa_priv_key_class = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS rsa_pub_key_class = CKO_PUBLIC_KEY;
  const char* label = keylabel.c_str();
  const size_t label_size = strnlen(label, maxKeyLabelSize);

  CK_ATTRIBUTE rsa_priv_template[] = {
      {CKA_CLASS, &rsa_priv_key_class, sizeof(rsa_priv_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
  };
  status = findKey(privkey, rsa_priv_template, DIM(rsa_priv_template), object_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to find private key.\n");
    return status;
  }

  if (object_count == 0) {
    if (verbose) {
      ENVOY_LOG(debug, "Find no private key.\n");
    }
    return status;
  } else if (object_count == 1) {
    if (verbose) {
      ENVOY_LOG(debug, "Find private key successfully.\n");
    }
  } else {
    throw EnvoyException("Find multi private keys with the same name in the SGX enclave.");
  }

  CK_ATTRIBUTE rsa_pub_template[] = {
      {CKA_CLASS, &rsa_pub_key_class, sizeof(rsa_pub_key_class)},
      {CKA_LABEL, const_cast<char*>(label), label_size},
  };
  status = findKey(pubkey, rsa_pub_template, DIM(rsa_pub_template), object_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to find public key.\n");
    return status;
  }

  if (object_count == 0) {
    if (verbose) {
      ENVOY_LOG(info, "Find no public key.\n");
    }
    return status;
  } else if (object_count == 1) {
    if (verbose) {
      ENVOY_LOG(info, "Find public key successfully.\n");
    }
  } else {
    if (verbose) {
      ENVOY_LOG(info, "Find multi public key.\n");
    }
    return status;
  }

  return status;
}

CK_RV SGXContext::findKey(CK_OBJECT_HANDLE_PTR object_handle, CK_ATTRIBUTE* template_attribs,
                          CK_ULONG attribs_count, CK_ULONG& object_count) {
  CK_RV status;
  object_count = 0;
  const CK_ULONG expected_obj_count = 1;

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE) || !object_handle ||
      !template_attribs) {
    ENVOY_LOG(debug, "findKey parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  status = p11_->C_FindObjectsInit(sessionhandle_, template_attribs, attribs_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to init Find objects: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_FindObjects(sessionhandle_, object_handle, expected_obj_count, &object_count);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to find objects in token: {}.\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_FindObjectsFinal(sessionhandle_);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Failed to finalize finding objects: {}.\n", ERROR_CODE_TO_STRING(status));
  }
  return status;
}

CK_ULONG SGXContext::quoteOffset(CK_BYTE_PTR bytes) {
  // TODO: double check
  auto* params = reinterpret_cast<CK_RSA_PUBLIC_KEY_PARAMS*>(bytes);
  CK_ULONG pubKeySize = params->ulModulusLen + params->ulExponentLen;
  CK_ULONG offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + pubKeySize;

  ENVOY_LOG(debug, "ulModulusLen: {}, ulExponentLen: {}, offset: {}\n", params->ulModulusLen,
            params->ulExponentLen, offset);
  return offset;
}

void SGXContext::logQuote(CK_BYTE_PTR bytes) {
  auto* quote = reinterpret_cast<sgx_quote_t*>(bytes);

  ENVOY_LOG(debug, "\n----------\nVersion: {}\nSignType: {}\nBasename: {}\n--------------\n",
            quote->version, quote->sign_type, quote->basename.name);
}

CK_RV SGXContext::createQuote(CK_OBJECT_HANDLE pubkey, ByteString* quote,
                              ByteString* quote_public) {
  CK_BYTE_PTR quote_public_key = NULL_PTR;
  CK_RV status = CKR_OK;
  CK_ULONG quote_len = 0;

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE)) {
    ENVOY_LOG(debug, "createQuote parameters error.");
    return CKR_ARGUMENTS_BAD;
  }
  // Wrap the key
  CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteParams;
  quoteParams.qlPolicy = SGX_QL_PERSISTENT;
  for (int i = 0; i < NONCE_LENGTH; i++) {
    quoteParams.nonce[i] = static_cast<CK_BYTE>(i);
  }
  CK_MECHANISM mechanism = {CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY, &quoteParams,
                            sizeof(quoteParams)};

  status = p11_->C_WrapKey(sessionhandle_, &mechanism, NULL_PTR, pubkey, NULL_PTR, &quote_len);
  if (status != CKR_OK || !quote_len) {
    ENVOY_LOG(debug, "Failed to get wrap key length:{}\n", ERROR_CODE_TO_STRING(status));
    if (status != CKR_OK) {
      return status;
    } else {
      return CKR_GENERAL_ERROR;
    }
  }

  quote_public_key = static_cast<CK_BYTE_PTR>(calloc(quote_len, sizeof(CK_BYTE)));
  if (!quote_public_key) {
    ENVOY_LOG(debug, "Mem failure allocating wrapped key length.\n");
    return CKR_HOST_MEMORY;
  }

  status =
      p11_->C_WrapKey(sessionhandle_, &mechanism, NULL_PTR, pubkey, quote_public_key, &quote_len);
  if (status != CKR_OK) {
    free(quote_public_key);
    ENVOY_LOG(debug, "Error during p11->C_WrapKey: {}\n", ERROR_CODE_TO_STRING(status));
    return status;
  }
  int offset = int(quoteOffset(quote_public_key));

  quote_public->byte_size = offset;
  status = allocAndCopyBytes(&quote_public->bytes, quote_public_key, quote_public->byte_size);
  if (status != CKR_OK) {
    free(quote_public_key);
    ENVOY_LOG(debug, "Error! Copying quote_public buf failed\n");
    return status;
  }

  quote->byte_size = quote_len - quote_public->byte_size;
  status = allocAndCopyBytes(&quote->bytes, quote_public_key + offset, quote->byte_size);
  if (status != CKR_OK) {
    free(quote_public_key);
    ENVOY_LOG(debug, "Error! Copying quote buf failed\n");
    return status;
  }

  logQuote(quote_public_key);
  free(quote_public_key);

  return status;
}

CK_RV SGXContext::rsaDecrypt(CK_OBJECT_HANDLE privkey, const uint8_t* in, size_t inlen,
                             ByteString* decrypted) {

  CK_RV status = CKR_OK;
  CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL_PTR, 0};

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE)) {
    ENVOY_LOG(debug, "rsaDecrypt parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  status = p11_->C_DecryptInit(sessionhandle_, &mechanism, privkey);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_DecryptInit: {}\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  decrypted->byte_size = 0;

  status = p11_->C_Decrypt(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, NULL_PTR,
                           &decrypted->byte_size);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Decrypt: {}\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  decrypted->bytes = static_cast<CK_BYTE_PTR>(calloc(decrypted->byte_size, sizeof(CK_BYTE)));

  status = p11_->C_Decrypt(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, decrypted->bytes,
                           &decrypted->byte_size);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Decrypt: {}\n", ERROR_CODE_TO_STRING(status));
    free(decrypted->bytes);
  }

  return status;
}

CK_RV SGXContext::rsaSign(CK_OBJECT_HANDLE privkey, CK_OBJECT_HANDLE pubkey, bool ispss, int hash,
                          const uint8_t* in, size_t inlen, ByteString* signature) {
  CK_MECHANISM_TYPE mechanismType;
  CK_VOID_PTR param = NULL_PTR;
  CK_ULONG paramLen = 0;
  CK_RV status = CKR_OK;
  CK_MECHANISM mechanism;
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug, "hash {}", hash);
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug, "is_pss {}", ispss);

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE)) {
    ENVOY_LOG(debug, "rsaSign parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  if (ispss) {
    CK_RSA_PKCS_PSS_PARAMS params[] = {{CKM_SHA224, CKG_MGF1_SHA224, 28},
                                       {CKM_SHA256, CKG_MGF1_SHA256, 32},
                                       {CKM_SHA384, CKG_MGF1_SHA384, 0},
                                       {CKM_SHA512, CKG_MGF1_SHA512, 0}};

    int param_index = -1;
    switch (hash) {
    case 224: {
      mechanismType = CKM_SHA224_RSA_PKCS_PSS;
      param_index = 0;
      break;
    }
    case 256: {
      mechanismType = CKM_SHA256_RSA_PKCS_PSS;
      param_index = 1;
      ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug, "256");
      break;
    }
    case 384: {
      mechanismType = CKM_SHA384_RSA_PKCS_PSS;
      param_index = 2;
      break;
    }
    case 512: {
      mechanismType = CKM_SHA512_RSA_PKCS_PSS;
      param_index = 3;
      break;
    }
    default:
      status = CKR_ARGUMENTS_BAD;
      return status;
    }

    param = &params[param_index];
    paramLen = sizeof(params[param_index]);

  } else {

    switch (hash) {
    case 0:
      mechanismType = CKM_RSA_PKCS;
      break;
    case 1:
      mechanismType = CKM_SHA1_RSA_PKCS;
      break;
    case 224:
      mechanismType = CKM_SHA224_RSA_PKCS;
      break;
    case 256:
      mechanismType = CKM_SHA256_RSA_PKCS;
      break;
    case 384:
      mechanismType = CKM_SHA384_RSA_PKCS;
      break;
    case 512:
      mechanismType = CKM_SHA512_RSA_PKCS;
      break;
    default:
      status = CKR_ARGUMENTS_BAD;
      return status;
    }
  }
  mechanism.mechanism = mechanismType;
  mechanism.pParameter = param;
  mechanism.ulParameterLen = paramLen;

  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug, "mechanism.mechanism {}",
                      mechanism.mechanism);
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug, "mechanism.paramLen {}",
                      mechanism.ulParameterLen);

  status = p11_->C_SignInit(sessionhandle_, &mechanism, privkey);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_SignInit: {}\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_Sign(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, NULL_PTR,
                        &signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Sign: {}\n", ERROR_CODE_TO_STRING(status));
    signature->byte_size = 0;
    return status;
  }

  signature->bytes = static_cast<CK_BYTE_PTR>(calloc(signature->byte_size, sizeof(CK_BYTE)));

  status = p11_->C_Sign(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, signature->bytes,
                        &signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Sign: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  status = p11_->C_VerifyInit(sessionhandle_, &mechanism, pubkey);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_VerifyInit: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  status = p11_->C_Verify(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, signature->bytes,
                          signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Verify: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  return status;
}

CK_RV SGXContext::ecdsaSign(CK_OBJECT_HANDLE private_key, CK_OBJECT_HANDLE pubkey,
                            const uint8_t* in, size_t inlen, ByteString* signature) {
  CK_MECHANISM_TYPE mechanismType = CKM_ECDSA;
  CK_VOID_PTR param = NULL_PTR;
  CK_ULONG paramLen = 0;
  CK_RV status = CKR_OK;
  CK_MECHANISM mechanism;

  if ((p11_ == NULL_PTR) || (sessionhandle_ == CK_INVALID_HANDLE)) {
    ENVOY_LOG(debug, "ecdsaSign parameters error.");
    return CKR_ARGUMENTS_BAD;
  }

  mechanism.mechanism = mechanismType;
  mechanism.pParameter = param;
  mechanism.ulParameterLen = paramLen;

  status = p11_->C_SignInit(sessionhandle_, &mechanism, private_key);

  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_SignInit: {}\n", ERROR_CODE_TO_STRING(status));
    return status;
  }

  status = p11_->C_Sign(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, NULL_PTR,
                        &signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Sign: {}\n", ERROR_CODE_TO_STRING(status));
    signature->byte_size = 0;
    return status;
  }

  signature->bytes = static_cast<CK_BYTE_PTR>(calloc(signature->byte_size, sizeof(CK_BYTE)));

  status = p11_->C_Sign(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, signature->bytes,
                        &signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Sign: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  status = p11_->C_VerifyInit(sessionhandle_, &mechanism, pubkey);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_VerifyInit: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  status = p11_->C_Verify(sessionhandle_, const_cast<CK_BYTE_PTR>(in), inlen, signature->bytes,
                          signature->byte_size);
  if (status != CKR_OK) {
    ENVOY_LOG(debug, "Error during p11->C_Verify: {}\n", ERROR_CODE_TO_STRING(status));
    free(signature->bytes);
    signature->byte_size = 0;
    return status;
  }

  return status;
}

CK_RV SGXContext::getRSAPublicKey(CK_OBJECT_HANDLE pubkey, ByteString* modulus,
                                  ByteString* exponent) {
  CK_RV status = CKR_OK;

  CK_ATTRIBUTE pubkey_template[] = {
      {CKA_MODULUS, NULL_PTR, 0},
      {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
  };

  status = p11_->C_GetAttributeValue(sessionhandle_, pubkey, pubkey_template, DIM(pubkey_template));
  if (status != CKR_OK) {
    return status;
  }

  modulus->byte_size = pubkey_template[0].ulValueLen;
  modulus->bytes = static_cast<CK_BYTE_PTR>(calloc(modulus->byte_size, sizeof(CK_BYTE)));
  pubkey_template[0].pValue = modulus->bytes;

  exponent->byte_size = pubkey_template[1].ulValueLen;
  exponent->bytes = static_cast<CK_BYTE_PTR>(calloc(exponent->byte_size, sizeof(CK_BYTE)));
  pubkey_template[1].pValue = exponent->bytes;

  status = p11_->C_GetAttributeValue(sessionhandle_, pubkey, pubkey_template, DIM(pubkey_template));

  return status;
}

CK_RV SGXContext::getECDSAPublicKey(CK_OBJECT_HANDLE pubkey, ByteString* group,
                                    ByteString* points) {
  CK_RV status = CKR_OK;

  CK_ATTRIBUTE pubkey_template[] = {
      {CKA_EC_PARAMS, NULL_PTR, 0},
      {CKA_EC_POINT, NULL_PTR, 0},
  };

  status = p11_->C_GetAttributeValue(sessionhandle_, pubkey, pubkey_template, DIM(pubkey_template));
  if (status != CKR_OK) {
    return status;
  }

  group->byte_size = pubkey_template[0].ulValueLen;
  group->bytes = static_cast<CK_BYTE_PTR>(calloc(group->byte_size, sizeof(CK_BYTE)));
  pubkey_template[0].pValue = group->bytes;

  points->byte_size = pubkey_template[1].ulValueLen;
  points->bytes = static_cast<CK_BYTE_PTR>(calloc(points->byte_size, sizeof(CK_BYTE)));
  pubkey_template[1].pValue = points->bytes;

  status = p11_->C_GetAttributeValue(sessionhandle_, pubkey, pubkey_template, DIM(pubkey_template));

  return status;
}

void SGXContext::addExt(STACK_OF(X509_EXTENSION) * exts, int nid, const char* subvalue) {
  X509_EXTENSION* pSubExt = X509V3_EXT_nconf_nid(NULL_PTR, NULL_PTR, nid, subvalue);
  if (pSubExt == NULL_PTR) {
    throw EnvoyException(absl::StrCat("Failed to find x509_extension:", subvalue));
  }
  sk_X509_EXTENSION_push(exts, pSubExt);
}

unsigned long SGXContext::longVal(const ByteString& byteString) {
  // Convert the first 8 bytes of the string to an unsigned long value
  unsigned long rv = 0;

  for (size_t i = 0; i < std::min(size_t(8), byteString.byte_size); i++) {
    rv <<= 8;
    rv += byteString.bytes[i];
  }

  return rv;
}
// Convert a DER encoded octet string to a raw ByteString
ByteString SGXContext::octet2Raw(const ByteString& byteString) {
  ByteString rv;
  ByteString repr = byteString;
  size_t len = repr.byte_size;
  size_t controlOctets = 2;

  if (len < controlOctets) {
    ENVOY_LOG(debug, "Undersized octet string\n");
    return rv;
  }

  if (repr.bytes[0] != 0x04) {
    ENVOY_LOG(debug, "ByteString is not an octet string\n");
    return rv;
  }

  // Definite, short
  if (repr.bytes[1] < 0x80) {
    if (repr.bytes[1] != (len - controlOctets)) {
      if (repr.bytes[1] < (len - controlOctets)) {
        ENVOY_LOG(debug, "Underrun octet string\n");
      } else {
        ENVOY_LOG(debug, "Overrun octet string\n");
      }

      return rv;
    }
  }
  // Definite, long
  else {
    size_t lengthOctets = repr.bytes[1] & 0x7f;
    controlOctets += lengthOctets;

    if (controlOctets >= repr.byte_size) {
      ENVOY_LOG(debug, "Undersized octet string\n");
      return rv;
    }

    ByteString length;
    length.byte_size = lengthOctets;
    length.bytes = static_cast<CK_BYTE_PTR>(calloc(length.byte_size, sizeof(CK_BYTE)));
    memcpy(length.bytes, repr.bytes + 2, lengthOctets); // NOLINT(safe-memcpy)

    if (longVal(length) != (len - controlOctets)) {
      if (longVal(length) < (len - controlOctets)) {
        ENVOY_LOG(debug, "Underrun octet string\n");
      } else {
        ENVOY_LOG(debug, "Overrun octet string\n");
      }
      free(length.bytes);
      return rv;
    }
  }

  rv.byte_size = len - controlOctets;
  rv.bytes = static_cast<CK_BYTE_PTR>(calloc(rv.byte_size, sizeof(CK_BYTE)));
  memcpy(rv.bytes, repr.bytes + controlOctets, rv.byte_size); // NOLINT(safe-memcpy)
  return rv;
}

int SGXContext::calculateDigest(const EVP_MD* md, const uint8_t* in, size_t in_len,
                                unsigned char* hash, unsigned int* hash_len) {
  bssl::ScopedEVP_MD_CTX ctx;

  // Calculate the message digest for signing.
  if (!EVP_DigestInit_ex(ctx.get(), md, NULL_PTR) || !EVP_DigestUpdate(ctx.get(), in, in_len) ||
      !EVP_DigestFinal_ex(ctx.get(), hash, hash_len)) {
    return 0;
  }
  return 1;
}

CK_RV SGXContext::createCSR(bool isrsa, CK_OBJECT_HANDLE pubkey, CK_OBJECT_HANDLE privkey,
                            std::string& csr_config, std::string& quote, std::string& quote_key,
                            std::string& quotepub, std::string& quotepub_key, std::string& out) {

  CK_RV status = CKR_OK;
  X509_REQ* x509_req = NULL_PTR;
  X509_NAME* x509_name = NULL_PTR;
  EVP_PKEY* evp_pkey = NULL_PTR;
  unsigned char* req_info_buffer = NULL_PTR;
  ByteString signed_data;
  BIO* bio = NULL_PTR;
  BUF_MEM* bptr = NULL_PTR;
  ASN1_OBJECT* algo = NULL_PTR;
  X509_ALGOR* x509_algor = NULL_PTR;
  STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

  x509_req = X509_REQ_new();
  X509_REQ_set_version(x509_req, 0);
  x509_name = X509_REQ_get_subject_name(x509_req);
  X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(""), -1, -1, 0);

  addExt(exts, NID_basic_constraints, CA.c_str());

  addExt(exts, NID_key_usage, keyUsage.c_str());

  addExt(exts, NID_ext_key_usage, extKeyUsage.c_str());

  const std::string alt_names = "[alt_names]";
  std::string altName = "URI:";
  std::size_t pos = csr_config.find(alt_names);
  if (pos == std::string::npos) {
    throw EnvoyException("Failed to search alt_names filed in openssl config!");
  } else {
    // to locate the start of alt_names in openssl config
    pos += alt_names.size() + strlen("\n") + strlen("URI.1 = ");
    csr_config = csr_config.substr(pos);
    pos = csr_config.find('\n');
    if (pos == std::string::npos) {
      throw EnvoyException("Failed to get alt_names in openssl config!");
    }
    altName += csr_config.substr(0, pos);
  }
  ENVOY_LOG(debug, "alt_names: {}", altName);
  addExt(exts, NID_subject_alt_name, altName.c_str());

  std::string value = Base64::encode(quote.c_str(), quote.size());
  ENVOY_LOG(debug, "The quote: {}", value);
  value = "ASN1:UTF8String:" + value;
  X509_EXTENSION* pSubExt = X509V3_EXT_nconf(NULL, NULL, quote_key.c_str(), value.c_str());
  sk_X509_EXTENSION_push(exts, pSubExt);

  value = Base64::encode(quotepub.c_str(), quotepub.size());
  ENVOY_LOG(debug, "The quote public key: {}", value);
  value = "ASN1:UTF8String:" + value;
  pSubExt = X509V3_EXT_nconf(NULL, NULL, quotepub_key.c_str(), value.c_str());
  sk_X509_EXTENSION_push(exts, pSubExt);

  X509_REQ_add_extensions(x509_req, exts);
  sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

  if (isrsa) {

    RSA* rsa = NULL_PTR;
    BIGNUM* bn_modulus = NULL_PTR;
    BIGNUM* bn_public_exponent = NULL_PTR;
    ByteString modulus, exponent;

    status = getRSAPublicKey(pubkey, &modulus, &exponent);
    if (status != CKR_OK) {
      ENVOY_LOG(debug, "Error get pubkey\n");
      return status;
    }

    rsa = RSA_new();
    bn_modulus = BN_bin2bn(modulus.bytes, static_cast<int>(modulus.byte_size), NULL_PTR);
    bn_public_exponent = BN_bin2bn(exponent.bytes, static_cast<int>(exponent.byte_size), NULL_PTR);
    RSA_set0_key(rsa, bn_modulus, bn_public_exponent, NULL_PTR);

    evp_pkey = EVP_PKEY_new();

    /* Add public key to certificate request */
    EVP_PKEY_assign(evp_pkey, EVP_PKEY_RSA, rsa);

    X509_REQ_set_pubkey(x509_req, evp_pkey);
    EVP_PKEY_free(evp_pkey);

    /* Sign certificate request */
    int req_info_size = i2d_re_X509_REQ_tbs(x509_req, &req_info_buffer);

    status = rsaSign(privkey, pubkey, false, 256, req_info_buffer, req_info_size, &signed_data);
    if (status != CKR_OK) {
      ENVOY_LOG(debug, "Error sign x509_req\n");
      return status;
    }

    algo = OBJ_nid2obj(NID_sha256WithRSAEncryption);
  } else {
    EC_KEY* ec = NULL_PTR;
    const EC_GROUP* ec_group = NULL_PTR;
    EC_POINT* ec_points = NULL_PTR;
    ByteString group, points;
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    status = getECDSAPublicKey(pubkey, &group, &points);
    if (status != CKR_OK) {
      ENVOY_LOG(debug, "Error get pubkey\n");
      return status;
    }

    ec = d2i_ECParameters(NULL_PTR, const_cast<const uint8_t**>(&group.bytes), group.byte_size);
    if (ec == NULL_PTR) {
      ENVOY_LOG(debug, "Error read group\n");
      return status;
    }
    ec_group = EC_KEY_get0_group(ec);

    ByteString raw = octet2Raw(points);
    size_t len = raw.byte_size;
    if (len == 0) {
      ENVOY_LOG(debug, "Error octet2Raw\n");
      status = CKR_GENERAL_ERROR;
      return status;
    }

    ec_points = EC_POINT_new(ec_group);
    if (!EC_POINT_oct2point(ec_group, ec_points, raw.bytes, raw.byte_size, NULL_PTR)) {
      EC_POINT_free(ec_points);
      ENVOY_LOG(debug, "Error oct2point\n");
      status = CKR_GENERAL_ERROR;
      return status;
    }

    if (!EC_KEY_set_public_key(ec, ec_points)) {
      EC_POINT_free(ec_points);
      ENVOY_LOG(debug, "Error set ecdsa public key\n");
      status = CKR_GENERAL_ERROR;
      return status;
    }

    EC_POINT_free(ec_points);

    evp_pkey = EVP_PKEY_new();

    /* Add public key to certificate request */
    EVP_PKEY_assign_EC_KEY(evp_pkey, ec);
    X509_REQ_set_pubkey(x509_req, evp_pkey);
    EVP_PKEY_free(evp_pkey);

    /* Sign certificate request */
    int req_info_size = i2d_re_X509_REQ_tbs(x509_req, &req_info_buffer);

    calculateDigest(md, req_info_buffer, req_info_size, hash, &hash_len);
    status = ecdsaSign(privkey, pubkey, hash, hash_len, &signed_data);

    len = signed_data.byte_size / 2;

    BIGNUM* r = BN_bin2bn(signed_data.bytes, len, NULL_PTR);
    BIGNUM* s = BN_bin2bn(signed_data.bytes + len, len, NULL_PTR);

    free(signed_data.bytes);

    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    signed_data.bytes = NULL_PTR;
    signed_data.byte_size = i2d_ECDSA_SIG(sig, &signed_data.bytes);
    ECDSA_SIG_free(sig);

    algo = OBJ_nid2obj(NID_ecdsa_with_SHA256);
  }

  x509_algor = X509_ALGOR_new();
  X509_ALGOR_set0(x509_algor, algo, V_ASN1_NULL, NULL_PTR);
  X509_REQ_set1_signature_algo(x509_req, x509_algor);
  X509_REQ_set1_signature_value(x509_req, signed_data.bytes, signed_data.byte_size);
  free(signed_data.bytes);

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_REQ(bio, x509_req);
  BIO_get_mem_ptr(bio, &bptr);
  int len = bptr->length;
  auto pem = static_cast<char*>(malloc(len + 1));
  if (pem == NULL_PTR) {
    BIO_free(bio);
    return CKR_HOST_MEMORY;
  }

  memset(pem, 0, len + 1);
  BIO_read(bio, pem, len);

  out = std::string(pem);
  free(pem);
  BIO_free(bio);
  return status;
}

CK_RV SGXContext::allocAndCopyBytes(CK_BYTE_PTR* dest, const CK_BYTE_PTR src, const CK_ULONG size) {
  if (!dest || !src || !size) {
    return CKR_ARGUMENTS_BAD;
  }

  *dest = static_cast<CK_BYTE_PTR>(calloc(size, sizeof(CK_BYTE)));

  if (*dest == NULL_PTR) {
    ENVOY_LOG(debug, "Error! No memory for a byte buffer field\n");
    return CKR_HOST_MEMORY;
  }

  void* result = memcpy(*dest, src, size * sizeof(CK_BYTE)); // NOLINT(safe-memcpy)

  if (result == NULL_PTR) {
    *dest = NULL_PTR;
    ENVOY_LOG(debug, "Error! memcpy failed!\n");
    return CKR_HOST_MEMORY;
  }

  return CKR_OK;
}

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy

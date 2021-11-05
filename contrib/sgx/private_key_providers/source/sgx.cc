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
  // if (status != CKR_OK && status != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
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
  // if (status != CKR_OK && status != CKR_USER_ALREADY_LOGGED_IN) {
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
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "mechanism.pParameter.hashAlg {}",
                      CK_RSA_PKCS_PSS_PARAMS_PTR(mechanism.pParameter)->hashAlg);
  ENVOY_LOG_TO_LOGGER(Logger::Registry::getLog(Logger::Id::secret), debug,
                      "mechanism.pParameter.mgf {}",
                      CK_RSA_PKCS_PSS_PARAMS_PTR(mechanism.pParameter)->mgf);

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

CK_RV SGXContext::createCSR(std::string& subj, std::string& key_label, std::string& out) const {
  if (!isValidString(subj) || !isValidString(std::to_string(slotid_)) ||
      !isValidString(key_label)) {
    throw EnvoyException("The parameters can only contain 'a-zA-Z0-9', '-', '_', '/' or '='.");
  }

  CK_RV status = CKR_OK;
  std::string osslCsrCmdTotal = osslCsrCmd;
  std::string osslCsrCmdKey = " -key";
  std::string osslCsrCmdSubj = " -subj";
  std::string osslCsrCmdOut = " -out";

  osslCsrCmdKey += " slot_" + std::to_string(slotid_) + "-label_" + key_label;
  osslCsrCmdSubj += " " + subj;
  osslCsrCmdOut += " " + out;
  osslCsrCmdTotal += osslCsrCmdKey + osslCsrCmdSubj + osslCsrCmdOut;

  ENVOY_LOG(debug, osslCsrCmdTotal.c_str());
  if (system(osslCsrCmdTotal.c_str()) != 0) {
    status = CKR_GENERAL_ERROR;
  }
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

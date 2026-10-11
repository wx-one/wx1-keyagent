/**
 * A PKCS#11 token (an HSM) as the key store, the module given by the customer
 * and loaded at start (dlopen) - nothing of it is linked in.
 *
 *   wx1-disk-<disk>   AES-256, sensitive, extractable only by wrapping
 *   wx1-state         HMAC key the state in the database is signed with,
 *                     never extractable
 *
 * The disk key is wrapped for the guest inside the token (wrap.h). Tokens
 * differ in how: CKM_RSA_AES_KEY_WRAP in one call where the token has it,
 * else RSA-OAEP of a session AES key plus AES-KWP with that key - under its
 * PKCS#11 3.0 number, or under the number of CKM_AES_KEY_WRAP_PAD, which some
 * tokens (SoftHSM) implement as RFC 5649. Which one gives exactly the format
 * is not taken on trust: the start-up check tries them in that order and
 * opens the result itself.
 *
 * One session per worker. A worker runs one call at a time and nothing here
 * waits, so nothing else uses the session in between.
 */
#ifndef WX_P11_H
#define WX_P11_H

#include "wrap.h"

#include <dlfcn.h>
#include <meta_text.h>
#include <openssl/bn.h>

#define CRYPTOKI_COMPAT
#include <pkcs11.h>

#ifndef CKM_AES_KEY_WRAP_KWP
#define CKM_AES_KEY_WRAP_KWP 0x210bUL
#endif

typedef struct {
  CK_ULONG ulAESKeyBits;
  CK_RSA_PKCS_OAEP_PARAMS *pOAEPParams;
} wx_rsa_aes_key_wrap_params_t;

enum { P11_RSA_AES = 1, P11_OAEP_KWP, P11_OAEP_PAD };

static const char *const p11WayNames[] = {"", "CKM_RSA_AES_KEY_WRAP", "RSA-OAEP + CKM_AES_KEY_WRAP_KWP",
                                          "RSA-OAEP + 0x210a (RFC 5649)"};

static CK_FUNCTION_LIST *p11;
static void *p11Module;
static CK_SLOT_ID p11Slot;
static CK_SESSION_HANDLE p11Session;
static CK_RV p11Rv;
static int p11Way;
static bool p11Sha1;
static char p11Pin[256];

static CK_BBOOL p11Yes = CK_TRUE, p11No = CK_FALSE;

/** Remembers the answer; a lost session is opened again by the next call. */
static bool p11Ok(CK_RV rv) {

  p11Rv = rv;

  if (rv == CKR_SESSION_HANDLE_INVALID || rv == CKR_SESSION_CLOSED || rv == CKR_DEVICE_REMOVED ||
      rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_USER_NOT_LOGGED_IN || rv == CKR_DEVICE_ERROR)
    p11Session = 0;

  return rv == CKR_OK;
}

/** A session, logged in. */
static bool p11Ready(void) {

  if (p11 == NULL)
    return false;

  if (p11Session != 0)
    return true;

  CK_SESSION_HANDLE s = 0;

  if (!p11Ok(p11->C_OpenSession(p11Slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s)))
    return false;

  CK_RV rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR *)p11Pin, (CK_ULONG)strlen(p11Pin));

  if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
    p11Rv = rv;
    p11->C_CloseSession(s);
    return false;
  }

  p11Session = s;

  return true;
}

/** The slot whose token has `label` (padded with blanks, as tokens keep it). */
static bool p11FindSlot(const char *label) {

  CK_ULONG count = 0;

  if (!p11Ok(p11->C_GetSlotList(CK_TRUE, NULL, &count)) || count == 0)
    return false;

  CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc(count, sizeof *slots);
  bool found = false;

  if (slots != NULL && p11Ok(p11->C_GetSlotList(CK_TRUE, slots, &count))) {

    for (CK_ULONG i = 0; !found && i < count; ++i) {

      CK_TOKEN_INFO info;
      size_t n = strlen(label);

      if (p11->C_GetTokenInfo(slots[i], &info) != CKR_OK || n > sizeof info.label)
        continue;

      found = memcmp(info.label, label, n) == 0;

      for (size_t j = n; found && j < sizeof info.label; ++j)
        found = info.label[j] == ' ';

      if (found)
        p11Slot = slots[i];
    }
  }

  free(slots);

  return found;
}

/**
 * Loads the module, finds the token, logs in. Once in each process that uses
 * it: the master to check, every worker after the fork. NULL, or why not.
 */
static const char *p11Open(void) {

  static char why[200];
  const char *module = env("WX_PKCS11_MODULE", "");
  const char *token = env("WX_PKCS11_TOKEN", "");
  const char *oaep = env("WX_PKCS11_OAEP", "sha256");

  if (module[0] == 0 || token[0] == 0)
    return "WX_PKCS11_MODULE and WX_PKCS11_TOKEN name the module and the token";

  if (strcmp(oaep, "sha256") != 0 && strcmp(oaep, "sha1") != 0)
    return "WX_PKCS11_OAEP is sha256 or sha1";

  p11Sha1 = strcmp(oaep, "sha1") == 0;

  if (!readSecret(env("WX_PKCS11_PIN_FILE", "/secrets/pkcs11-pin"), p11Pin, sizeof p11Pin))
    return "no PIN for the token (WX_PKCS11_PIN_FILE)";

  /* what the module reads itself (its configuration file, say), put back in a worker */
  envRestoreListed("WX_PKCS11_ENV");

  if (p11Module == NULL && (p11Module = dlopen(module, RTLD_NOW | RTLD_LOCAL)) == NULL) {
    snprintf(why, sizeof why, "cannot load %s: %s", module, dlerror());
    return why;
  }

  CK_C_GetFunctionList get = (CK_C_GetFunctionList)dlsym(p11Module, "C_GetFunctionList");

  if (get == NULL || get(&p11) != CKR_OK || p11 == NULL)
    return "the module is no PKCS#11 module (C_GetFunctionList)";

  CK_C_INITIALIZE_ARGS args = {0};
  args.flags = CKF_OS_LOCKING_OK;
  CK_RV rv = p11->C_Initialize(&args);

  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    snprintf(why, sizeof why, "C_Initialize: 0x%lx", (unsigned long)rv);
    return why;
  }

  if (!p11FindSlot(token)) {
    snprintf(why, sizeof why, "no token labelled \"%s\"", token);
    return why;
  }

  p11Session = 0;

  if (!p11Ready()) {
    snprintf(why, sizeof why, "cannot log in to the token: 0x%lx", (unsigned long)p11Rv);
    return why;
  }

  return NULL;
}

/** The master's check is done; the workers open their own after the fork. */
static void p11Close(void) {

  if (p11 == NULL)
    return;

  if (p11Session != 0)
    p11->C_CloseSession(p11Session);

  p11->C_Finalize(NULL);
  p11Session = 0;
  p11 = NULL;
}

/** The first object with `label` of `cls`; 0 if there is none. */
static CK_OBJECT_HANDLE p11Find(const char *label, CK_OBJECT_CLASS cls) {

  CK_OBJECT_HANDLE found = 0;
  CK_ULONG count = 0;
  CK_ATTRIBUTE match[] = {
      {CKA_CLASS, &cls, sizeof cls},
      {CKA_LABEL, (void *)label, (CK_ULONG)strlen(label)},
  };

  if (!p11Ok(p11->C_FindObjectsInit(p11Session, match, 2)))
    return 0;

  if (!p11Ok(p11->C_FindObjects(p11Session, &found, 1, &count)) || count == 0)
    found = 0;

  p11->C_FindObjectsFinal(p11Session);

  return found;
}

/** Every secret key with `label` destroyed; true when none is left. */
static bool p11DestroyAll(const char *label) {

  CK_OBJECT_HANDLE key;

  for (int i = 0; i < 16 && (key = p11Find(label, CKO_SECRET_KEY)) != 0; ++i)
    if (!p11Ok(p11->C_DestroyObject(p11Session, key)))
      return false;

  return p11Rv == CKR_OK && p11Find(label, CKO_SECRET_KEY) == 0 && p11Rv == CKR_OK;
}

/** A new AES-256 key: on the token with `label`, or a session key when NULL. */
static CK_OBJECT_HANDLE p11Aes(const char *label, bool sensitive, bool wraps) {

  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE type = CKK_AES;
  CK_ULONG length = 32;
  CK_MECHANISM gen = {CKM_AES_KEY_GEN, NULL, 0};
  CK_OBJECT_HANDLE key = 0;
  CK_ATTRIBUTE t[] = {
      {CKA_CLASS, &cls, sizeof cls},
      {CKA_KEY_TYPE, &type, sizeof type},
      {CKA_VALUE_LEN, &length, sizeof length},
      {CKA_TOKEN, label != NULL ? &p11Yes : &p11No, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, sensitive ? &p11Yes : &p11No, sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_ENCRYPT, &p11No, sizeof(CK_BBOOL)},
      {CKA_DECRYPT, &p11No, sizeof(CK_BBOOL)},
      {CKA_WRAP, wraps ? &p11Yes : &p11No, sizeof(CK_BBOOL)},
      {CKA_UNWRAP, &p11No, sizeof(CK_BBOOL)},
      {CKA_SIGN, &p11No, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &p11No, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &p11No, sizeof(CK_BBOOL)},
      {CKA_LABEL, (void *)(label ?: ""), label != NULL ? (CK_ULONG)strlen(label) : 0},
  };

  /* every use not named is off: a token's defaults differ (SoftHSM allows them) */
  CK_ULONG count = sizeof t / sizeof t[0] - (label != NULL ? 0 : 1);

  if (!p11Ok(p11->C_GenerateKey(p11Session, &gen, t, count, &key)))
    return 0;

  return key;
}

/** The guest's public key as a session object to wrap for. */
static CK_OBJECT_HANDLE p11Guest(EVP_PKEY *guest) {

  BIGNUM *n = NULL, *e = NULL;
  unsigned char modulus[1024], exponent[16];
  CK_OBJECT_HANDLE key = 0;

  if (EVP_PKEY_get_bn_param(guest, OSSL_PKEY_PARAM_RSA_N, &n) == 1 &&
      EVP_PKEY_get_bn_param(guest, OSSL_PKEY_PARAM_RSA_E, &e) == 1 && BN_num_bytes(n) <= (int)sizeof modulus &&
      BN_num_bytes(e) <= (int)sizeof exponent) {

    CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
    CK_KEY_TYPE type = CKK_RSA;
    int nLength = BN_bn2bin(n, modulus), eLength = BN_bn2bin(e, exponent);
    CK_ATTRIBUTE t[] = {
        {CKA_CLASS, &cls, sizeof cls},
        {CKA_KEY_TYPE, &type, sizeof type},
        {CKA_TOKEN, &p11No, sizeof(CK_BBOOL)},
        {CKA_WRAP, &p11Yes, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &p11Yes, sizeof(CK_BBOOL)},
        {CKA_MODULUS, modulus, (CK_ULONG)nLength},
        {CKA_PUBLIC_EXPONENT, exponent, (CK_ULONG)eLength},
    };

    if (!p11Ok(p11->C_CreateObject(p11Session, t, 7, &key)))
      key = 0;
  }

  BN_free(n);
  BN_free(e);

  return key;
}

/** C_WrapKey into `out` at `*at`, moving `*at` on. */
static bool p11WrapInto(CK_MECHANISM *how, CK_OBJECT_HANDLE with, CK_OBJECT_HANDLE key,
                        unsigned char *out, size_t room, size_t *at) {

  CK_ULONG length = (CK_ULONG)(room - *at);

  if (!p11Ok(p11->C_WrapKey(p11Session, how, with, key, out + *at, &length)))
    return false;

  *at += length;

  return true;
}

/** `key` wrapped for `guest` the given way; the length in `out`, or -1. */
static long p11WrapWay(int way, CK_OBJECT_HANDLE key, EVP_PKEY *guest, unsigned char *out, size_t room) {

  CK_RSA_PKCS_OAEP_PARAMS oaep = {p11Sha1 ? CKM_SHA_1 : CKM_SHA256, p11Sha1 ? CKG_MGF1_SHA1 : CKG_MGF1_SHA256,
                                  CKZ_DATA_SPECIFIED, NULL, 0};
  CK_OBJECT_HANDLE pub = p11Guest(guest);
  size_t at = 0;
  bool done = false;

  if (pub == 0)
    return -1;

  if (way == P11_RSA_AES) {

    wx_rsa_aes_key_wrap_params_t params = {256, &oaep};
    CK_MECHANISM how = {CKM_RSA_AES_KEY_WRAP, &params, sizeof params};

    done = p11WrapInto(&how, pub, key, out, room, &at);

  } else {

    CK_OBJECT_HANDLE aes = p11Aes(NULL, true, true);
    CK_MECHANISM rsa = {CKM_RSA_PKCS_OAEP, &oaep, sizeof oaep};
    CK_MECHANISM kwp = {way == P11_OAEP_KWP ? CKM_AES_KEY_WRAP_KWP : CKM_AES_KEY_WRAP_PAD, NULL, 0};
    unsigned char inner[256];
    size_t innerLength = 0;

    /* the RSA part goes first: the AES key, then what it wraps */
    done = aes != 0 && p11WrapInto(&kwp, aes, key, inner, sizeof inner, &innerLength) &&
           p11WrapInto(&rsa, pub, aes, out, room, &at) && at + innerLength <= room;

    if (done) {
      memcpy(out + at, inner, innerLength);
      at += innerLength;
    }

    if (aes != 0)
      p11->C_DestroyObject(p11Session, aes);
  }

  p11->C_DestroyObject(p11Session, pub);

  return done ? (long)at : -1;
}

/**
 * Which way gives exactly the format: a known session key wrapped each way
 * for a throwaway key and opened here. NULL and `p11Way` set, or why not.
 */
static const char *p11SelfTest(void) {

  static char why[200];
  EVP_PKEY *guest = wrapTestKey();
  CK_OBJECT_HANDLE key = guest != NULL ? p11Aes(NULL, false, false) : 0;
  unsigned char value[32], wrapped[1100], back[64];
  CK_ATTRIBUTE read = {CKA_VALUE, value, sizeof value};

  p11Way = 0;

  if (key != 0 && p11Ok(p11->C_GetAttributeValue(p11Session, key, &read, 1)) && read.ulValueLen == 32) {

    for (int way = P11_RSA_AES; p11Way == 0 && way <= P11_OAEP_PAD; ++way) {
      long n = p11WrapWay(way, key, guest, wrapped, sizeof wrapped);
      long opened = n > 0 ? wrapOpen(guest, wrapOaepMd(p11Sha1), wrapped, (size_t)n, back, sizeof back) : -1;

      if (opened == 32 && CRYPTO_memcmp(back, value, 32) == 0)
        p11Way = way;
    }
  }

  if (key != 0)
    p11->C_DestroyObject(p11Session, key);

  EVP_PKEY_free(guest);
  OPENSSL_cleanse(value, sizeof value);
  OPENSSL_cleanse(back, sizeof back);

  if (p11Way != 0)
    return NULL;

  snprintf(why, sizeof why,
           "the token cannot wrap a key as RSA-OAEP(%s) + AES-KWP (tried CKM_RSA_AES_KEY_WRAP, "
           "CKM_AES_KEY_WRAP_KWP, 0x210a)%s",
           p11Sha1 ? "SHA-1" : "SHA-256", p11Sha1 ? "" : "; WX_PKCS11_OAEP=sha1 if it can only do SHA-1");

  return why;
}

/** The state key, made on the first start. */
static CK_OBJECT_HANDLE p11StateKey(void) {

  CK_OBJECT_HANDLE key = p11Find("wx1-state", CKO_SECRET_KEY);

  if (key != 0 || p11Rv != CKR_OK)
    return key;

  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE type = CKK_GENERIC_SECRET;
  CK_ULONG length = 32;
  CK_MECHANISM gen = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
  CK_ATTRIBUTE t[] = {
      {CKA_CLASS, &cls, sizeof cls},
      {CKA_KEY_TYPE, &type, sizeof type},
      {CKA_VALUE_LEN, &length, sizeof length},
      {CKA_TOKEN, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE, &p11No, sizeof(CK_BBOOL)},
      {CKA_SIGN, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &p11Yes, sizeof(CK_BBOOL)},
      {CKA_ENCRYPT, &p11No, sizeof(CK_BBOOL)},
      {CKA_DECRYPT, &p11No, sizeof(CK_BBOOL)},
      {CKA_WRAP, &p11No, sizeof(CK_BBOOL)},
      {CKA_UNWRAP, &p11No, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &p11No, sizeof(CK_BBOOL)},
      {CKA_LABEL, (void *)"wx1-state", 9},
  };

  if (!p11Ok(p11->C_GenerateKey(p11Session, &gen, t, sizeof t / sizeof t[0], &key)))
    return 0;

  return key;
}

/** What the master checks: the state key there, and a way to wrap. */
static const char *p11Check(void) {

  static char why[120];

  if (p11StateKey() == 0) {
    snprintf(why, sizeof why, "cannot find or make the state key on the token: 0x%lx", (unsigned long)p11Rv);
    return why;
  }

  return p11SelfTest();
}

static void p11DiskLabel(const char *diskId, char *label, size_t room) {
  text_t l = TEXT`wx1-disk-${diskId}`;
  l.into(label, room);
}

/* --------------------------------------------- what the key store offers */

static bool p11New(const char *diskId) {

  char label[96];

  p11DiskLabel(diskId, label, sizeof label);

  for (int attempt = 0; attempt < 2; ++attempt)
    if (p11Ready() && p11DestroyAll(label) && p11Aes(label, true, false) != 0)
      return true;

  return false;
}

static const char *p11Wrap(const char *diskId, EVP_PKEY *guest, char *out, size_t room) {

  char label[96];
  unsigned char wrapped[1100];

  p11DiskLabel(diskId, label, sizeof label);

  for (int attempt = 0; attempt < 2; ++attempt) {

    if (!p11Ready())
      continue;

    CK_OBJECT_HANDLE key = p11Find(label, CKO_SECRET_KEY);

    if (key == 0 && p11Rv == CKR_OK)
      return "disk key not found (PKCS#11)";

    long n = key != 0 ? p11WrapWay(p11Way, key, guest, wrapped, sizeof wrapped) : -1;

    if (n > 0 && ((size_t)n + 2) / 3 * 4 + 1 <= room) {
      toBase64(wrapped, (size_t)n, out);
      return NULL;
    }
  }

  return "key store cannot wrap the disk key (PKCS#11)";
}

static bool p11Shred(const char *diskId) {

  char label[96];

  p11DiskLabel(diskId, label, sizeof label);

  for (int attempt = 0; attempt < 2; ++attempt)
    if (p11Ready() && p11DestroyAll(label))
      return true;

  return false;
}

/** HMAC-SHA256 with the state key: "p11:<base64>". */
static bool p11Mac(const char *message, size_t length, char *mac, size_t room) {

  unsigned char sum[32];
  CK_ULONG n = sizeof sum;
  CK_MECHANISM how = {CKM_SHA256_HMAC, NULL, 0};

  for (int attempt = 0; attempt < 2; ++attempt) {

    CK_OBJECT_HANDLE key = p11Ready() ? p11Find("wx1-state", CKO_SECRET_KEY) : 0;

    if (key == 0 || !p11Ok(p11->C_SignInit(p11Session, &how, key)))
      continue;

    if (!p11Ok(p11->C_Sign(p11Session, (CK_BYTE *)message, (CK_ULONG)length, sum, &n)) || n != 32)
      continue;

    if (room < 4 + 45)
      return false;

    memcpy(mac, "p11:", 4);
    toBase64(sum, 32, mac + 4);

    return true;
  }

  return false;
}

static int p11MacOk(const char *message, size_t length, const char *mac) {

  char want[64];

  if (!p11Mac(message, length, want, sizeof want))
    return -1;

  return strlen(mac) == strlen(want) && CRYPTO_memcmp(mac, want, strlen(want)) == 0 ? 1 : 0;
}

#endif /* WX_P11_H */

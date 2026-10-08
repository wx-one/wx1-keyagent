/**
 * The TPM side of a key release, on OpenSSL alone: what tpm2_makecredential
 * and tpm2_checkquote did in the Python version, and the NV certification.
 *
 * Everything the guest sends is parsed with bounds checks and refused when
 * it is not exactly the shape expected; no field is trusted before the
 * signature over it is.
 */
#ifndef WX_TPM_H
#define WX_TPM_H

#include "util.h"

#include <limits.h>
#include <openssl/crypto.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#define TPM_ALG_RSA 0x0001
#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_NULL 0x0010
#define TPM_ALG_ECDSA 0x0018
#define TPM_ALG_ECC 0x0023
#define TPM_ALG_AES 0x0006
#define TPM_ALG_CFB 0x0043
#define TPM_ECC_NIST_P256 0x0003

/* ------------------------------------------------------------- reading */

/** Big-endian reading that stops for good at the first short read. */
typedef struct {
  const unsigned char *at;
  size_t left;
  bool broke;
} tpmRead_t;

static tpmRead_t tpmReader(const void *data, size_t length) {
  tpmRead_t r = {(const unsigned char *)data, length, false};
  return r;
}

static const unsigned char *tpmRead_t__take(tpmRead_t *self, size_t n) {

  if (self->broke || self->left < n) {
    self->broke = true;
    return NULL;
  }

  const unsigned char *p = self->at;

  self->at += n;
  self->left -= n;

  return p;
}

static unsigned tpmRead_t__u16(tpmRead_t *self) {
  const unsigned char *p = self.take(2);
  return p != NULL ? (unsigned)(p[0] << 8 | p[1]) : 0;
}

static uint32_t tpmRead_t__u32(tpmRead_t *self) {
  const unsigned char *p = self.take(4);
  return p != NULL ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3] : 0;
}

/** A TPM2B: its size, then that many bytes. */
static const unsigned char *tpmRead_t__sized(tpmRead_t *self, size_t *length) {

  *length = self.u16();

  return self.take(*length);
}

/* --------------------------------------------------------- public keys */

/** A TPMT_PUBLIC, the parts used here. Views into the bytes it came from. */
typedef struct {
  unsigned type;
  unsigned nameAlg;
  uint32_t attributes;
  unsigned symAlg, symBits, symMode;
  /* RSA */
  const unsigned char *modulus;
  size_t modulusLength;
  uint32_t exponent;
  /* ECC */
  unsigned curve;
  const unsigned char *x, *y;
  size_t xLength, yLength;
  /* the whole TPMT_PUBLIC, for its name */
  const unsigned char *raw;
  size_t rawLength;
} tpmPublic_t;

/** Parses a TPMT_PUBLIC that fills `length` exactly. */
static bool tpmPublic(const unsigned char *data, size_t length, tpmPublic_t *out) {

  tpmRead_t r = tpmReader(data, length);
  size_t n;

  memset(out, 0, sizeof *out);
  out->raw = data;
  out->rawLength = length;

  out->type = r.u16();
  out->nameAlg = r.u16();
  out->attributes = r.u32();
  r.sized(&n); /* authPolicy */

  if (out->type == TPM_ALG_RSA) {
    out->symAlg = r.u16();
    if (out->symAlg != TPM_ALG_NULL) {
      out->symBits = r.u16();
      out->symMode = r.u16();
    }
    if (r.u16() != TPM_ALG_NULL) /* scheme */
      r.u16();
    r.u16(); /* keyBits: the modulus says it */
    out->exponent = r.u32();
    out->modulus = r.sized(&out->modulusLength);
  } else if (out->type == TPM_ALG_ECC) {
    out->symAlg = r.u16();
    if (out->symAlg != TPM_ALG_NULL) {
      out->symBits = r.u16();
      out->symMode = r.u16();
    }
    if (r.u16() != TPM_ALG_NULL) /* scheme */
      r.u16();
    out->curve = r.u16();
    if (r.u16() != TPM_ALG_NULL) /* kdf */
      r.u16();
    out->x = r.sized(&out->xLength);
    out->y = r.sized(&out->yLength);
  } else {
    return false;
  }

  return !r.broke && r.left == 0;
}

/** The TPM name: nameAlg || SHA-256(TPMT_PUBLIC). 34 bytes. */
static void tpmName(const tpmPublic_t *key, unsigned char name[34]) {

  name[0] = TPM_ALG_SHA256 >> 8;
  name[1] = TPM_ALG_SHA256 & 0xff;
  sha256(key->raw, key->rawLength, name + 2);
}

/** An OpenSSL key for an ECC P-256 TPM key. */
static EVP_PKEY *tpmEccKey(const tpmPublic_t *key) {

  unsigned char point[65];
  EVP_PKEY *pkey = NULL;

  if (key->type != TPM_ALG_ECC || key->curve != TPM_ECC_NIST_P256 || key->xLength != 32 ||
      key->yLength != 32)
    return NULL;

  point[0] = 4;
  memcpy(point + 1, key->x, 32);
  memcpy(point + 33, key->y, 32);

  OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
  OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point);
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(b);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

  if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    pkey = NULL;

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(b);

  return pkey;
}

/** An OpenSSL key for an RSA TPM key. */
static EVP_PKEY *tpmRsaKey(const tpmPublic_t *key) {

  unsigned char e[4];
  uint32_t exponent = key->exponent != 0 ? key->exponent : 65537;
  EVP_PKEY *pkey = NULL;

  if (key->type != TPM_ALG_RSA || key->modulusLength < 256)
    return NULL;

  e[0] = (unsigned char)(exponent >> 24);
  e[1] = (unsigned char)(exponent >> 16);
  e[2] = (unsigned char)(exponent >> 8);
  e[3] = (unsigned char)exponent;

  BIGNUM *n = BN_bin2bn(key->modulus, (int)key->modulusLength, NULL);
  BIGNUM *ee = BN_bin2bn(e, 4, NULL);
  OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_N, n);
  OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_E, ee);
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(b);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

  if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    pkey = NULL;

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(b);
  BN_free(n);
  BN_free(ee);

  return pkey;
}

/**
 * The AK: a restricted signing key of this TPM (fixedTPM, fixedParent,
 * sensitiveDataOrigin, restricted, sign), named with SHA-256, on P-256.
 */
static const char *tpmCheckAk(const tpmPublic_t *ak) {

  if (ak->nameAlg != TPM_ALG_SHA256)
    return "AK nameAlg is not SHA-256";

  if ((ak->attributes & 0x50032) != 0x50032)
    return "AK is not a restricted signing key of the TPM";

  if (ak->type != TPM_ALG_ECC || ak->curve != TPM_ECC_NIST_P256)
    return "AK is not an ECC P-256 key";

  return NULL;
}

/* ---------------------------------------------------------- signatures */

/**
 * A TPMT_SIGNATURE (ECDSA, SHA-256) by `ak` over `data`. The signature
 * must fill its bytes exactly.
 */
static bool tpmVerify(const tpmPublic_t *ak, const void *data, size_t length,
                      const unsigned char *signature, size_t signatureLength) {

  tpmRead_t r = tpmReader(signature, signatureLength);
  size_t rl, sl;
  bool good = false;

  if (r.u16() != TPM_ALG_ECDSA || r.u16() != TPM_ALG_SHA256)
    return false;

  const unsigned char *rb = r.sized(&rl);
  const unsigned char *sb = r.sized(&sl);

  if (r.broke || r.left != 0 || rl == 0 || sl == 0 || rl > 66 || sl > 66)
    return false;

  EVP_PKEY *pkey = tpmEccKey(ak);
  ECDSA_SIG *sig = ECDSA_SIG_new();
  unsigned char *der = NULL;
  int derLength;

  if (pkey == NULL || sig == NULL ||
      !ECDSA_SIG_set0(sig, BN_bin2bn(rb, (int)rl, NULL), BN_bin2bn(sb, (int)sl, NULL)))
    goto done;

  derLength = i2d_ECDSA_SIG(sig, &der);

  EVP_MD_CTX *md = EVP_MD_CTX_new();
  good = derLength > 0 && md != NULL &&
         EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pkey) == 1 &&
         EVP_DigestVerify(md, der, (size_t)derLength, (const unsigned char *)data, length) == 1;
  EVP_MD_CTX_free(md);

done:
  OPENSSL_free(der);
  ECDSA_SIG_free(sig);
  EVP_PKEY_free(pkey);

  return good;
}

/* ------------------------------------------------------ make credential */

/**
 * KDFa (TPM 2.0 part 1, 11.4.10.2) with SHA-256: HMAC in counter mode over
 * counter || label NUL || contextU || contextV || bits.
 */
static bool tpmKdfa(const unsigned char *key, size_t keyLength, const char *label,
                    const unsigned char *u, size_t uLength, unsigned char *out, size_t bytes) {

  unsigned char block[32];
  uint32_t bits = (uint32_t)(bytes * 8);

  unsigned char input[4 + 16 + 64 + 4];
  size_t labelLength = strlen(label) + 1;

  if (labelLength > 16 || uLength > 64)
    return false;

  for (uint32_t counter = 1, done = 0; done < bytes; ++counter) {

    unsigned int length = 0;
    size_t n = 0;

    input[n++] = (unsigned char)(counter >> 24);
    input[n++] = (unsigned char)(counter >> 16);
    input[n++] = (unsigned char)(counter >> 8);
    input[n++] = (unsigned char)counter;
    memcpy(input + n, label, labelLength);
    n += labelLength;
    if (uLength > 0)
      memcpy(input + n, u, uLength);
    n += uLength;
    input[n++] = (unsigned char)(bits >> 24);
    input[n++] = (unsigned char)(bits >> 16);
    input[n++] = (unsigned char)(bits >> 8);
    input[n++] = (unsigned char)bits;

    if (HMAC(EVP_sha256(), key, (int)keyLength, input, n, block, &length) == NULL || length != 32)
      return false;

    size_t take = bytes - done < 32 ? bytes - done : 32;
    memcpy(out + done, block, take);
    done += (uint32_t)take;
  }

  return true;
}

static void put16(buf_t *out, unsigned v) {
  char b[2] = {(char)(v >> 8), (char)v};
  buf_t__add(out, b, 2);
}

/**
 * TPM2_MakeCredential for an RSA EK, in tpm2-tools' file format (what
 * tpm2_activatecredential -i reads): BADCC0DE, version 1, TPM2B_ID_OBJECT,
 * TPM2B_ENCRYPTED_SECRET.
 *
 * The seed goes to the EK under RSA-OAEP (SHA-256, label "IDENTITY"); from
 * it come the AES-CFB key that hides the secret, bound to the AK's name, and
 * the HMAC key that seals both. Only the TPM holding that EK, with that AK
 * loaded, gets the secret back.
 */
static const char *tpmMakeCredential(const tpmPublic_t *ek, const unsigned char akName[34],
                                     const unsigned char *secret, size_t secretLength,
                                     buf_t *out) {

  unsigned char seed[32], aesKey[32], hmacKey[32], hmac[32];
  unsigned char plain[2 + 64], cipher[2 + 64], iv[16] = {0};
  unsigned char encSeed[512];
  size_t encLength = sizeof encSeed;
  unsigned int hmacLength = 0;
  int written = 0, final = 0;
  const char *wrong = NULL;

  if (ek->type != TPM_ALG_RSA)
    return "EK is not an RSA key";

  if (ek->nameAlg != TPM_ALG_SHA256 || ek->symAlg != TPM_ALG_AES || ek->symMode != TPM_ALG_CFB ||
      (ek->symBits != 128 && ek->symBits != 256))
    return "EK template not supported (want SHA-256, AES-CFB)";

  if (secretLength == 0 || secretLength > 64 || !randomBytes(seed, sizeof seed))
    return "no secret";

  EVP_PKEY *pkey = tpmRsaKey(ek);
  EVP_PKEY_CTX *ctx = pkey != NULL ? EVP_PKEY_CTX_new(pkey, NULL) : NULL;
  char *label = OPENSSL_strdup("IDENTITY");

  /* the label includes its NUL, as the TPM computes it */
  if (ctx == NULL || label == NULL || EVP_PKEY_encrypt_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, 9) <= 0) {
    OPENSSL_free(label);
    wrong = "cannot encrypt to the EK";
    goto done;
  }

  if (EVP_PKEY_encrypt(ctx, encSeed, &encLength, seed, sizeof seed) <= 0) {
    wrong = "cannot encrypt to the EK";
    goto done;
  }

  size_t aesBytes = ek->symBits / 8;

  if (!tpmKdfa(seed, sizeof seed, "STORAGE", akName, 34, aesKey, aesBytes) ||
      !tpmKdfa(seed, sizeof seed, "INTEGRITY", NULL, 0, hmacKey, 32)) {
    wrong = "KDFa failed";
    goto done;
  }

  plain[0] = (unsigned char)(secretLength >> 8);
  plain[1] = (unsigned char)secretLength;
  memcpy(plain + 2, secret, secretLength);

  EVP_CIPHER_CTX *aes = EVP_CIPHER_CTX_new();
  bool encrypted = aes != NULL &&
                   EVP_EncryptInit_ex(aes, aesBytes == 16 ? EVP_aes_128_cfb128() : EVP_aes_256_cfb128(),
                                      NULL, aesKey, iv) == 1 &&
                   EVP_EncryptUpdate(aes, cipher, &written, plain, (int)(2 + secretLength)) == 1 &&
                   EVP_EncryptFinal_ex(aes, cipher + written, &final) == 1;
  EVP_CIPHER_CTX_free(aes);

  size_t cipherLength = (size_t)(written + final);

  unsigned char sealedInput[66 + 34];
  memcpy(sealedInput, cipher, cipherLength);
  memcpy(sealedInput + cipherLength, akName, 34);

  bool sealed = encrypted &&
                HMAC(EVP_sha256(), hmacKey, 32, sealedInput, cipherLength + 34, hmac, &hmacLength) != NULL &&
                hmacLength == 32;

  if (!sealed) {
    wrong = "cannot seal the credential";
    goto done;
  }

  buf_t__add(out, "\xba\xdc\xc0\xde\x00\x00\x00\x01", 8);
  put16(out, 2 + 32 + (unsigned)cipherLength);
  put16(out, 32);
  buf_t__add(out, (const char *)hmac, 32);
  buf_t__add(out, (const char *)cipher, cipherLength);
  put16(out, (unsigned)encLength);
  buf_t__add(out, (const char *)encSeed, encLength);

  if (out->broke)
    wrong = "no memory";

done:
  OPENSSL_cleanse(seed, sizeof seed);
  OPENSSL_cleanse(aesKey, sizeof aesKey);
  OPENSSL_cleanse(hmacKey, sizeof hmacKey);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  return wrong;
}

/* --------------------------------------------------------------- attests */

#define TPM_GENERATED 0xff544347u
#define TPM_ST_ATTEST_NV 0x8014
#define TPM_ST_ATTEST_QUOTE 0x8018

/** The common head of a TPMS_ATTEST; leaves `r` at the attested part. */
static bool tpmAttestHead(tpmRead_t *r, unsigned type, const unsigned char *nonce,
                          size_t nonceLength) {

  size_t n;

  if (r.u32() != TPM_GENERATED || r.u16() != type)
    return false;

  r.sized(&n); /* qualifiedSigner */

  const unsigned char *extra = r.sized(&n);

  if (r->broke || n != nonceLength || CRYPTO_memcmp(extra, nonce, n) != 0)
    return false;

  r.take(17 + 8); /* clockInfo, firmwareVersion */

  return !r->broke;
}

/** PCR values of the SHA-256 bank, by index. */
typedef struct {
  unsigned char value[24][32];
  uint32_t present;
} tpmPcrs_t;

static uint32_t le32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/**
 * tpm2-tools' "serialized" PCR file (tpm2_quote -o): TPML_PCR_SELECTION and
 * then TPML_DIGESTs as the C structures lie in memory on x86-64 - 132 bytes,
 * a count, and 532 bytes per list. What it says is only believed once it
 * hashes to the digest the AK signed (tpmCheckQuote).
 */
static const char *tpmPcrFile(const unsigned char *data, size_t length, tpmPcrs_t *out,
                              uint32_t *selected) {

  memset(out, 0, sizeof *out);
  *selected = 0;

  if (length < 136 || le32(data) != 1)
    return "PCR file: expected one bank";

  const unsigned char *sel = data + 4;
  unsigned hash = (unsigned)(sel[0] | sel[1] << 8);
  unsigned size = sel[2];

  if (hash != TPM_ALG_SHA256 || size < 1 || size > 3)
    return "PCR file: expected the SHA-256 bank";

  for (unsigned i = 0; i < size * 8; ++i)
    if (sel[3 + i / 8] & (1u << (i % 8)))
      *selected |= 1u << i;

  uint32_t lists = le32(data + 132);

  if (lists == 0 || lists > 3 || length != 136 + (size_t)lists * 532)
    return "PCR file: wrong size";

  unsigned pcr = 0;

  for (uint32_t l = 0; l < lists; ++l) {

    const unsigned char *list = data + 136 + l * 532;
    uint32_t count = le32(list);

    if (count > 8)
      return "PCR file: list too long";

    for (uint32_t d = 0; d < count; ++d) {

      const unsigned char *digest = list + 4 + d * 66;

      while (pcr < 24 && !(*selected & (1u << pcr)))
        ++pcr;

      if (pcr == 24 || (digest[0] | digest[1] << 8) != 32)
        return "PCR file: values do not fit the selection";

      memcpy(out->value[pcr], digest + 2, 32);
      out->present |= 1u << pcr;
      ++pcr;
    }
  }

  if (out->present != *selected)
    return "PCR file: values missing";

  return NULL;
}

/**
 * The quote: generated by the TPM, over this nonce, signed by the AK, for a
 * SHA-256 selection that is the one in the PCR file - whose values hash to
 * the signed digest. Then they are what the TPM had.
 */
static const char *tpmCheckQuote(const tpmPublic_t *ak, const unsigned char *msg, size_t msgLength,
                                 const unsigned char *sig, size_t sigLength,
                                 const unsigned char *pcrFile, size_t pcrLength,
                                 const unsigned char *nonce, size_t nonceLength, tpmPcrs_t *pcrs) {

  uint32_t fileSelected, quoteSelected = 0;
  const char *wrong;
  size_t n;

  if (!tpmVerify(ak, msg, msgLength, sig, sigLength))
    return "quote not signed by the AK";

  tpmRead_t r = tpmReader(msg, msgLength);

  if (!tpmAttestHead(&r, TPM_ST_ATTEST_QUOTE, nonce, nonceLength))
    return "quote is not a TPM quote over this session's nonce";

  if (r.u32() != 1 || r.u16() != TPM_ALG_SHA256)
    return "quote is not over the SHA-256 bank alone";

  unsigned size = r.take(1) != NULL ? r.at[-1] : 0;
  const unsigned char *bits = r.take(size);

  for (unsigned i = 0; bits != NULL && size <= 3 && i < size * 8; ++i)
    if (bits[i / 8] & (1u << (i % 8)))
      quoteSelected |= 1u << i;

  const unsigned char *digest = r.sized(&n);

  if (r.broke || r.left != 0 || n != 32)
    return "quote cannot be read";

  if ((wrong = tpmPcrFile(pcrFile, pcrLength, pcrs, &fileSelected)) != NULL)
    return wrong;

  if (fileSelected != quoteSelected)
    return "PCR file is not for the quoted selection";

  EVP_MD_CTX *md = EVP_MD_CTX_new();
  unsigned char got[32];
  unsigned int gotLength = 0;
  bool hashed = md != NULL && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;

  for (unsigned i = 0; hashed && i < 24; ++i)
    if (quoteSelected & (1u << i))
      hashed = EVP_DigestUpdate(md, pcrs->value[i], 32) == 1;

  hashed = hashed && EVP_DigestFinal_ex(md, got, &gotLength) == 1;
  EVP_MD_CTX_free(md);

  if (!hashed || CRYPTO_memcmp(got, digest, 32) != 0)
    return "PCR values do not match the quote";

  return NULL;
}

/**
 * The replay stand: an AK-signed certification of an 8-byte NV index over
 * this session's nonce. Answers the index name (hex) and the value.
 */
static const char *tpmNvCounter(const tpmPublic_t *ak, const unsigned char *att, size_t attLength,
                                const unsigned char *sig, size_t sigLength,
                                const unsigned char *nonce, size_t nonceLength,
                                char nameHex[80], long *value) {

  size_t n, m;

  if (!tpmVerify(ak, att, attLength, sig, sigLength))
    return "replay stand not signed by the AK of this vTPM";

  tpmRead_t r = tpmReader(att, attLength);

  if (!tpmAttestHead(&r, TPM_ST_ATTEST_NV, nonce, nonceLength))
    return "replay stand is not an NV certification over this session's nonce";

  const unsigned char *name = r.sized(&n);
  unsigned offset = r.u16();
  const unsigned char *contents = r.sized(&m);

  if (r.broke || r.left != 0 || n == 0 || n > 39 || offset != 0 || m != 8)
    return "replay stand incomplete";

  toHex(name, n, nameHex);

  uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v = v << 8 | contents[i];

  if (v > (uint64_t)LONG_MAX)
    return "replay stand out of range";

  *value = (long)v;

  return NULL;
}

#endif /* WX_TPM_H */

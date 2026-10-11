/**
 * How a disk key travels to the guest: wrapped for the fresh RSA key the
 * guest made for this one release, the way PKCS#11 calls CKM_RSA_AES_KEY_WRAP
 * and OpenBao's transit/byok-export writes it -
 *
 *   RSA-OAEP(guest key, AES-256 key made for this once) || AES-KWP(that key, disk key)
 *
 * AES-KWP is RFC 5649. The guest takes the first modulus-length bytes apart
 * with its private key, unwraps the rest with what came out, and uses the 32
 * bytes in base64 as the LUKS passphrase.
 *
 * The key store does the wrapping, so the disk key is never in the clear here.
 * What the agent does itself is only the other side, to check at start-up that
 * the key store writes exactly this, and importing old keys into transit.
 */
#ifndef WX_WRAP_H
#define WX_WRAP_H

#include "util.h"

#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/** What the answer says, and what the guest must ask for. */
static const char wrapName[] = "rsa-aes-kwp";

/** The OAEP hash: SHA-256, or SHA-1 for a key store that cannot do better. */
static const EVP_MD *wrapOaepMd(bool sha1) {
  return sha1 ? EVP_sha1() : EVP_sha256();
}

/** The guest's key from DER (SubjectPublicKeyInfo); RSA of 3072 bits or more, else NULL. */
static EVP_PKEY *wrapGuestKey(const unsigned char *der, size_t length) {

  const unsigned char *p = der;
  EVP_PKEY *key = d2i_PUBKEY(NULL, &p, (long)length);

  if (key != NULL && (p != der + length || EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA ||
                      EVP_PKEY_get_bits(key) < 3072)) {
    EVP_PKEY_free(key);
    key = NULL;
  }

  return key;
}

/** A public key as PEM text (what transit imports); owned. */
static char *wrapPem(EVP_PKEY *key) {

  BIO *out = BIO_new(BIO_s_mem());
  char *pem = NULL, *at;
  long length;

  if (out != NULL && PEM_write_bio_PUBKEY(out, key) == 1 && (length = BIO_get_mem_data(out, &at)) > 0 &&
      (pem = (char *)malloc((size_t)length + 1)) != NULL) {
    memcpy(pem, at, (size_t)length);
    pem[length] = 0;
  }

  BIO_free(out);

  return pem;
}

/** RSA-OAEP with `md` for MGF1 as well, in either direction. */
static bool wrapRsa(EVP_PKEY *key, bool encrypt, const EVP_MD *md, const unsigned char *in,
                    size_t length, unsigned char *out, size_t *outLength) {

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);

  bool good = ctx != NULL && (encrypt ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx)) > 0 &&
              EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
              EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) > 0 && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0 &&
              (encrypt ? EVP_PKEY_encrypt(ctx, out, outLength, in, length)
                       : EVP_PKEY_decrypt(ctx, out, outLength, in, length)) > 0;

  EVP_PKEY_CTX_free(ctx);

  return good;
}

/** AES-256 KWP (RFC 5649), in either direction; the output's length, or -1. */
static long wrapKwp(const unsigned char aes[32], bool wrap, const unsigned char *in, size_t length,
                    unsigned char *out, size_t room) {

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0, last = 0;

  if (ctx == NULL || room < length + 16)
    return EVP_CIPHER_CTX_free(ctx), -1;

  /* a wrap cipher has to be allowed on the context, else OpenSSL refuses it */
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

  bool good = EVP_CipherInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, aes, NULL, wrap ? 1 : 0) == 1 &&
              EVP_CipherUpdate(ctx, out, &n, in, (int)length) == 1 &&
              EVP_CipherFinal_ex(ctx, out + n, &last) == 1;

  EVP_CIPHER_CTX_free(ctx);

  return good ? n + last : -1;
}

/** Wraps `raw` for `key` as above; the length written to `out`, or -1. Used to
    import a key into transit (its wrapping key) - the one place it is in the clear. */
static long wrapFor(EVP_PKEY *key, const EVP_MD *md, const unsigned char *raw, size_t length,
                    unsigned char *out, size_t room) {

  unsigned char aes[32];
  size_t rsaLength = room;

  if (!randomBytes(aes, sizeof aes) || !wrapRsa(key, true, md, aes, sizeof aes, out, &rsaLength)) {
    OPENSSL_cleanse(aes, sizeof aes);
    return -1;
  }

  long kwp = wrapKwp(aes, true, raw, length, out + rsaLength, room - rsaLength);
  OPENSSL_cleanse(aes, sizeof aes);

  return kwp < 0 ? -1 : (long)rsaLength + kwp;
}

/** The other way, with the private key: the key's length in `out`, or -1. */
static long wrapOpen(EVP_PKEY *key, const EVP_MD *md, const unsigned char *wrapped, size_t length,
                     unsigned char *out, size_t room) {

  size_t rsaLength = (size_t)EVP_PKEY_get_size(key);
  /* room for a whole modulus: OpenSSL asks for that much, whatever comes out */
  unsigned char aes[1024];
  size_t aesLength = sizeof aes;

  if (length <= rsaLength || !wrapRsa(key, false, md, wrapped, rsaLength, aes, &aesLength) ||
      aesLength != 32)
    return -1;

  long n = wrapKwp(aes, false, wrapped + rsaLength, length - rsaLength, out, room);
  OPENSSL_cleanse(aes, sizeof aes);

  return n;
}

/** A throwaway guest key for the start-up check. */
static EVP_PKEY *wrapTestKey(void) {
  return EVP_RSA_gen(3072);
}

/** DER of a key's public half (what a guest sends), into `out`; its length or -1. */
static long wrapPublicDer(EVP_PKEY *key, unsigned char *out, size_t room) {

  int length = i2d_PUBKEY(key, NULL);
  unsigned char *p = out;

  if (length <= 0 || (size_t)length > room)
    return -1;

  return i2d_PUBKEY(key, &p) == length ? length : -1;
}

#endif /* WX_WRAP_H */

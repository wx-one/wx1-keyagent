/**
 * OpenBao as the key store: its transit engine holds the disk keys and the key
 * the agent's state is signed with, and does everything with them itself.
 *
 *   transit/keys/wx1-disk-<disk>   AES-256, exportable only wrapped (byok-export)
 *   transit/keys/wx1-state         signs the state in the database (HMAC)
 *   transit/keys/wx1-guest-<..>    a guest's public key, for the one release
 *
 * A disk key leaves OpenBao only wrapped for the guest's fresh key
 * (wrap.h); deploy/openbao-policy.hcl denies the plain export.
 */
#ifndef WX_BAO_H
#define WX_BAO_H

#include "wrap.h"

#include <meta_fetch.h>
#include <meta_json.h>
#include <meta_text.h>

static char baoUrl[512];
static char baoToken[256];
static char baoMount[64];

static bool baoConfigure(void) {

  text_t url = TEXT`${env("WX_OPENBAO_URL", "http://127.0.0.1:8200")}`;
  url.into(baoUrl, sizeof baoUrl);

  text_t mount = TEXT`${env("WX_OPENBAO_TRANSIT", "transit")}`;
  mount.into(baoMount, sizeof baoMount);

  return readSecret(env("WX_OPENBAO_TOKEN_FILE", "/secrets/openbao-token"), baoToken,
                    sizeof baoToken);
}

static fetch_answer_t baoCall(const char *method, const char *path, const char *body) {

  char url[1024];

  text_t at = TEXT`${baoUrl}/v1/${path}`;

  at.into(url, sizeof url);

  fetch_call_t call = meta_fetch(method, url).header("x-vault-token", baoToken);

  if (body != NULL)
    call = call.json(body);

  return call.send();
}

/** A call on the transit mount: `path` below it. */
static fetch_answer_t transitCall(const char *method, const char *path, const char *body) {

  char at[512];

  text_t p = TEXT`${baoMount}/${path}`;
  p.into(at, sizeof at);

  return baoCall(method, at, body);
}

/** A call on the transit mount with a document as its body. */
static fetch_answer_t transitWith(const char *method, const char *path, json_t body) {

  char *text = body.owned();
  fetch_answer_t got = transitCall(method, path, text ?: "{}");

  free(text);

  return got;
}

/** The status of a call whose answer is not needed. */
static int transitDo(const char *method, const char *path) {

  fetch_answer_t got = transitCall(method, path, NULL);
  int status = got.status;

  got.release();

  return status;
}

/** The status of a POST whose answer is not needed. */
static int transitPost(const char *path, json_t body) {

  fetch_answer_t got = transitWith("POST", path, body);
  int status = got.status;

  got.release();

  return status;
}

/** Removes a key for good. A key absent already is fine. */
static bool transitDelete(const char *name) {

  char path[200];

  text_t c = TEXT`keys/${name}/config`;
  c.into(path, sizeof path);

  int status = transitPost(path, {deletion_allowed: true});

  if (status == 404 || status == 400) {
    text_t k = TEXT`keys/${name}`;
    k.into(path, sizeof path);
    return transitDo("GET", path) == 404;
  }

  if (status / 100 != 2)
    return false;

  text_t k = TEXT`keys/${name}`;
  k.into(path, sizeof path);

  status = transitDo("DELETE", path);

  return status / 100 == 2 || status == 404;
}

/**
 * The transit mount and the state key there. Enabled here if the token may
 * (a root token in a test); a token with the agent's own policy may not, and
 * then the operator enables it once. Either way, making the state key - which
 * changes nothing when it exists - says whether it is usable.
 */
static bool transitEnsure(void) {

  char path[200];

  text_t m = TEXT`sys/mounts/${baoMount}`;
  m.into(path, sizeof path);

  json_t mount = {type: "transit"};
  char *text = mount.owned();
  mount.release();

  fetch_answer_t made = baoCall("POST", path, text);
  made.release();
  free(text);

  return transitPost("keys/wx1-state", {type: "aes256-gcm96"}) / 100 == 2;
}

/** A disk's key name. */
static void transitDiskKey(const char *diskId, char *name, size_t room) {
  text_t n = TEXT`wx1-disk-${diskId}`;
  n.into(name, room);
}

/** A fresh key for the disk; an old one is destroyed first. */
static bool transitNew(const char *diskId) {

  char name[96], path[160];

  transitDiskKey(diskId, name, sizeof name);

  if (!transitDelete(name))
    return false;

  text_t k = TEXT`keys/${name}`;
  k.into(path, sizeof path);

  return transitPost(path, {type: "aes256-gcm96", exportable: true}) / 100 == 2;
}

/** Brings `raw` (32 bytes) in as the key `name`: wrapped for transit's own wrapping key. */
static bool transitImportAs(const char *name, const unsigned char *raw, size_t length) {

  char path[160];
  unsigned char wrapped[1024];
  bool done = false;

  fetch_answer_t got = transitCall("GET", "wrapping_key", NULL);

  if (!got.ok) {
    got.release();
    return false;
  }

  json_t doc = got.json();
  got.release();

  const char *pem = doc.data.public_key.text();
  BIO *in = pem != NULL ? BIO_new_mem_buf(pem, -1) : NULL;
  EVP_PKEY *key = in != NULL ? PEM_read_bio_PUBKEY(in, NULL, NULL, NULL) : NULL;
  BIO_free(in);
  doc.release();

  long n = key != NULL ? wrapFor(key, EVP_sha256(), raw, length, wrapped, sizeof wrapped) : -1;
  EVP_PKEY_free(key);

  if (n > 0) {
    char *b64 = (char *)malloc((size_t)n / 3 * 4 + 8);

    if (b64 != NULL) {
      toBase64(wrapped, (size_t)n, b64);

      text_t k = TEXT`keys/${name}/import`;
      k.into(path, sizeof path);

      done = transitPost(path, {ciphertext: b64, type: "aes256-gcm96", hash_function: "SHA256",
                                exportable: true}) / 100 == 2;

      free(b64);
    }
  }

  OPENSSL_cleanse(wrapped, sizeof wrapped);

  return done;
}

/** An old key (from KV) as the disk's key in transit. */
static bool transitImport(const char *diskId, const unsigned char *raw, size_t length) {

  char name[96];

  transitDiskKey(diskId, name, sizeof name);

  return transitDelete(name) && transitImportAs(name, raw, length);
}

/**
 * Key `name` wrapped for the guest's key, in base64 into `out`. NULL, or why
 * not. Transit takes RSA of 3072 or 4096 bits.
 */
static const char *transitWrapNamed(const char *name, EVP_PKEY *guest, char *out, size_t room) {

  char guestName[64], path[256], hex[33];
  int bits = EVP_PKEY_get_bits(guest);
  const char *wrong = NULL;

  if (bits != 3072 && bits != 4096)
    return "guest key unusable (want RSA 3072 or 4096)";

  if (!randomHex(16, hex))
    return "no randomness";

  char *pem = wrapPem(guest);

  if (pem == NULL)
    return "no memory";

  text_t g = TEXT`wx1-guest-${hex}`;
  g.into(guestName, sizeof guestName);

  text_t type = TEXT`rsa-${bits}`;
  char typeText[16];
  type.into(typeText, sizeof typeText);

  text_t i = TEXT`keys/${guestName}/import`;
  i.into(path, sizeof path);

  int status = transitPost(path, {public_key: pem, type: (const char *)typeText});
  free(pem);

  if (status / 100 != 2)
    return "key store refused the guest key (OpenBao)";

  text_t e = TEXT`byok-export/${guestName}/${name}/latest`;
  e.into(path, sizeof path);

  fetch_answer_t got = transitCall("GET", path, NULL);

  if (got.status == 400 || got.status == 404) {
    wrong = "disk key not found (OpenBao)";
  } else if (!got.ok) {
    wrong = "key store cannot wrap the disk key (OpenBao)";
  } else {
    /* {"keys": {"<version>": "<wrapped>"}}, one version since it asks for the latest */
    json_t doc = got.json();
    json_t keys = doc.data.keys;
    const char *wrapped = keys[keys.keyAt(0)].text();

    if (wrapped == NULL || strlen(wrapped) + 1 > room)
      wrong = "key store answered no wrapped key (OpenBao)";
    else
      memcpy(out, wrapped, strlen(wrapped) + 1);

    doc.release();
  }

  got.release();
  transitDelete(guestName);

  return wrong;
}

static const char *transitWrap(const char *diskId, EVP_PKEY *guest, char *out, size_t room) {

  char name[96];

  transitDiskKey(diskId, name, sizeof name);

  return transitWrapNamed(name, guest, out, room);
}

static bool transitShred(const char *diskId) {

  char name[96];

  transitDiskKey(diskId, name, sizeof name);

  return transitDelete(name);
}

/** HMAC-SHA256 of `message` with the state key: "vault:v<n>:<base64>". */
static bool transitMac(const char *message, size_t length, char *mac, size_t room) {

  char *b64 = (char *)malloc(length / 3 * 4 + 8);
  bool done = false;

  if (b64 == NULL)
    return false;

  toBase64((const unsigned char *)message, length, b64);

  fetch_answer_t got = transitWith("POST", "hmac/wx1-state/sha2-256", {input: b64});
  free(b64);

  if (got.ok) {
    json_t doc = got.json();
    const char *h = doc.data.hmac.text();

    if (h != NULL && strlen(h) + 1 <= room) {
      memcpy(mac, h, strlen(h) + 1);
      done = true;
    }

    doc.release();
  }

  got.release();

  return done;
}

/** 1 when `mac` belongs to `message`, 0 when not, -1 when OpenBao cannot say. */
static int transitMacOk(const char *message, size_t length, const char *mac) {

  char *b64 = (char *)malloc(length / 3 * 4 + 8);
  int valid = -1;

  if (b64 == NULL)
    return -1;

  toBase64((const unsigned char *)message, length, b64);

  fetch_answer_t got = transitWith("POST", "verify/wx1-state/sha2-256", {input: b64, hmac: mac});
  free(b64);

  if (got.ok) {
    json_t doc = got.json();
    valid = doc.data.valid.truth() ? 1 : 0;
    doc.release();
  } else if (got.status == 400) {
    /* a mac that is not one of ours at all */
    valid = 0;
  }

  got.release();

  return valid;
}

/**
 * Whether transit writes exactly what the guest expects: a known key
 * imported, wrapped for a throwaway guest key, opened here. NULL, or why not.
 */
static const char *transitSelfTest(void) {

  unsigned char raw[32], back[64];
  char name[64], hex[33], wrapped[1400];
  unsigned char bytes[1100];
  const char *wrong = NULL;

  if (!randomBytes(raw, sizeof raw) || !randomHex(16, hex))
    return "no randomness";

  text_t n = TEXT`wx1-check-${hex}`;
  n.into(name, sizeof name);

  EVP_PKEY *guest = wrapTestKey();

  if (guest == NULL)
    return "cannot make a test key";

  if (!transitImportAs(name, raw, sizeof raw)) {
    wrong = "transit does not import a key (BYOK import, transit/wrapping_key)";
  } else if ((wrong = transitWrapNamed(name, guest, wrapped, sizeof wrapped)) == NULL) {
    long length = fromBase64(wrapped, bytes, sizeof bytes);
    long opened = length > 0 ? wrapOpen(guest, EVP_sha256(), bytes, (size_t)length, back, sizeof back) : -1;

    if (opened != 32 || CRYPTO_memcmp(back, raw, 32) != 0)
      wrong = "transit's byok-export is not RSA-OAEP(SHA-256) + AES-KWP";
  }

  transitDelete(name);
  EVP_PKEY_free(guest);
  OPENSSL_cleanse(raw, sizeof raw);
  OPENSSL_cleanse(back, sizeof back);

  return wrong;
}

#endif /* WX_BAO_H */

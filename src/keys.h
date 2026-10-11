/**
 * The key store: where the disk keys are and the key the state is signed with.
 * WX_KEYSTORE picks it -
 *
 *   openbao   OpenBao's transit engine (bao.h), the default
 *   pkcs11    a PKCS#11 token, an HSM (p11.h)
 *
 * Either way the agent never holds a disk key: the store makes it, wraps it
 * for the guest (wrap.h) and destroys it. What the agent keeps in its
 * database it signs here, so the database alone cannot bind a disk to
 * another VM.
 */
#ifndef WX_KEYS_H
#define WX_KEYS_H

#include "bao.h"
#include "p11.h"

static bool keysPkcs11;

static const char *keysName(void) {
  return keysPkcs11 ? "PKCS#11" : "OpenBao";
}

/**
 * Configures the store from the environment. `check`: in the master, once -
 * reachable, the state key there, and that it wraps exactly as the guest
 * expects. NULL, or why the agent cannot start.
 */
static const char *keysConfigure(bool check) {

  static char why[400];
  const char *store = env("WX_KEYSTORE", "openbao");
  const char *wrong;

  if (strcmp(store, "openbao") != 0 && strcmp(store, "pkcs11") != 0)
    return "WX_KEYSTORE is openbao or pkcs11";

  keysPkcs11 = strcmp(store, "pkcs11") == 0;

  if (keysPkcs11) {

    if ((wrong = p11Open()) != NULL)
      return wrong;

    if (!check)
      return NULL;

    wrong = p11Check();
    p11Close();

    return wrong;
  }

  if (!baoConfigure()) {
    snprintf(why, sizeof why, "no OpenBao token in %s, nothing to release without it",
             env("WX_OPENBAO_TOKEN_FILE", "/secrets/openbao-token"));
    return why;
  }

  if (!check)
    return NULL;

  fetch_answer_t health = baoCall("GET", "sys/health", NULL);
  int status = health.status;
  health.release();

  if (status != 200) {
    snprintf(why, sizeof why, "OpenBao does not answer at %s (%d)", baoUrl, status);
    return why;
  }

  if (!transitEnsure()) {
    snprintf(why, sizeof why,
             "the transit mount %s/ in OpenBao is missing or not ours: bao secrets enable "
             "-path=%s transit, and the policy in deploy/openbao-policy.hcl",
             baoMount, baoMount);
    return why;
  }

  return transitSelfTest();
}

/** A fresh key for the disk; one it had before is destroyed. */
static bool keyNew(const char *diskId) {
  return keysPkcs11 ? p11New(diskId) : transitNew(diskId);
}

/** The disk key wrapped for the guest, base64 into `out`. NULL, or why not. */
static const char *keyWrap(const char *diskId, const unsigned char *guestDer, size_t length, char *out,
                           size_t room) {

  EVP_PKEY *guest = wrapGuestKey(guestDer, length);

  if (guest == NULL)
    return "guest key unusable (want RSA 3072 or more)";

  const char *wrong = keysPkcs11 ? p11Wrap(diskId, guest, out, room) : transitWrap(diskId, guest, out, room);

  EVP_PKEY_free(guest);

  return wrong;
}

/** Crypto-shredding: the disk key destroyed in the store. */
static bool keyShred(const char *diskId) {
  return keysPkcs11 ? p11Shred(diskId) : transitShred(diskId);
}

/** The OAEP hash the store wraps with, as the answer names it. */
static const char *keyOaep(void) {
  return keysPkcs11 && p11Sha1 ? "sha1" : "sha256";
}

/** A signature over `message` with the state key, as text into `mac`. */
static bool keysMac(const char *message, size_t length, char *mac, size_t room) {
  return keysPkcs11 ? p11Mac(message, length, mac, room) : transitMac(message, length, mac, room);
}

/** 1 when `mac` is the state key's over `message`, 0 when not, -1 when the store cannot say. */
static int keysMacOk(const char *message, size_t length, const char *mac) {
  return keysPkcs11 ? p11MacOk(message, length, mac) : transitMacOk(message, length, mac);
}

#endif /* WX_KEYS_H */

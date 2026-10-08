/**
 * tpm.h against what real tpm2-tools wrote (test/tpm.sh makes it with
 * swtpm): reads the AK, quote, PCR file and NV certification, and writes a
 * credential for the EK that tpm2_activatecredential then has to open.
 *
 *   tpmtest <dir>     files as test/tpm.sh leaves them
 */
#include "tpm.h"

static long slurp(const char *dir, const char *name, unsigned char *into, size_t room) {

  char path[512];
  snprintf(path, sizeof path, "%s/%s", dir, name);

  FILE *in = fopen(path, "rb");

  if (in == NULL)
    return -1;

  long n = (long)fread(into, 1, room, in);
  fclose(in);

  return n;
}

static int failed;

static void expect(bool good, const char *what) {
  printf("%s %s\n", good ? "ok  " : "FAIL", what);
  failed += !good;
}

int main(int argc, char **argv) {

  static unsigned char ak[512], ek[1024], msg[512], sig[256], pcrs[4096], att[512], nvsig[256];
  unsigned char nonce[32], name[34], secret[32];
  char nonceHex[80] = {0}, nvName[80];
  const char *dir = argc > 1 ? argv[1] : ".";
  tpmPublic_t akKey, ekKey;
  tpmPcrs_t values;
  long v = -1;

  long akLength = slurp(dir, "ak.pub", ak, sizeof ak);
  long ekLength = slurp(dir, "ek.pub", ek, sizeof ek);
  long msgLength = slurp(dir, "msg", msg, sizeof msg);
  long sigLength = slurp(dir, "sig", sig, sizeof sig);
  long pcrLength = slurp(dir, "pcrs", pcrs, sizeof pcrs);
  long attLength = slurp(dir, "nvatt", att, sizeof att);
  long nvsigLength = slurp(dir, "nvsig", nvsig, sizeof nvsig);
  slurp(dir, "qnonce", (unsigned char *)nonceHex, 64);
  fromHex(nonceHex, nonce, sizeof nonce);

  /* files hold TPM2B_PUBLIC; the SVSM manifest and our parser want TPMT_PUBLIC */
  expect(tpmPublic(ak + 2, (size_t)akLength - 2, &akKey), "AK parses");
  expect(tpmCheckAk(&akKey) == NULL, "AK is a restricted signing key");
  expect(tpmPublic(ek + 2, (size_t)ekLength - 2, &ekKey), "EK parses");

  const char *q = tpmCheckQuote(&akKey, msg, (size_t)msgLength, sig, (size_t)sigLength, pcrs,
                                (size_t)pcrLength, nonce, 32, &values);
  printf("     quote: %s\n", q ?: "-");
  expect(q == NULL, "quote verifies");
  expect(values.present == 0x3ff, "PCR 0-9 present");

  char pcr0[65];
  toHex(values.value[0], 32, pcr0);
  printf("     pcr0 %s\n", pcr0);

  /* a flipped bit anywhere must fail */
  msg[msgLength - 1] ^= 1;
  expect(tpmCheckQuote(&akKey, msg, (size_t)msgLength, sig, (size_t)sigLength, pcrs,
                       (size_t)pcrLength, nonce, 32, &values) != NULL, "tampered quote refused");
  msg[msgLength - 1] ^= 1;
  pcrs[150] ^= 1;
  expect(tpmCheckQuote(&akKey, msg, (size_t)msgLength, sig, (size_t)sigLength, pcrs,
                       (size_t)pcrLength, nonce, 32, &values) != NULL, "tampered PCR value refused");
  pcrs[150] ^= 1;
  nonce[0] ^= 1;
  expect(tpmCheckQuote(&akKey, msg, (size_t)msgLength, sig, (size_t)sigLength, pcrs,
                       (size_t)pcrLength, nonce, 32, &values) != NULL, "other nonce refused");

  const char *n = tpmNvCounter(&akKey, att, (size_t)attLength, nvsig, (size_t)nvsigLength, nonce,
                               32, nvName, &v);
  expect(n != NULL, "NV stand over other nonce refused");
  nonce[0] ^= 1;
  n = tpmNvCounter(&akKey, att, (size_t)attLength, nvsig, (size_t)nvsigLength, nonce, 32, nvName,
                   &v);
  printf("     nv: %s name=%s value=%ld\n", n ?: "-", n ? "" : nvName, v);
  expect(n == NULL && v == 5, "NV stand verifies, value 5");

  /* a credential for the activate test */
  buf_t cred = {0};
  tpmName(&akKey, name);
  slurp(dir, "secret", secret, sizeof secret);
  const char *c = tpmMakeCredential(&ekKey, name, secret, 32, &cred);
  printf("     credential: %s (%zu bytes)\n", c ?: "-", cred.length);
  expect(c == NULL && cred.length == 336, "credential made");

  char path[512];
  snprintf(path, sizeof path, "%s/cred.ours", dir);
  FILE *out = fopen(path, "wb");
  fwrite(cred.at, 1, cred.length, out);
  fclose(out);

  return failed != 0;
}

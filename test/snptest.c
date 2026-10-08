/**
 * snp.h and the EK side of tpm.h against reports a guest produced:
 *   snptest <dir> <measurements>
 * <dir> holds nonce, snp, svsm, manifest (test/snp-sample.sh fetches them)
 * and a KDS cache under kds/ (WX_KDS).
 */
#include "snp.h"
#include "tpm.h"

static int failed;

static void expect(bool good, const char *what) {
  printf("%s %s\n", good ? "ok  " : "FAIL", what);
  failed += !good;
}

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

int main(int argc, char **argv) {

  static unsigned char snp[2048], svsm[2048], manifest[1024], nonce[64];
  unsigned char both[64 + 1024], digest[64];
  snpReport_t guest, vtpm;
  tpmPublic_t ek;

  long g = slurp(argv[1], "snp", snp, sizeof snp);
  long v = slurp(argv[1], "svsm", svsm, sizeof svsm);
  long m = slurp(argv[1], "manifest", manifest, sizeof manifest);
  slurp(argv[1], "nonce", nonce, sizeof nonce);

  const char *a = snpVerify(snp, (size_t)g, argv[2], &guest);
  printf("     guest: %s vmpl=%u chip=%.16s.. tcb=%02x%02x..%02x%02x\n", a ?: "-", guest.vmpl,
         guest.chipId, guest.tcb[0], guest.tcb[1], guest.tcb[6], guest.tcb[7]);
  expect(a == NULL, "guest report verifies");
  expect(guest.vmpl == 2, "guest report from VMPL2");
  expect(memcmp(guest.reportData, nonce, 64) == 0, "guest report carries the nonce");

  const char *b = snpVerify(svsm, (size_t)v, argv[2], &vtpm);
  printf("     svsm: %s vmpl=%u\n", b ?: "-", vtpm.vmpl);
  expect(b == NULL && vtpm.vmpl == 0, "SVSM report verifies, VMPL0");
  expect(strcmp(vtpm.reportId, guest.reportId) == 0, "same REPORT_ID");

  memcpy(both, nonce, 64);
  memcpy(both + 64, manifest, (size_t)m);
  SHA512(both, 64 + (size_t)m, digest);
  expect(memcmp(vtpm.reportData, digest, 64) == 0, "SVSM report binds nonce and EK");

  snp[0x100] ^= 1;
  expect(snpVerify(snp, (size_t)g, argv[2], &guest) != NULL, "tampered report refused");
  snp[0x100] ^= 1;
  expect(snpVerify(snp, (size_t)g, "00", &guest) != NULL, "unknown measurement refused");

  bool parsed = tpmPublic(manifest, (size_t)m, &ek);
  printf("     EK: type=%04x nameAlg=%04x sym=%04x/%u/%04x n=%zu\n", ek.type, ek.nameAlg,
         ek.symAlg, ek.symBits, ek.symMode, ek.modulusLength);
  expect(parsed, "manifest is a TPMT_PUBLIC");

  unsigned char name[34] = {0}, secret[32] = {1};
  buf_t cred = {0};
  const char *c = tpmMakeCredential(&ek, name, secret, 32, &cred);
  printf("     credential: %s\n", c ?: "-");
  expect(c == NULL, "credential for the SVSM's EK");

  return failed != 0;
}

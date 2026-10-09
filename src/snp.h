/**
 * SEV-SNP attestation reports: parsed, and checked against AMD's chain.
 *
 * ARK -> ASK -> VCEK -> report. The ARK is pinned by the SHA-256 of its
 * public key (SubjectPublicKeyInfo, DER), so a cache someone else filled
 * cannot bring its own root. ASK and VCEK come from AMD's KDS once and are
 * kept under WX_KDS; the VCEK per chip and TCB, since it changes with
 * every firmware update.
 */
#ifndef WX_SNP_H
#define WX_SNP_H

#include "util.h"

#include <meta_fetch.h>
#include <meta_text.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/stat.h>

#define SNP_REPORT_SIZE 0x4A0

/** ARK-Milan, checked against AMD's KDS and an independent cached copy. */
static const char snpArkMilan[] =
    "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9";

typedef struct {
  unsigned vmpl;
  bool debug;
  bool migrateMa;
  unsigned char reportData[64];
  char measurement[97];
  char hostData[65];
  char reportId[65];
  unsigned char tcb[8];
  char chipId[129];
} snpReport_t;

static uint32_t snpLe32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static const char *snpParse(const unsigned char *raw, size_t length, snpReport_t *out) {

  if (length != SNP_REPORT_SIZE)
    return "SNP report has the wrong size";

  /* signature algorithm 1: ECDSA P-384 with SHA-384 */
  if (snpLe32(raw + 0x34) != 1)
    return "SNP report signed with an unknown algorithm";

  uint64_t policy = (uint64_t)snpLe32(raw + 0x08) | (uint64_t)snpLe32(raw + 0x0C) << 32;

  out->vmpl = snpLe32(raw + 0x30);
  out->debug = (policy >> 19) & 1;
  out->migrateMa = (policy >> 18) & 1;
  memcpy(out->reportData, raw + 0x50, 64);
  toHex(raw + 0x90, 48, out->measurement);
  toHex(raw + 0xC0, 32, out->hostData);
  toHex(raw + 0x140, 32, out->reportId);
  memcpy(out->tcb, raw + 0x180, 8);
  toHex(raw + 0x1A0, 64, out->chipId);

  return NULL;
}

/* ------------------------------------------------------------- the chain */

static bool snpSpkiIs(X509 *cert, const char *wantHex) {

  unsigned char *der = NULL;
  char got[65];
  int length = i2d_PUBKEY(X509_get0_pubkey(cert), &der);

  if (length <= 0)
    return false;

  sha256Hex(der, (size_t)length, got);
  OPENSSL_free(der);

  return CRYPTO_memcmp(got, wantHex, 64) == 0;
}

static const char *snpKds(void) {
  return env("WX_KDS", "/kds");
}

static void snpMkdirs(const char *path) {

  char at[512];
  text_t t = TEXT`${path}`;
  t.into(at, sizeof at);

  for (char *p = at + 1; *p != 0; ++p)
    if (*p == '/') {
      *p = 0;
      mkdir(at, 0750);
      *p = '/';
    }
}

/** A file from the cache, or from AMD (and then kept). Free `.at`. */
static buf_t snpFetch(const char *cached, const char *url) {

  buf_t got = {0};
  char chunk[4096];
  FILE *in = fopen(cached, "rb");

  if (in != NULL) {
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, in)) > 0)
      buf_t__add(&got, chunk, n);
    fclose(in);
    return got;
  }

  fetch_answer_t answer = meta_get(url);

  if (answer.ok && answer.body != NULL && answer.length > 0) {
    buf_t__add(&got, answer.body, answer.length);

    snpMkdirs(cached);
    FILE *out = fopen(cached, "wb");
    if (out != NULL) {
      fwrite(got.at, 1, got.length, out);
      fclose(out);
    }
  }

  answer.release();

  return got;
}

static const char *snpProduct(void) {
  return env("WX_SNP_PRODUCT", "Milan");
}

/** The ASK, checked under the pinned ARK. Caller frees. */
static X509 *snpAsk(void) {

  char cached[512], url[256];
  X509 *ask = NULL, *ark = NULL;

  if (strcmp(snpProduct(), "Milan") != 0)
    return NULL; /* no pinned root for anything else yet */

  text_t c = TEXT`${snpKds()}/cert_chain/${snpProduct()}.pem`;
  c.into(cached, sizeof cached);
  text_t u = TEXT`https://kdsintf.amd.com/vcek/v1/${snpProduct()}/cert_chain`;
  u.into(url, sizeof url);

  buf_t pem = snpFetch(cached, url);
  BIO *bio = pem.at != NULL ? BIO_new_mem_buf(pem.at, (int)pem.length) : NULL;

  if (bio != NULL) {
    ask = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    ark = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  }

  bool good = ask != NULL && ark != NULL && snpSpkiIs(ark, snpArkMilan) &&
              X509_verify(ark, X509_get0_pubkey(ark)) == 1 &&
              X509_verify(ask, X509_get0_pubkey(ark)) == 1;

  BIO_free(bio);
  X509_free(ark);
  free(pem.at);

  if (!good) {
    X509_free(ask);
    return NULL;
  }

  return ask;
}

/** The VCEK for this chip at this TCB, checked under the ASK. Caller frees. */
static X509 *snpVcek(const snpReport_t *report) {

  char cached[600], url[512], tcb[17];
  const unsigned char *t = report->tcb;

  toHex(report->tcb, 8, tcb);

  text_t c = TEXT`${snpKds()}/vcek/${report->chipId}/${tcb}.der`;
  c.into(cached, sizeof cached);

  char spl[96];
  snprintf(spl, sizeof spl, "blSPL=%02u&teeSPL=%02u&snpSPL=%02u&ucodeSPL=%02u", t[0], t[1], t[6],
           t[7]);
  text_t u = TEXT`https://kdsintf.amd.com/vcek/v1/${snpProduct()}/${report->chipId}?${spl}`;
  u.into(url, sizeof url);

  X509 *ask = snpAsk();

  if (ask == NULL)
    return NULL;

  buf_t der = snpFetch(cached, url);
  const unsigned char *p = (const unsigned char *)der.at;
  X509 *vcek = der.at != NULL ? d2i_X509(NULL, &p, (long)der.length) : NULL;

  bool good = vcek != NULL && X509_verify(vcek, X509_get0_pubkey(ask)) == 1;

  X509_free(ask);
  free(der.at);

  if (!good) {
    /* a bad file in the cache would refuse this chip forever */
    if (vcek != NULL)
      remove(cached);
    X509_free(vcek);
    return NULL;
  }

  return vcek;
}

/**
 * A report signed by its chip's VCEK, for a platform the customer took
 * over (`measurements`, hex, comma separated), without debug or migration
 * agent.
 */
static const char *snpVerify(const unsigned char *raw, size_t length, const char *measurements,
                             snpReport_t *out) {

  const char *wrong = snpParse(raw, length, out);

  if (wrong != NULL)
    return wrong;

  X509 *vcek = snpVcek(out);

  if (vcek == NULL)
    return "no VCEK for this chip (AMD KDS) or the chain does not check out";

  ECDSA_SIG *sig = ECDSA_SIG_new();
  unsigned char *der = NULL;
  int derLength = 0;
  bool signedOk = false;

  if (sig != NULL && ECDSA_SIG_set0(sig, BN_lebin2bn(raw + 0x2A0, 72, NULL),
                                    BN_lebin2bn(raw + 0x2A0 + 72, 72, NULL)))
    derLength = i2d_ECDSA_SIG(sig, &der);

  EVP_MD_CTX *md = EVP_MD_CTX_new();
  signedOk = derLength > 0 && md != NULL &&
             EVP_DigestVerifyInit(md, NULL, EVP_sha384(), NULL, X509_get0_pubkey(vcek)) == 1 &&
             EVP_DigestVerify(md, der, (size_t)derLength, raw, 0x2A0) == 1;

  EVP_MD_CTX_free(md);
  OPENSSL_free(der);
  ECDSA_SIG_free(sig);
  X509_free(vcek);

  if (!signedOk)
    return "SNP report signature invalid";

  if (strstr(measurements, out->measurement) == NULL)
    return "SVSM/firmware measurement not in the reference values";

  if (out->debug)
    return "debug allowed";

  if (out->migrateMa)
    return "migration agent allowed";

  return NULL;
}

#endif /* WX_SNP_H */

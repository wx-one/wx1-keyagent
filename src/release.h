/**
 * The key release for disks: what the guest's initramfs asks
 * (wx-release-client), in three calls.
 *
 *   1. /v1/challenge  {disk_id}                       -> session, nonce
 *   2. /v1/attest     guest report (VMPL2), SVSM report (VMPL0, vTPM EK),
 *                     AK, initdata, the guest's public key -> credential
 *   3. /v1/release    the opened credential, TPM quote, replay stand
 *                     -> the disk key, encrypted to the guest's key
 *
 * What is checked:
 *  - both SNP reports signed by AMD (pinned ARK -> ASK -> VCEK), same chip,
 *    same measurement (from the reference values), same REPORT_ID (one VM
 *    instance), no debug, no migration agent
 *  - guest report: REPORT_DATA = SHA-512(nonce || guest key), HOST_DATA =
 *    SHA-256(initdata) = the disk's binding, the chip allowed for the disk
 *  - SVSM report at VMPL0: REPORT_DATA = SHA-512(nonce || EK): the EK is
 *    this VM's vTPM; with a persistent vTPM it is pinned on the first release
 *  - AK: a restricted signing key, bound to exactly that EK by a credential
 *  - quote over a fresh nonce; PCR 4/8/9 (boot loader, GRUB commands and
 *    command line, kernel/initrd) in an approved reference set
 *  - replay stand in the vTPM at least the last confirmed one
 *  - lease: per disk at most one REPORT_ID holds the key at a time
 */
#ifndef WX_RELEASE_H
#define WX_RELEASE_H

#include "requests.h"
#include "snp.h"
#include "tpm.h"


static long leaseTtl(void) {
  return atol(env("WX_LEASE_TTL", "600"));
}

/* -------------------------------------------------------- reference values */

/** The platform measurements; with `persistOnly` those with a persistent vTPM. */
static void releaseMeasurements(buf_t *out, bool persistOnly) {

  static const char *const both[] = {"igvm_measurement", "igvm_persist_measurement"};

  if (persistOnly)
    refMeasurements(out, both + 1, 1);
  else
    refMeasurements(out, both, 2);
}

static bool pcrSetMatches(json_t ref, tpmPcrs_t *pcrs) {

  static const int which[] = {4, 8, 9};

  for (int i = 0; i < 3; ++i) {

    char key[4], got[65];
    text_t k = TEXT`${which[i]}`;
    k.into(key, sizeof key);

    toHex(pcrs->value[which[i]], 32, got);

    const char *want = ref.get(key).text();

    if (want == NULL || strcasecmp(want, got) != 0)
      return false;
  }

  return true;
}

/**
 * PCR 4/8/9 in one of the approved sets: the provider's (pcrs.json next to
 * the reference values) or the customer's own (settings.pcr_refs).
 */
static bool pcrApproved(tpmPcrs_t *pcrs) {

  bool found = false;
  char path[512];

  /* next to the reference values: <dir of WX_REFS>/pcrs.json */
  text_t refs = TEXT`${env("WX_REFS", "/refs/manifest.txt")}`;
  refs.into(path, sizeof path - 16);

  char *slash = strrchr(path, '/');
  strcpy(slash != NULL ? slash + 1 : path, "pcrs.json");

  FILE *in = fopen(path, "rb");

  if (in != NULL) {
    buf_t text = {0};
    char chunk[4096];
    size_t n;

    while ((n = fread(chunk, 1, sizeof chunk, in)) > 0)
      buf_t__add(&text, chunk, n);
    fclose(in);

    json_t list = meta_toJSON(text.at);
    for (int i = 0; !found && i < list.count(); ++i)
      found = pcrSetMatches(list.at(i), pcrs);
    list.release();
    free(text.at);
  }

  if (!found) {
    settings_t settings = settingsRead();
    json_t list = settings.data.get("pcr_refs");

    for (int i = 0; settings.entry.found && !found && i < list.count(); ++i)
      found = pcrSetMatches(list.at(i), pcrs);

    settings.release();
  }

  return found;
}

/* ---------------------------------------------------------- release modes */

static const char *const days[] = {"Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"};

static int dayIndex(const char *s, size_t n) {

  for (int i = 0; i < 7; ++i)
    if (n == 2 && strncmp(s, days[i], 2) == 0)
      return i;

  return -1;
}

static int minutesOf(const char *s) {

  if (strlen(s) < 5 || s[2] != ':')
    return -1;

  return atoi(s) * 60 + atoi(s + 3);
}

/**
 * "Mo-Fr 06:00-22:00" or "06:00-22:00", in the agent's local time. -1 for a
 * window that cannot be read, then 1 inside, 0 outside.
 */
static int inWindow(const char *window, time_t now) {

  char days_[16] = "Mo-So", hours[16];
  struct tm t;
  const char *space = strchr(window, ' ');

  if (space != NULL) {
    if ((size_t)(space - window) >= sizeof days_ || strlen(space + 1) >= sizeof hours)
      return -1;
    memcpy(days_, window, (size_t)(space - window));
    days_[space - window] = 0;
    strcpy(hours, space + 1);
  } else {
    if (strlen(window) >= sizeof hours)
      return -1;
    strcpy(hours, window);
  }

  const char *dash = strchr(days_, '-');
  int d0 = dayIndex(days_, dash != NULL ? (size_t)(dash - days_) : strlen(days_));
  int d1 = dash != NULL ? dayIndex(dash + 1, strlen(dash + 1)) : d0;

  char *hdash = strchr(hours, '-');

  if (d0 < 0 || d1 < 0 || hdash == NULL)
    return -1;

  *hdash = 0;

  int a = minutesOf(hours), b = minutesOf(hdash + 1);

  if (a < 0 || b < 0 || a > 24 * 60 || b > 24 * 60)
    return -1;

  localtime_r(&now, &t);

  int wday = (t.tm_wday + 6) % 7; /* Monday first */
  int m = t.tm_hour * 60 + t.tm_min;

  bool day = d0 <= d1 ? wday >= d0 && wday <= d1 : wday >= d0 || wday <= d1;
  bool hour = a <= b ? m >= a && m < b : m >= a || m < b;

  return day && hour;
}

/**
 * Whether a new instance may unlock the disk: always, inside its window, or
 * only once the customer confirmed this very instance. NULL, or why not -
 * then a request is waiting for the customer.
 */
static const char *admit(const char *diskId, const char *reportId, const char *chipId,
                         tpmPcrs_t *pcrs, char *why, size_t room) {

  bao_entry_t disk = storeGet("disks", diskId);
  char mode[16], window[64];

  text_t m = TEXT`${disk.found ? disk.payload().get("mode").text() : ""}`;
  m.into(mode, sizeof mode);
  text_t w = TEXT`${disk.found ? disk.payload().get("window").text() : ""}`;
  w.into(window, sizeof window);
  disk.release();

  if (disk.failed)
    return "state not readable (OpenBao)";

  /* text() answers "" for an absent key, never NULL: no mode is "always" */
  if (mode[0] == 0)
    strcpy(mode, "always");

  if (strcmp(mode, "always") == 0 ||
      (strcmp(mode, "window") == 0 && window[0] != 0 && inWindow(window, time(NULL)) == 1))
    return NULL;

  /* the customer's answer for this instance, if there is one */
  sql_t q = SQL`select id, status from requests
    where type = 'unlock' and payload->>'disk_id' = ${diskId} and payload->>'report_id' = ${reportId}
    order by id desc limit 1`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r == NULL || PQresultStatus(r) != PGRES_TUPLES_OK) {
    if (r != NULL)
      PQclear(r);
    return "database not reachable";
  }

  if (PQntuples(r) == 1) {

    long id = atol(PQgetvalue(r, 0, 0));
    char status[16];
    text_t s = TEXT`${PQgetvalue(r, 0, 1)}`;
    s.into(status, sizeof status);
    PQclear(r);

    if (strcmp(status, "applied") == 0)
      return NULL;

    if (strcmp(status, "pending") == 0 || strcmp(status, "deciding") == 0) {
      text_t t = TEXT`waiting for the customer's confirmation (request #${id})`;
      t.into(why, room);
      return why;
    }

    return "denied by the customer";
  }

  PQclear(r);

  /* the first time: ask */
  char reason[96];
  text_t t = strcmp(mode, "window") == 0 ? TEXT`outside the time window ${window}`
                                         : TEXT`the disk asks for confirmation`;
  t.into(reason, sizeof reason);

  /* PCR 4/8/9 under their numbers: a literal names its keys, so these as text
     - hex only, nothing to escape */
  char p4[65], p8[65], p9[65], chain[256];
  toHex(pcrs->value[4], 32, p4);
  toHex(pcrs->value[8], 32, p8);
  toHex(pcrs->value[9], 32, p9);
  snprintf(chain, sizeof chain, "{\"4\":\"%s\",\"8\":\"%s\",\"9\":\"%s\"}", p4, p8, p9);
  json_t pcrSet = meta_toJSON(chain);

  bao_entry_t att = storeGet("attachments", diskId);
  const char *vm = att.found ? att.payload().get("vm_uuid").text() : "";
  const char *vmName = att.found ? att.payload().get("vm_name").text() : "";
  json_t p = {disk_id: diskId, report_id: reportId, chip_id: chipId, reason: reason, vm_uuid: vm,
              vm_name: vmName, pcrs: pcrSet};
  char *payload = p.owned();
  p.release();
  pcrSet.release();
  att.release();

  /* the one remark the customer sees: why it waits */
  checks_t remark = checksNew();
  remark.note(reason);
  char *checks = remark.json();
  remark.release();

  sql_t insert = SQL`insert into requests (type, payload, status, checks)
    values ('unlock', ${payload ?: "{}"}::JSONB, 'pending', ${checks ?: "[]"}::JSONB)
    returning id`;
  PGresult *made = dbAsk(&insert);
  insert.release();
  free(payload);
  free(checks);

  long id = made != NULL && PQresultStatus(made) == PGRES_TUPLES_OK && PQntuples(made) == 1
                ? atol(PQgetvalue(made, 0, 0))
                : -1;

  if (made != NULL)
    PQclear(made);

  text_t t2 = TEXT`waiting for the customer's confirmation (request #${id})`;
  t2.into(why, room);

  return why;
}

/* ------------------------------------------------------------ the answer */

/** RSA-OAEP (SHA-256) to the guest's one-off key, base64 into `out`. */
static bool sealToGuest(const unsigned char *der, size_t derLength, const unsigned char *data,
                        size_t length, char *out, size_t room) {

  const unsigned char *p = der;
  EVP_PKEY *key = d2i_PUBKEY(NULL, &p, (long)derLength);
  EVP_PKEY_CTX *ctx = key != NULL ? EVP_PKEY_CTX_new(key, NULL) : NULL;
  unsigned char sealed[1024];
  size_t sealedLength = sizeof sealed;

  bool good = ctx != NULL && p == der + derLength && EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA &&
              EVP_PKEY_get_bits(key) >= 3072 && EVP_PKEY_encrypt_init(ctx) > 0 &&
              EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
              EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0 &&
              EVP_PKEY_encrypt(ctx, sealed, &sealedLength, data, length) > 0 &&
              (sealedLength + 2) / 3 * 4 + 1 <= room;

  if (good)
    toBase64(sealed, sealedLength, out);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);

  return good;
}

/* -------------------------------------------------------------- the calls */

/** What a call answers: JSON for the guest, or why not. */
typedef struct {
  buf_t json;
  const char *wrong;
  int code;
  char why[200];
  char disk[48];
  char ctx[640];
} release_t;

static void release_t__refuse(release_t *self, int code, const char *why) {

  self->code = code;

  if (why != self->why) {
    text_t t = TEXT`${why}`;
    t.into(self->why, sizeof self->why);
  }

  self->wrong = self->why;
}

/** {"k": "v", ...} into the answer; values are hex or base64, never quoted text. */
static void release_t__field(release_t *self, const char *key, const char *value) {
  buf_t__printf(&self->json, "%s\"%s\":\"%s\"", self->json.length > 1 ? "," : "", key, value);
}

/** 1. A nonce for one disk. */
static void challenge(release_t *out, json_t req) {

  const char *diskId = req.get("disk_id").text();
  unsigned char nonce[64];
  char nonceHex[129], nonceB64[96], session[33];

  if (!isDiskId(diskId))
    return out.refuse(400, "disk_id missing or not vm-<uuid> / vol-<uuid>");

  text_t d = TEXT`${diskId}`;
  d.into(out->disk, sizeof out->disk);

  if (!randomBytes(nonce, sizeof nonce) || !randomHex(16, session))
    return out.refuse(500, "no randomness");

  toHex(nonce, 64, nonceHex);
  toBase64(nonce, 64, nonceB64);

  bool renew = req.get("renew").truth() || req.get("end").truth();
  bool ending = req.get("end").truth();

  sql_t gone = SQL`delete from sessions where expires < now() - interval '1 hour'`;
  dbDo(&gone);
  gone.release();

  sql_t q = SQL`insert into sessions (id, disk_id, nonce, expires, renew, ending, stage)
    values (${(const char *)session}, ${diskId}, ${(const char *)nonceHex},
            now() + interval '120 seconds', ${renew}, ${ending}, 'challenge')`;
  bool stored = dbDo(&q);
  q.release();

  if (!stored)
    return out.refuse(503, "database not reachable");

  buf_t__put(&out->json, "{");
  out.field("session", session);
  out.field("nonce", nonceB64);
  buf_t__put(&out->json, "}");
}

/** SHA-512(a || b) == want */
static bool boundTo(const unsigned char *want, const unsigned char *a, size_t aLength,
                    const char *b, size_t bLength) {

  unsigned char digest[64];
  unsigned int length = 0;
  EVP_MD_CTX *md = EVP_MD_CTX_new();

  bool hashed = md != NULL && EVP_DigestInit_ex(md, EVP_sha512(), NULL) == 1 &&
                EVP_DigestUpdate(md, a, aLength) == 1 && EVP_DigestUpdate(md, b, bLength) == 1 &&
                EVP_DigestFinal_ex(md, digest, &length) == 1 && length == 64;

  EVP_MD_CTX_free(md);

  return hashed && CRYPTO_memcmp(digest, want, 64) == 0;
}

/** Whether `chip` is among the attachment's allowed hosts. */
static bool chipAllowed(json_t att, const char *chip) {

  json_t chips = att.get("chip_ids");

  for (int i = 0; i < chips.count(); ++i)
    if (strcmp(chips.at(i).text() ?: "", chip) == 0)
      return true;

  return false;
}

typedef struct {
  blob_t initdata, guestPub, snp, svsm, manifest, ak;
} attestIn_t;

static void attestIn_t__release(attestIn_t *self) {
  free(self->initdata.at);
  free(self->guestPub.at);
  free(self->snp.at);
  free(self->svsm.at);
  free(self->manifest.at);
  free(self->ak.at);
}

/** 2. Who is asking: this VM instance, its vTPM, its AK. */
static void attestStep(release_t *out, json_t req, attestIn_t *in) {

  const char *session = req.get("session").text() ?: "";
  unsigned char nonce[64];
  snpReport_t guest, vtpm;
  const char *wrong;

  sql_t q = SQL`select disk_id, nonce from sessions
    where id = ${session} and stage = 'challenge' and expires > now()`;
  PGresult *r = dbAsk(&q);
  q.release();

  bool known = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (known) {
    text_t d = TEXT`${PQgetvalue(r, 0, 0)}`;
    d.into(out->disk, sizeof out->disk);
    fromHex(PQgetvalue(r, 0, 1), nonce, sizeof nonce);
  }

  if (r != NULL)
    PQclear(r);

  if (!known)
    return out.refuse(403, "session unknown, used or expired");

  in->initdata = blobOf(req.get("initdata"));
  in->guestPub = blobOf(req.get("guest_pub"));
  in->snp = blobOf(req.get("snp_report"));
  in->svsm = blobOf(req.get("svsm_report"));
  in->manifest = blobOf(req.get("manifest"));
  in->ak = blobOf(req.get("ak_pub"));

  if (in->initdata.length <= 0 || in->guestPub.length <= 0 || in->snp.length <= 0 ||
      in->svsm.length <= 0 || in->manifest.length <= 0 || in->ak.length <= 2)
    return out.refuse(400, "request incomplete");

  buf_t measurements = {0}, persist = {0};
  releaseMeasurements(&measurements, false);
  releaseMeasurements(&persist, true);

  wrong = snpVerify((const unsigned char *)in->snp.at, (size_t)in->snp.length,
                    measurements.at ?: "", &guest);

  if (wrong == NULL) {
    /* hex only: nothing to escape */
    snprintf(out->ctx, sizeof out->ctx, "{\"chip_id\":\"%s\",\"report_id\":\"%s\"}",
             guest.chipId, guest.reportId);
    wrong = snpVerify((const unsigned char *)in->svsm.at, (size_t)in->svsm.length,
                      measurements.at ?: "", &vtpm);
  }

  bool persistent = wrong == NULL && strstr(persist.at ?: "", vtpm.measurement) != NULL;

  free(measurements.at);
  free(persist.at);

  if (wrong != NULL)
    return out.refuse(403, wrong);

  /* the guest report: fresh, bound to the guest's key, exactly this VM configuration */
  if (guest.vmpl < 1)
    return out.refuse(403, "guest report not from the guest (VMPL)");

  if (!boundTo(guest.reportData, nonce, 64, in->guestPub.at, (size_t)in->guestPub.length))
    return out.refuse(403, "guest report not bound to the nonce and the guest key");

  char initdataHash[65];
  sha256Hex(in->initdata.at, (size_t)in->initdata.length, initdataHash);

  if (strcmp(initdataHash, guest.hostData) != 0)
    return out.refuse(403, "initdata does not match HOST_DATA");

  bao_entry_t att = storeGet("attachments", out->disk);
  bool bound = att.found && strcmp(att.payload().get("host_data").text() ?: "", guest.hostData) == 0;
  bool hostOk = att.found && chipAllowed(att.payload(), guest.chipId);
  bool failed = att.failed, attached = att.found;
  att.release();

  if (failed)
    return out.refuse(503, "state not readable (OpenBao)");
  if (!attached)
    return out.refuse(403, "disk attached to no VM (no binding)");
  if (!bound)
    return out.refuse(403, "VM configuration (HOST_DATA) not approved for this disk");
  if (!hostOk)
    return out.refuse(403, "host not approved for this disk");

  /* the SVSM report: same VM instance, the vTPM's EK from the SVSM */
  if (vtpm.vmpl != 0)
    return out.refuse(403, "vTPM report not from the SVSM (VMPL0)");

  if (!boundTo(vtpm.reportData, nonce, 64, in->manifest.at, (size_t)in->manifest.length))
    return out.refuse(403, "vTPM report not bound to the nonce and the EK");

  if (strcmp(vtpm.reportId, guest.reportId) != 0 || strcmp(vtpm.chipId, guest.chipId) != 0 ||
      strcmp(vtpm.measurement, guest.measurement) != 0 ||
      strcmp(vtpm.hostData, guest.hostData) != 0)
    return out.refuse(403, "vTPM report belongs to another VM");

  /* the AK, bound to this EK by a credential */
  tpmPublic_t ek, ak;
  unsigned char name[34], secret[32], quoteNonce[32];
  char secretHash[65], quoteHex[65], ekHash[65], bound_[80];

  if (!tpmPublic((const unsigned char *)in->manifest.at, (size_t)in->manifest.length, &ek))
    return out.refuse(403, "EK cannot be read");

  if (!tpmPublic((const unsigned char *)in->ak.at + 2, (size_t)in->ak.length - 2, &ak) ||
      ((unsigned char)in->ak.at[0] << 8 | (unsigned char)in->ak.at[1]) != in->ak.length - 2)
    return out.refuse(403, "AK cannot be read");

  if ((wrong = tpmCheckAk(&ak)) != NULL)
    return out.refuse(403, wrong);

  tpmName(&ak, name);

  if (!randomBytes(secret, sizeof secret) || !randomBytes(quoteNonce, sizeof quoteNonce))
    return out.refuse(500, "no randomness");

  buf_t cred = {0};

  if ((wrong = tpmMakeCredential(&ek, name, secret, sizeof secret, &cred)) != NULL) {
    free(cred.at);
    return out.refuse(403, wrong);
  }

  sha256Hex(secret, sizeof secret, secretHash);
  OPENSSL_cleanse(secret, sizeof secret);
  toHex(quoteNonce, sizeof quoteNonce, quoteHex);
  sha256Hex(in->manifest.at, (size_t)in->manifest.length, ekHash);

  /* the vTPM's identity: with a persistent vTPM the EK stays the same across
     boots. Another one means its state was lost or swapped, or the SVSM fell
     back to an ephemeral vTPM (it does when it does not get its state key) */
  if (!storeEk(guest.hostData, bound_, sizeof bound_)) {
    free(cred.at);
    return out.refuse(503, "state not readable (OpenBao)");
  }

  if (bound_[0] != 0 && strcmp(bound_, ekHash) != 0) {
    free(cred.at);
    return out.refuse(403, "the vTPM is not the same any more (EK): state lost, swapped or "
                           "ephemeral. No release until the customer unbinds the EK");
  }

  /* hex of the public parts, for the next call */
  char *akHex = (char *)malloc((size_t)in->ak.length * 2 + 1);
  char *pubHex = (char *)malloc((size_t)in->guestPub.length * 2 + 1);
  char *credB64 = (char *)malloc(cred.length / 3 * 4 + 8);

  if (akHex == NULL || pubHex == NULL || credB64 == NULL) {
    free(akHex);
    free(pubHex);
    free(credB64);
    free(cred.at);
    return out.refuse(500, "no memory");
  }

  toHex((const unsigned char *)in->ak.at, (size_t)in->ak.length, akHex);
  toHex((const unsigned char *)in->guestPub.at, (size_t)in->guestPub.length, pubHex);
  toBase64((const unsigned char *)cred.at, cred.length, credB64);
  free(cred.at);

  sql_t u = SQL`update sessions set stage = 'attested', secret_hash = ${(const char *)secretHash},
      quote_nonce = ${(const char *)quoteHex}, ak_pub = ${(const char *)akHex},
      guest_pub = ${(const char *)pubHex}, ek = ${(const char *)ekHash}, persist = ${persistent},
      report_id = ${(const char *)guest.reportId}, chip_id = ${(const char *)guest.chipId},
      host_data = ${(const char *)guest.hostData}
    where id = ${session} and stage = 'challenge' and expires > now()
    returning id`;
  PGresult *done = dbAsk(&u);
  u.release();

  bool moved = done != NULL && PQresultStatus(done) == PGRES_TUPLES_OK && PQntuples(done) == 1;

  if (done != NULL)
    PQclear(done);

  free(akHex);
  free(pubHex);

  if (!moved) {
    free(credB64);
    return out.refuse(403, "session used or expired");
  }

  buf_t__put(&out->json, "{");
  out.field("credential", credB64);
  out.field("quote_nonce", quoteHex);
  buf_t__put(&out->json, "}");

  free(credB64);
}

static void attest(release_t *out, json_t req) {

  attestIn_t in = {0};

  attestStep(out, req, &in);
  in.release();
}

/** The session as attest left it. */
typedef struct {
  char disk[48];
  bool renew, ending, persist;
  char secretHash[65], quoteNonce[65], ek[65], reportId[65], chipId[129], hostData[65];
  unsigned char ak[512], guestPub[1024];
  long akLength, guestPubLength;
} session_t;

/** Takes the attested session for this one release; nobody can use it again. */
static bool takeSession(const char *id, session_t *s) {

  sql_t q = SQL`update sessions set stage = 'used'
    where id = ${id} and stage = 'attested' and expires > now()
    returning disk_id, renew, ending, persist, secret_hash, quote_nonce, ek, report_id, chip_id,
              host_data, ak_pub, guest_pub`;
  PGresult *r = dbAsk(&q);
  q.release();

  bool got = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (got) {
    text_t a = TEXT`${PQgetvalue(r, 0, 0)}`;
    a.into(s->disk, sizeof s->disk);
    s->renew = PQgetvalue(r, 0, 1)[0] == 't';
    s->ending = PQgetvalue(r, 0, 2)[0] == 't';
    s->persist = PQgetvalue(r, 0, 3)[0] == 't';
    text_t b = TEXT`${PQgetvalue(r, 0, 4)}`;
    b.into(s->secretHash, sizeof s->secretHash);
    text_t c = TEXT`${PQgetvalue(r, 0, 5)}`;
    c.into(s->quoteNonce, sizeof s->quoteNonce);
    text_t d = TEXT`${PQgetvalue(r, 0, 6)}`;
    d.into(s->ek, sizeof s->ek);
    text_t e = TEXT`${PQgetvalue(r, 0, 7)}`;
    e.into(s->reportId, sizeof s->reportId);
    text_t f = TEXT`${PQgetvalue(r, 0, 8)}`;
    f.into(s->chipId, sizeof s->chipId);
    text_t g = TEXT`${PQgetvalue(r, 0, 9)}`;
    g.into(s->hostData, sizeof s->hostData);
    s->akLength = fromHex(PQgetvalue(r, 0, 10), s->ak, sizeof s->ak);
    s->guestPubLength = fromHex(PQgetvalue(r, 0, 11), s->guestPub, sizeof s->guestPub);
    got = s->akLength > 2 && s->guestPubLength > 0;
  }

  if (r != NULL)
    PQclear(r);

  return got;
}

/** 3. The disk key, if the boot chain, the replay stand and the lease allow it. */
static void releaseStep(release_t *out, json_t req, session_t *s, blob_t *parts) {

  const char *wrong;
  char why[200];

  if (!takeSession(req.get("session").text() ?: "", s))
    return out.refuse(403, "session unknown, used or expired (first /v1/attest)");

  text_t d = TEXT`${s->disk}`;
  d.into(out->disk, sizeof out->disk);
  snprintf(out->ctx, sizeof out->ctx, "{\"chip_id\":\"%s\",\"report_id\":\"%s\"}",
           s->chipId, s->reportId);

  blob_t *secret = &parts[0], *msg = &parts[1], *sig = &parts[2], *pcrFile = &parts[3];
  blob_t *nvAtt = &parts[4], *nvSig = &parts[5];

  *secret = blobOf(req.get("secret"));
  *msg = blobOf(req.get("msg"));
  *sig = blobOf(req.get("sig"));
  *pcrFile = blobOf(req.get("pcrs"));
  *nvAtt = blobOf(req.get("nv_attest"));
  *nvSig = blobOf(req.get("nv_sig"));

  if (secret->length <= 0 || msg->length <= 0 || sig->length <= 0 || pcrFile->length <= 0)
    return out.refuse(400, "request incomplete");

  char got[65];
  sha256Hex(secret->at, (size_t)secret->length, got);

  if (CRYPTO_memcmp(got, s->secretHash, 64) != 0)
    return out.refuse(403, "credential not opened (another vTPM)");

  tpmPublic_t ak;
  tpmPcrs_t pcrs;
  unsigned char quoteNonce[32];

  if (!tpmPublic(s->ak + 2, (size_t)s->akLength - 2, &ak))
    return out.refuse(500, "AK lost");

  fromHex(s->quoteNonce, quoteNonce, sizeof quoteNonce);

  wrong = tpmCheckQuote(&ak, (const unsigned char *)msg->at, (size_t)msg->length,
                        (const unsigned char *)sig->at, (size_t)sig->length,
                        (const unsigned char *)pcrFile->at, (size_t)pcrFile->length, quoteNonce,
                        32, &pcrs);

  if (wrong != NULL)
    return out.refuse(403, wrong);

  /* the replay stand, if the guest sent one */
  char nvName[80] = "";
  long nv = -1;

  if (nvAtt->length > 0) {
    wrong = tpmNvCounter(&ak, (const unsigned char *)nvAtt->at, (size_t)nvAtt->length,
                         (const unsigned char *)nvSig->at, nvSig->length > 0 ? (size_t)nvSig->length : 0,
                         quoteNonce, 32, nvName, &nv);
    if (wrong != NULL)
      return out.refuse(403, wrong);
  }

  {
    /* whole values: a customer who looks at a refused boot can take them over */
    char p4[65], p8[65], p9[65];
    toHex(pcrs.value[4], 32, p4);
    toHex(pcrs.value[8], 32, p8);
    toHex(pcrs.value[9], 32, p9);
    snprintf(out->ctx, sizeof out->ctx,
             "{\"chip_id\":\"%s\",\"report_id\":\"%s\",\"pcrs\":{\"4\":\"%s\",\"8\":\"%s\",\"9\":\"%s\"}}",
             s->chipId, s->reportId, p4, p8, p9);
  }

  if (!pcrApproved(&pcrs))
    return out.refuse(403, "boot chain (PCR 4/8/9) not in the approved reference values");

  /* still bound: a detach between attest and now takes effect */
  bao_entry_t att = storeGet("attachments", s->disk);
  bool bound = att.found && strcmp(att.payload().get("host_data").text() ?: "", s->hostData) == 0 &&
               chipAllowed(att.payload(), s->chipId);
  att.release();

  if (!bound)
    return out.refuse(403, "disk no longer bound to this VM and host");

  /* lease: at most one instance (REPORT_ID) per disk */
  bool holds = storeHoldsLease(s->disk, s->reportId);

  if (!holds && !storeLeaseOpen(s->disk, s->reportId))
    return out.refuse(403, "disk is already unlocked in another running instance (lease)");

  if (s->renew && !holds && !s->ending)
    return out.refuse(403, "renewal without a valid lease");

  /* replay protection: every release hands out a higher stand, the guest
     writes it into its vTPM and proves it the next time. Checked only from
     below - at least the last confirmed - never "exactly the last issued":
     a lost answer leaves the previous one in the vTPM */
  long next = -1;

  if (s->persist) {
    replay_t stand = storeReplay(s->hostData);

    if (stand.failed)
      return out.refuse(503, "state not readable (OpenBao)");

    if (stand.found && stand.nvName[0] != 0 && nv < 0)
      return out.refuse(403, "replay stand missing (replay protection)");

    if (nv >= 0 && (wrong = stand.refuses(nvName, nv)) != NULL)
      return out.refuse(403, wrong);

    /* a new stand at every boot; while the instance runs only as often as
       the disk asks for (replay_interval, seconds; 0 = boot only) */
    bool due = !s->renew && !s->ending;

    if (!due && stand.found) {
      bao_entry_t disk = storeGet("disks", s->disk);
      long interval = disk.found ? disk.payload().get("replay_interval").number() : 0;
      disk.release();
      due = interval > 0 && (long)time(NULL) - stand.at >= interval;
    }

    if (nv >= 0 && (due || !stand.found))
      next = nv + 1;
  }

  char nextB64[16] = "";

  if (next > 0) {
    unsigned char be[8];
    for (int i = 0; i < 8; ++i)
      be[i] = (unsigned char)((unsigned long)next >> (56 - 8 * i));
    toBase64(be, 8, nextB64);
  }

  if (s->ending) {
    /* a clean shutdown: the instance gives its lease back itself */
    storeEndLease(s->disk, s->reportId);
    if (next > 0 && !storeReplayConfirm(s->hostData, nvName, nv, next))
      return out.refuse(503, "cannot confirm the replay stand (OpenBao)");
    buf_t__put(&out->json, "{\"ended\":true");
    if (next > 0)
      buf_t__printf(&out->json, ",\"nv_next\":\"%s\"", nextB64);
    buf_t__put(&out->json, "}");
    return;
  }

  /* a new instance: the disk's release mode. A running one always renews */
  if (!holds && (wrong = admit(s->disk, s->reportId, s->chipId, &pcrs, why, sizeof why)) != NULL)
    return out.refuse(403, wrong);

  if (!storeTakeLease(s->disk, s->reportId, s->chipId, leaseTtl()))
    return out.refuse(403, "disk is already unlocked in another running instance (lease)");

  /* the EK binding (see attest), held on the first successful release */
  if (s->persist)
    storePinEk(s->hostData, s->ek);

  if (next > 0 && !storeReplayConfirm(s->hostData, nvName, nv, next))
    return out.refuse(503, "cannot confirm the replay stand (OpenBao)");

  long expires = (long)time(NULL) + leaseTtl();

  if (s->renew) {
    buf_t__printf(&out->json, "{\"lease_expires\":%ld", expires);
    if (next > 0)
      buf_t__printf(&out->json, ",\"nv_next\":\"%s\"", nextB64);
    buf_t__put(&out->json, "}");
    return;
  }

  char keyPath[80], sealed[1400];
  unsigned char key[128];
  text_t kp = TEXT`disk/${s->disk}/key`;
  kp.into(keyPath, sizeof keyPath);

  long keyLength = baoGetKey(keyPath, key, sizeof key);

  if (keyLength <= 0)
    return out.refuse(503, "disk key not readable (OpenBao)");

  bool sealedOk = sealToGuest(s->guestPub, (size_t)s->guestPubLength, key, (size_t)keyLength,
                              sealed, sizeof sealed);
  OPENSSL_cleanse(key, sizeof key);

  if (!sealedOk)
    return out.refuse(403, "guest key unusable (want RSA 3072 or more)");

  buf_t__printf(&out->json, "{\"key\":\"%s\",\"lease_expires\":%ld", sealed, expires);
  if (next > 0)
    buf_t__printf(&out->json, ",\"nv_next\":\"%s\"", nextB64);
  buf_t__put(&out->json, "}");
}

static void releaseKey(release_t *out, json_t req) {

  session_t s = {0};
  blob_t parts[6] = {{NULL, -1}, {NULL, -1}, {NULL, -1}, {NULL, -1}, {NULL, -1}, {NULL, -1}};

  releaseStep(out, req, &s, parts);

  for (int i = 0; i < 6; ++i)
    free(parts[i].at);

  OPENSSL_cleanse(&s, sizeof s);
}

#endif /* WX_RELEASE_H */

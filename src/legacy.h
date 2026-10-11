/**
 * Taking over an installation from before 0.0.6, once: then the state was in
 * OpenBao's KV (wx/, v2) and the disk keys in kv/disk/<id>/key, readable by
 * the agent.
 *
 *   - every entry of wx/ into the table `state`, signed; replay/<host_data>
 *     into the vTPM entry it belongs to
 *   - every disk key not shredded into transit (BYOK import), checked by
 *     wrapping it for a throwaway key and opening that here, and only then
 *     deleted from kv/ - the one time the agent has a disk key in the clear
 *   - a marker, meta/openbao-kv-imported, so it is not done again
 *
 * wx/ itself is left as it was: what it holds is no secret, and it is the way
 * back to the old version. The vTPM state keys stay where they are - in kv/,
 * where the KBS reads them; new ones the agent writes through the KBS.
 *
 * In the launcher, after the migrations, before any worker serves. Anything
 * that goes wrong stops the start: half a state is worse than none, and the
 * next start begins again where this one stopped.
 */
#ifndef WX_LEGACY_H
#define WX_LEGACY_H

#include "store.h"

static const char legacyMarker[] = "meta/openbao-kv-imported";

/** The names under wx/metadata/<prefix>, folders ending in "/"; owned, or nothing. */
static json_t legacyList(const char *prefix, int *status) {

  char path[300];

  text_t at = TEXT`wx/metadata/${prefix}`;
  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("LIST", path, NULL);
  json_t doc = {0};

  *status = got.status;

  if (got.ok)
    doc = got.json();

  got.release();

  return doc;
}

/** One entry of wx/ as JSON text; owned, NULL if it cannot be read. */
static char *legacyRead(const char *key) {

  char path[300];

  text_t at = TEXT`wx/data/${key}`;
  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("GET", path, NULL);
  char *json = NULL;

  if (got.ok) {
    json_t doc = got.json();
    json = doc.data.data.owned();
    doc.release();
  }

  got.release();

  return json;
}

typedef struct {
  int entries, keys, skipped;
  char why[300];
} legacy_t;

/** The replay stand as it was (replay/<hd>) into the vTPM entry (vtpm/<hd>). */
static bool legacyReplay(legacy_t *self, const char *hostData, const char *json) {

  char key[160];
  json_t old = meta_toJSON(json);
  entry_t vtpm = storeGet("vtpm", hostData);
  bool there = vtpm.found;
  vtpm.release();

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  /* a stand without its vTPM entry belongs to nothing any more */
  bool done = !there;

  if (there) {
    json_t patch = {replay_nv: old.nv_name.text(), replay_confirmed: old.confirmed.number(),
                    replay_issued: old.issued.number(), replay_at: old["at"].number()};
    done = statePatch(key, patch);
    patch.release();
  }

  old.release();

  if (!done)
    snprintf(self->why, sizeof self->why, "cannot write the replay stand of %s", hostData);

  return done;
}

/** Walks wx/metadata/<prefix>; `replays` true for the second pass (replay/ only). */
static bool legacyWalk(legacy_t *self, const char *prefix, bool replays) {

  int status = 0;
  json_t list = legacyList(prefix, &status);
  bool good = true;

  if (status == 404)
    return true;

  if (status != 200) {
    snprintf(self->why, sizeof self->why, "cannot list wx/metadata/%s (%d)", prefix, status);
    return false;
  }

  json_t names = list.data.keys;

  for (int i = 0; good && i < names.count(); ++i) {

    char key[300];
    const char *name = names[i].text() ?: "";
    size_t n = strlen(name);

    text_t k = TEXT`${prefix}${name}`;
    k.into(key, sizeof key);

    if (n > 0 && name[n - 1] == '/') {
      good = legacyWalk(self, key, replays);
      continue;
    }

    bool replay = strncmp(key, "replay/", 7) == 0;

    if (replay != replays)
      continue;

    char *json = legacyRead(key);

    if (json == NULL) {
      snprintf(self->why, sizeof self->why, "cannot read wx/%s", key);
      good = false;
    } else if (replay) {
      good = legacyReplay(self, key + 7, json);
    } else {
      bool conflict = false;
      /* an entry there already (a start that stopped half way) is kept */
      good = stateWrite(key, json, 0, &conflict) || conflict;
      if (!good)
        snprintf(self->why, sizeof self->why, "cannot write %s into the database", key);
    }

    self->entries += good;
    free(json);
  }

  list.release();

  return good;
}

/** One disk key from kv/ into transit, checked, then gone from kv/. */
static bool legacyKey(legacy_t *self, const char *diskId) {

  char path[200], wrapped[1400];
  unsigned char raw[64], bytes[1100], back[64];
  char text[64];

  text_t at = TEXT`kv/disk/${diskId}/key`;
  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("GET", path, NULL);

  if (got.status == 404) {
    got.release();
    ++self->skipped;
    return true;
  }

  if (!got.ok) {
    snprintf(self->why, sizeof self->why, "cannot read the key of %s from kv/ (%d)", diskId, got.status);
    got.release();
    return false;
  }

  /* {"data":[byte, ...]}: the 44 characters of base64 the guest used as passphrase */
  json_t doc = got.json();
  got.release();
  json_t list = doc.data.data;
  int count = list.count();

  for (int i = 0; i < count && i < (int)sizeof text - 1; ++i)
    text[i] = (char)list[i].number();

  text[count > 0 && count < (int)sizeof text ? count : 0] = 0;
  doc.release();

  long length = fromBase64(text, raw, sizeof raw);
  OPENSSL_cleanse(text, sizeof text);

  if (length != 32) {
    snprintf(self->why, sizeof self->why, "the key of %s in kv/ is not 32 bytes in base64", diskId);
    return false;
  }

  EVP_PKEY *guest = wrapTestKey();
  bool good = guest != NULL && transitImport(diskId, raw, 32) &&
              transitWrap(diskId, guest, wrapped, sizeof wrapped) == NULL;

  if (good) {
    long n = fromBase64(wrapped, bytes, sizeof bytes);
    good = n > 0 && wrapOpen(guest, EVP_sha256(), bytes, (size_t)n, back, sizeof back) == 32 &&
           CRYPTO_memcmp(back, raw, 32) == 0;
  }

  EVP_PKEY_free(guest);
  OPENSSL_cleanse(raw, sizeof raw);
  OPENSSL_cleanse(back, sizeof back);

  if (!good) {
    snprintf(self->why, sizeof self->why, "the key of %s does not come back from transit as it went in", diskId);
    return false;
  }

  fetch_answer_t gone = baoCall("DELETE", path, NULL);
  bool deleted = gone.ok || gone.status == 404;
  gone.release();

  if (!deleted)
    fprintf(stderr, "wx1-keyagent: import: the key of %s is in transit, but still in kv/ too - "
                    "delete it there (bao delete %s)\n", diskId, path);

  ++self->keys;

  return true;
}

/** The disks not shredded, their keys moved. */
static bool legacyKeys(legacy_t *self) {

  bool failed = false, good = true;
  json_t disks = stateList("disks/", &failed);

  for (int i = 0; good && !failed && i < disks.count(); ++i) {

    const char *id = disks[i].text() ?: "";
    entry_t disk = storeGet("disks", id);
    bool shredded = disk.found && strcmp(disk.payload().status.text() ?: "", "deleted") == 0;
    disk.release();

    if (!shredded && isDiskId(id))
      good = legacyKey(self, id);
  }

  disks.release();

  if (failed)
    snprintf(self->why, sizeof self->why, "cannot list the disks in the database");

  return good && !failed;
}

static int legacyImportWith(void);

/** In nginx's master: with a connection of its own, closed before the workers are forked. */
static int legacyImport(void) {

  if (keysPkcs11 || strcmp(env("WX_IMPORT_OPENBAO_KV", "auto"), "off") == 0)
    return 0;

  if (dbConnect() != 0)
    return 1;

  int failed = legacyImportWith();
  dbClose();

  return failed;
}

static int legacyImportWith(void) {

  entry_t marker = stateRead(legacyMarker);
  bool done = marker.found, failed = marker.failed;
  marker.release();

  if (failed) {
    fprintf(stderr, "wx1-keyagent: import: cannot read the state\n");
    return 1;
  }

  if (done)
    return 0;

  /* nothing there, or no right to look: a new installation */
  int status = 0;
  json_t top = legacyList("", &status);
  top.release();

  if (status != 200)
    return 0;

  legacy_t self = {0};

  fprintf(stderr, "wx1-keyagent: import: the state from OpenBao wx/ into the database, the disk keys "
                  "from kv/ into transit\n");

  bool good = legacyWalk(&self, "", false) && legacyWalk(&self, "", true) && legacyKeys(&self);

  if (!good) {
    fprintf(stderr, "wx1-keyagent: import stopped: %s\n", self.why);
    return 1;
  }

  long now = (long)time(NULL);
  json_t note = {at: now, entries: self.entries, keys: self.keys};
  char *json = note.owned();
  note.release();

  bool conflict = false;
  bool marked = json != NULL && (stateWrite(legacyMarker, json, 0, &conflict) || conflict);
  free(json);

  if (!marked) {
    fprintf(stderr, "wx1-keyagent: import: cannot mark it done\n");
    return 1;
  }

  fprintf(stderr, "wx1-keyagent: import done: %d entries, %d disk keys (%d without a key in kv/); "
                  "wx/ is left as it was\n", self.entries, self.keys, self.skipped);

  return 0;
}

#endif /* WX_LEGACY_H */

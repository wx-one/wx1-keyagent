/**
 * OpenBao client: KV v1 for keys (mount "kv", read by the KBS), KV v2 for the
 * agent's state (mount "wx", check-and-set).
 */
#ifndef WX_BAO_H
#define WX_BAO_H

#include "util.h"

#include <meta_fetch.h>
#include <meta_json.h>
#include <meta_text.h>

static char baoUrl[512];
static char baoToken[256];

static bool baoConfigure(void) {

  text_t url = TEXT`${env("WX_OPENBAO_URL", "http://127.0.0.1:8200")}`;

  url.into(baoUrl, sizeof baoUrl);

  return readSecret(env("WX_OPENBAO_TOKEN_FILE", "/secrets/openbao-token"), baoToken,
                    sizeof baoToken);
}

static fetch_answer_t baoCall(const char *method, const char *path, const char *body) {

  char url[1024];

  text_t at = TEXT`${baoUrl}/v1/${path}`;

  at.into(url, sizeof url);

  fetch_call_t call = freshCall(method, url).header("x-vault-token", baoToken);

  if (body != NULL)
    call = call.json(body);

  return call.send();
}

/**
 * Whether the agent's state mount (wx/, KV v2) is there and usable.
 *
 * Enabled here if the token may (a root token in a test); a token with the
 * agent's own policy (deploy/openbao-policy.hcl) may not, and then the
 * operator enables it once. Either way it is checked by listing it: 200 or
 * 404 (empty) means it answers.
 */
static bool baoEnsureStateMount(void) {

  fetch_answer_t made = baoCall("POST", "sys/mounts/wx",
                                "{\"type\":\"kv\",\"options\":{\"version\":\"2\"}}");
  made.release();

  fetch_answer_t got = baoCall("LIST", "wx/metadata/", NULL);
  int status = got.status;
  got.release();

  return status == 200 || status == 404;
}

/* ------------------------------------------------------------ KV v2 state */

/** An entry: its data (owned, release with json) and its version, 0 if absent. */
typedef struct {
  json_t data;
  long version;
  bool found;
  bool failed;
} bao_entry_t;

static bao_entry_t baoRead(const char *key) {

  char path[512];
  bao_entry_t entry = {0};

  text_t at = TEXT`wx/data/${key}`;

  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("GET", path, NULL);

  if (got.status == 404) {
    got.release();
    return entry;
  }

  if (!got.ok) {
    entry.failed = true;
    got.release();
    return entry;
  }

  json_t doc = got.json();
  got.release();

  entry.found = true;
  entry.version = doc.get("data").get("metadata").get("version").number();
  entry.data = doc;

  return entry;
}

/** The entry's payload, a view into `entry.data`. */
static json_t bao_entry_t__payload(bao_entry_t *self) {
  return self->data.get("data").get("data");
}

static void bao_entry_t__release(bao_entry_t *self) {

  if (self->found)
    self->data.release();

  self->found = false;
}

/**
 * Writes `json` (an object) as the entry. `cas` is the version it must still
 * have: 0 for "must not exist yet", -1 for "whatever is there". Answers
 * whether it was written; false with `*conflict` set means someone else
 * wrote first.
 */
static bool baoWrite(const char *key, const char *json, long cas, bool *conflict) {

  char path[512];
  buf_t body = {0};
  bool written;

  text_t at = TEXT`wx/data/${key}`;

  at.into(path, sizeof path);

  if (cas >= 0)
    buf_t__printf(&body, "{\"options\":{\"cas\":%ld},\"data\":%s}", cas, json);
  else
    buf_t__printf(&body, "{\"data\":%s}", json);

  fetch_answer_t got = baoCall("POST", path, body.at);

  written = got.ok;

  if (conflict != NULL)
    *conflict = !got.ok && got.status == 400 && got.body != NULL &&
                strstr(got.body, "check-and-set") != NULL;

  got.release();
  free(body.at);

  return written;
}

/** Removes an entry with all its versions. */
static bool baoDestroy(const char *key) {

  char path[512];

  text_t at = TEXT`wx/metadata/${key}`;

  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("DELETE", path, NULL);
  bool done = got.ok || got.status == 404;

  got.release();

  return done;
}

/** Keys directly under a prefix ("disks/"), as a JSON array view; owned. */
static json_t baoList(const char *prefix, bool *failed) {

  char path[512];

  text_t at = TEXT`wx/metadata/${prefix}`;

  at.into(path, sizeof path);

  fetch_answer_t got = baoCall("LIST", path, NULL);
  json_t doc = {0};

  *failed = !got.ok && got.status != 404;

  if (got.ok)
    doc = got.json();

  got.release();

  return doc;
}

/* --------------------------------------------------------------- KV v1 keys */

/**
 * A key as the KBS stores and reads it: {"data":[byte, byte, ...]} under
 * kv/<path>. Writing a new value over an old one destroys the old one.
 */
static bool baoPutKey(const char *path, const unsigned char *key, size_t length) {

  char where[512];
  buf_t body = {0};

  buf_t__put(&body, "{\"data\":[");

  for (size_t i = 0; i < length; ++i)
    buf_t__printf(&body, "%s%u", i ? "," : "", key[i]);

  buf_t__put(&body, "]}");

  text_t at = TEXT`kv/${path}`;

  at.into(where, sizeof where);

  fetch_answer_t got = baoCall("POST", where, body.at);
  bool done = got.ok;

  got.release();
  free(body.at);

  return done;
}

/** Reads a key back; its length, or -1. */
static long baoGetKey(const char *path, unsigned char *into, size_t room) {

  char where[512];
  long length = -1;

  text_t at = TEXT`kv/${path}`;

  at.into(where, sizeof where);

  fetch_answer_t got = baoCall("GET", where, NULL);

  if (got.ok) {
    json_t doc = got.json();
    json_t bytes = doc.get("data").get("data");
    int count = bytes.count();

    if (count >= 0 && (size_t)count <= room) {
      for (int i = 0; i < count; ++i)
        into[i] = (unsigned char)bytes.at(i).number();
      length = count;
    }

    doc.release();
  }

  got.release();

  return length;
}

#endif /* WX_BAO_H */

/**
 * The agent's state, by what it means rather than where it lives.
 *
 * In the table `state`, one row per entry, signed with the key store's state
 * key (keys.h) over its name, version and content:
 *   disks/<id>         status, release mode, time window, replay interval
 *   attachments/<id>   the binding: VM, HOST_DATA, initdata, user-data, hosts
 *   vtpm/<host_data>   the VM's vTPM: disk, VM, the EK once bound, and the
 *                      replay stand - in one entry, so neither can go alone
 *   settings           host pool, SSH keys, auto rules, boot chain references
 * A row whose signature is not the store's is not read: it was changed
 * outside the agent. What the signature cannot tell is a whole row put back
 * as it was before (an old backup) - as with OpenBao's storage, whoever runs
 * the database can do that; and a row taken out, which is why the release
 * asks for the entries a disk must have (release.h).
 *
 * Next to it, unsigned, because nothing is released on their word alone:
 * requests, leases, releases (the log).
 *
 * Every write is read, change, write back if the version is still the one
 * read, and once more on a conflict - two workers changing one entry both
 * get theirs.
 */
#ifndef WX_STORE_H
#define WX_STORE_H

#include "db.h"
#include "keys.h"

#include <time.h>

/* --------------------------------------------------------------- entries */

/** An entry: its content (owned, release with json) and its version, 0 if absent. */
typedef struct {
  json_t data;
  long version;
  bool found;
  bool failed;
} entry_t;

/** What the signature covers: the name, the version, the content as stored. */
static void stateSigned(buf_t *into, const char *key, long version, const char *data) {
  buf_t__printf(into, "wx1-keyagent state\n%s\n%ld\n", key, version);
  buf_t__put(into, data);
}

static entry_t stateRead(const char *key) {

  entry_t entry = {0};

  sql_t q = SQL`select data, version, mac from state where key = ${key}`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r == NULL || PQresultStatus(r) != PGRES_TUPLES_OK) {
    entry.failed = true;
  } else if (PQntuples(r) == 1) {

    const char *data = PQgetvalue(r, 0, 0);
    long version = atol(PQgetvalue(r, 0, 1));
    buf_t message = {0};

    stateSigned(&message, key, version, data);

    int valid = message.broke ? -1 : keysMacOk(message.at, message.length, PQgetvalue(r, 0, 2));
    free(message.at);

    if (valid == 1) {
      entry.found = true;
      entry.version = version;
      entry.data = meta_toJSON(data);
    } else {
      entry.failed = true;
      if (valid == 0)
        fprintf(stderr, "wx1-keyagent: state %s is not signed by the key store: changed outside the "
                        "agent, not used\n", key);
    }
  }

  if (r != NULL)
    PQclear(r);

  return entry;
}

/** The entry's content. */
static json_t entry_t__payload(entry_t *self) {
  return self->data;
}

static void entry_t__release(entry_t *self) {

  if (self->found)
    self->data.release();

  self->found = false;
}

/**
 * Writes `json` (an object) as the entry. `cas` is the version it must still
 * have: 0 for "must not exist yet". Answers whether it was written; false
 * with `*conflict` set means someone else wrote first.
 */
static bool stateWrite(const char *key, const char *json, long cas, bool *conflict) {

  char mac[160];
  buf_t message = {0};
  long version = cas + 1, changed;

  if (conflict != NULL)
    *conflict = false;

  stateSigned(&message, key, version, json);
  bool signedOk = !message.broke && keysMac(message.at, message.length, mac, sizeof mac);
  free(message.at);

  if (!signedOk)
    return false;

  if (cas == 0) {
    sql_t q = SQL`insert into state (key, version, data, mac) values (${key}, 1, ${json}, ${(const char *)mac})
      on conflict (key) do nothing`;
    changed = dbCount(&q);
    q.release();
  } else {
    sql_t q = SQL`update state set version = ${version}, data = ${json}, mac = ${(const char *)mac},
        updated = now()
      where key = ${key} and version = ${cas}`;
    changed = dbCount(&q);
    q.release();
  }

  if (conflict != NULL)
    *conflict = changed == 0;

  return changed == 1;
}

/** Removes an entry. */
static bool stateDrop(const char *key) {

  sql_t q = SQL`delete from state where key = ${key}`;
  bool done = dbDo(&q);
  q.release();

  return done;
}

/** The names directly under a prefix ("disks/"), as a JSON array; owned. */
static json_t stateList(const char *prefix, bool *failed) {

  /* the range [prefix, prefix with its last character one higher) */
  char end[64];
  size_t n = strlen(prefix);

  if (n == 0 || n >= sizeof end) {
    *failed = true;
    return meta_toJSON("[]");
  }

  memcpy(end, prefix, n + 1);
  end[n - 1] = (char)(end[n - 1] + 1);

  sql_t q = SQL`select key from state where key > ${prefix} and key < ${(const char *)end} order by key`;
  PGresult *r = dbAsk(&q);
  q.release();

  json_t names = meta_toJSON("[]");
  *failed = r == NULL || PQresultStatus(r) != PGRES_TUPLES_OK;

  for (int i = 0; !*failed && i < PQntuples(r); ++i) {
    const char *name = PQgetvalue(r, i, 0) + n;
    if (strchr(name, '/') == NULL)
      names.push(name);
  }

  if (r != NULL)
    PQclear(r);

  return names;
}

/** An edit: changes the entry it is given and answers whether to write it back. */
typedef bool (*state_edit_t)(json_t entry, void *with);

/**
 * Changes one entry: `edit` gets its content (an empty object when there is
 * none) and answers whether to write it back. A conflict reads again and
 * edits again, after a short random wait that grows, so writers that
 * collided do not collide again in step.
 */
static bool stateEdit(const char *key, state_edit_t edit, void *with) {

  for (int attempt = 0; attempt < 12; ++attempt) {

    if (attempt > 0) {
      unsigned char r = 0;
      randomBytes(&r, 1);
      meta_sleepMs((long)(r % (5 << (attempt < 6 ? attempt : 6))) + 1);
    }

    entry_t entry = stateRead(key);

    if (entry.failed)
      return false;

    long version = entry.found ? entry.version : 0;
    json_t content = entry.found ? entry.data : meta_toJSON("{}");

    /* the content is the edit's now, released once below */
    entry.found = false;

    char *json = edit(content, with) ? content.owned() : NULL;
    content.release();

    if (json == NULL)
      return false;

    bool conflict = false;
    bool written = stateWrite(key, json, version, &conflict);
    free(json);

    if (written || !conflict)
      return written;
  }

  return false;
}

/** The top-level fields of the patch set in the entry; a null takes one out. */
static bool stateMerge(json_t entry, void *with) {

  json_t patch = *(json_t *)with;

  for (int i = 0; i < patch.count(); ++i) {

    const char *key = patch.keyAt(i);
    json_t value = patch.get(key);

    if (value.isNothing())
      entry.remove(key);
    else
      entry.set(key, value);
  }

  return true;
}

/** Sets the top-level fields of `patch` in the entry; a null removes one. */
static bool statePatch(const char *key, json_t patch) {
  return stateEdit(key, stateMerge, &patch);
}

/** A new entry, written only if there is none yet; `*taken` if there was. */
static bool stateCreate(const char *key, json_t entry, bool *taken) {

  char *json = entry.owned();
  bool conflict = false;
  bool written = json != NULL && stateWrite(key, json, 0, &conflict);

  free(json);
  *taken = conflict;

  return written;
}

/* ---------------------------------------------- disks, attachments, settings */

/**
 * disks/<id>, attachments/<id>, vtpm/<host_data>, settings: read whole,
 * changed field by field. `id` NULL for settings.
 */
static entry_t storeGet(const char *kind, const char *id) {

  char key[200];

  text_t at = id != NULL ? TEXT`${kind}/${id}` : TEXT`${kind}`;
  at.into(key, sizeof key);

  return stateRead(key);
}

static bool storeSet(const char *kind, const char *id, json_t patch) {

  char key[200];

  text_t at = id != NULL ? TEXT`${kind}/${id}` : TEXT`${kind}`;
  at.into(key, sizeof key);

  return statePatch(key, patch);
}

static bool storeDrop(const char *kind, const char *id) {

  char key[200];

  text_t at = TEXT`${kind}/${id}`;
  at.into(key, sizeof key);

  return stateDrop(key);
}

/* ------------------------------------------------------------ replay stand */

/**
 * In vtpm/<host_data>: replay_nv, replay_confirmed, replay_issued, replay_at.
 * The guest proves the stand in its vTPM; it has to be at least the last
 * confirmed one (never "exactly the last issued": a lost answer leaves the
 * previous one in the vTPM) and at most the last issued one.
 */
typedef struct {
  char nvName[80];
  long confirmed;
  long issued;
  long at; /* when it was last confirmed */
  bool found;
  bool failed;
} replay_t;

static replay_t storeReplay(const char *hostData) {

  replay_t stand = {0};
  entry_t entry = storeGet("vtpm", hostData);

  stand.failed = entry.failed;

  if (entry.found) {
    json_t p = entry.payload();
    text_t name = TEXT`${p.get("replay_nv").text() ?: ""}`;
    name.into(stand.nvName, sizeof stand.nvName);
    stand.found = stand.nvName[0] != 0;
    stand.confirmed = p.get("replay_confirmed").number();
    stand.issued = p.get("replay_issued").number();
    stand.at = p.get("replay_at").number();
    entry.release();
  }

  return stand;
}

/** NULL when `seen` (in NV index `nvName`) is acceptable, else why not. */
static const char *replay_t__refuses(replay_t *self, const char *nvName, long seen) {

  if (!self->found || self->nvName[0] == 0)
    return NULL;

  if (strcmp(nvName, self->nvName) != 0)
    return "another NV index than before (replay protection)";

  if (seen < self->confirmed)
    return "vTPM state was played back: its stand is older than the last confirmed one";

  if (seen > self->issued)
    return "the vTPM's stand was never issued";

  return NULL;
}

typedef struct {
  const char *nvName;
  long seen;
  long next;
} replay_step_t;

static bool replayStep(json_t entry, void *with) {

  replay_step_t *step = (replay_step_t *)with;
  json_t confirmed = entry.replay_confirmed;

  /* the entry is made with the binding; one that is not there is not made here */
  if (entry.count() == 0)
    return false;

  /* someone confirmed a later stand since we checked */
  if (!confirmed.isNothing() && confirmed.number() > step->seen)
    return false;

  entry.replay_nv = step->nvName;
  entry.replay_confirmed = step->seen;
  entry.replay_issued = step->next;
  entry.replay_at = (long)time(NULL);

  return true;
}

/** After a release: `seen` is confirmed, `next` handed out. */
static bool storeReplayConfirm(const char *hostData, const char *nvName, long seen, long next) {

  char key[160];
  replay_step_t step = {nvName, seen, next};

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  return stateEdit(key, replayStep, &step);
}

/** The customer's reset: the next release starts the stand anew. */
static bool storeReplayReset(const char *hostData) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  json_t reset = {replay_nv: NULL, replay_confirmed: NULL, replay_issued: NULL, replay_at: NULL};
  bool done = statePatch(key, reset);
  reset.release();

  return done;
}

/* ------------------------------------------------------------- EK binding */

/**
 * vtpm/<host_data>.ek: the persistent vTPM's EK, pinned on the first release.
 * Another one means its state was lost or swapped, or SVSM fell back to an
 * ephemeral vTPM; nothing is released until the customer unbinds it.
 *
 * 1 with the EK in `ek` ("" when none is pinned yet), 0 when the VM has no
 * vTPM entry at all, -1 when the state cannot be read.
 */
static int storeEk(const char *hostData, char *ek, size_t room) {

  entry_t entry = storeGet("vtpm", hostData);

  ek[0] = 0;

  if (entry.failed)
    return -1;

  if (!entry.found)
    return 0;

  text_t got = TEXT`${entry.payload().get("ek").text() ?: ""}`;
  got.into(ek, room);
  entry.release();

  return 1;
}

static bool ekPin(json_t entry, void *with) {

  /* no entry: not made here. Already bound, to this one or another: nothing to do */
  if (entry.count() == 0 || entry.ek.text()[0] != 0)
    return false;

  entry.ek = (const char *)with;
  entry.ek_first = (long)time(NULL);

  return true;
}

static void storePinEk(const char *hostData, const char *ek) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  stateEdit(key, ekPin, (void *)ek);
}

/** The customer's decision that the vTPM may be a new one: EK and replay stand anew. */
static bool storeUnbindEk(const char *hostData) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  json_t unbind = {ek: NULL, ek_first: NULL, replay_nv: NULL, replay_confirmed: NULL,
                   replay_issued: NULL, replay_at: NULL};
  bool done = statePatch(key, unbind);
  unbind.release();

  return done;
}

/* ----------------------------------------------------------------- leases */

/**
 * At most one running instance (REPORT_ID) per disk. Taken or extended in one
 * statement, so two instances racing for a free disk cannot both win.
 */
static bool storeTakeLease(const char *disk, const char *reportId, const char *chipId, long ttl) {

  sql_t q = SQL`insert into leases (disk_id, report_id, chip_id, expires, first_seen)
    values (${disk}, ${reportId}, ${chipId}, now() + ${ttl}::INT8 * interval '1 second', now())
    on conflict (disk_id) do update set
      report_id = excluded.report_id, chip_id = excluded.chip_id, expires = excluded.expires,
      first_seen = case when leases.report_id = excluded.report_id
                        then leases.first_seen else excluded.first_seen end
    where leases.report_id = excluded.report_id or leases.expires < now()
    returning disk_id`;

  PGresult *r = dbAsk(&q);
  q.release();
  bool took = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (r != NULL)
    PQclear(r);

  return took;
}

/** Whether this instance holds the disk's lease right now (for a renewal). */
static bool storeHoldsLease(const char *disk, const char *reportId) {

  sql_t q = SQL`select 1 from leases
    where disk_id = ${disk} and report_id = ${reportId} and expires >= now()`;

  PGresult *r = dbAsk(&q);
  q.release();
  bool holds = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (r != NULL)
    PQclear(r);

  return holds;
}

/** Whether this instance could take the lease: free, expired or its own. */
static bool storeLeaseOpen(const char *disk, const char *reportId) {

  sql_t q = SQL`select 1 from leases
    where disk_id = ${disk} and report_id <> ${reportId} and expires >= now()`;

  PGresult *r = dbAsk(&q);
  q.release();
  bool open = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0;

  if (r != NULL)
    PQclear(r);

  return open;
}

/** A clean shutdown gives the lease back. */
static bool storeEndLease(const char *disk, const char *reportId) {

  sql_t q = SQL`delete from leases where disk_id = ${disk} and report_id = ${reportId}`;

  bool done = dbDo(&q);
  q.release();

  return done;
}

/** The customer's reset (UI/API): the instance is gone, don't wait for expiry. */
static bool storeResetLease(const char *disk) {

  sql_t q = SQL`delete from leases where disk_id = ${disk}`;

  bool done = dbDo(&q);
  q.release();

  return done;
}

/* ------------------------------------------------------------ release log */

static void storeLog(const char *disk, const char *step, bool ok, const char *detail,
                     const char *ctx, const char *source) {

  sql_t q = SQL`insert into releases (disk_id, step, ok, detail, ctx, source)
    values (${disk ?: ""}, ${step}, ${ok}, ${detail ?: ""}, ${ctx ?: "{}"}::JSONB, ${source ?: ""})`;

  bool done = dbDo(&q);
  q.release();

  if (!done)
    fprintf(stderr, "wx1-keyagent: cannot log %s for %s\n", step, disk ?: "-");
}

#endif /* WX_STORE_H */

/**
 * The agent's state, by what it means rather than where it lives.
 *
 * In OpenBao (wx/, KV v2), because key releases depend on it:
 *   disks/<id>         status, release mode, time window, replay interval
 *   attachments/<id>   the binding: VM, HOST_DATA, initdata, user-data, hosts
 *   vtpm/<host_data>   the VM's vTPM: disk, VM, EK once bound
 *   replay/<host_data> the replay stand, written on its own and often
 *   settings           host pool, SSH keys, auto rules, boot chain references
 *
 * In the database, because nothing is released on their word:
 *   requests, leases, releases (the log).
 *
 * Every write to OpenBao is read, change, write back with check-and-set, and
 * once more on a conflict - two workers changing one entry both get theirs.
 */
#ifndef WX_STORE_H
#define WX_STORE_H

#include "bao.h"
#include "db.h"

#include <time.h>

/* ------------------------------------------------------- OpenBao entries */

typedef bool (*bao_edit_t)(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with);

/**
 * Changes one entry: `edit` gets the current payload as a mutable copy (an
 * empty object when there is none) and answers whether to write it back.
 * A conflict reads again and edits again, after a short random wait that
 * grows, so writers that collided do not collide again in step.
 */
static bool baoEdit(const char *key, bao_edit_t edit, void *with) {

  for (int attempt = 0; attempt < 12; ++attempt) {

    if (attempt > 0) {
      unsigned char r = 0;
      randomBytes(&r, 1);
      meta_sleepMs((long)(r % (5 << (attempt < 6 ? attempt : 6))) + 1);
    }

    bao_entry_t entry = baoRead(key);

    if (entry.failed)
      return false;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = NULL;

    if (entry.found)
      root = yyjson_val_mut_copy(doc, entry.payload().node);

    if (root == NULL || !yyjson_mut_is_obj(root))
      root = yyjson_mut_obj(doc);

    yyjson_mut_doc_set_root(doc, root);

    long version = entry.found ? entry.version : 0;
    entry.release();

    if (!edit(doc, root, with)) {
      yyjson_mut_doc_free(doc);
      return false;
    }

    char *json = yyjson_mut_write(doc, 0, NULL);
    bool conflict = false;
    bool written = json != NULL && baoWrite(key, json, version, &conflict);

    free(json);
    yyjson_mut_doc_free(doc);

    if (written || !conflict)
      return written;
  }

  return false;
}

static bool baoMerge(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  yyjson_val *patch = ((json_t *)with)->node;
  yyjson_val *key, *value;
  yyjson_obj_iter it;

  if (!yyjson_is_obj(patch))
    return false;

  yyjson_obj_iter_init(patch, &it);

  while ((key = yyjson_obj_iter_next(&it)) != NULL) {
    value = yyjson_obj_iter_get_val(key);
    yyjson_mut_obj_remove_str(root, yyjson_get_str(key));

    if (!yyjson_is_null(value))
      yyjson_mut_obj_put(root, yyjson_val_mut_copy(doc, key), yyjson_val_mut_copy(doc, value));
  }

  return true;
}

/** Sets the top-level fields of `patch` in the entry; a null removes one. */
static bool baoPatch(const char *key, json_t patch) {
  return baoEdit(key, baoMerge, &patch);
}

/* ---------------------------------------------- disks, attachments, settings */

/**
 * disks/<id>, attachments/<id>, vtpm/<host_data>, settings: read whole,
 * changed field by field. `id` NULL for settings.
 */
static bao_entry_t storeGet(const char *kind, const char *id) {

  char key[200];

  text_t at = id != NULL ? TEXT`${kind}/${id}` : TEXT`${kind}`;
  at.into(key, sizeof key);

  return baoRead(key);
}

static bool storeSet(const char *kind, const char *id, json_t patch) {

  char key[200];

  text_t at = id != NULL ? TEXT`${kind}/${id}` : TEXT`${kind}`;
  at.into(key, sizeof key);

  return baoPatch(key, patch);
}

static bool storeDrop(const char *kind, const char *id) {

  char key[200];

  text_t at = TEXT`${kind}/${id}`;
  at.into(key, sizeof key);

  return baoDestroy(key);
}

/* ------------------------------------------------------------ replay stand */

/**
 * replay/<host_data>: {nv_name, confirmed, issued}. The guest proves the stand
 * in its vTPM; it has to be at least the last confirmed one (never "exactly
 * the last issued": a lost answer leaves the previous one in the vTPM) and at
 * most the last issued one.
 */
typedef struct {
  char nvName[80];
  long confirmed;
  long issued;
  bool found;
  bool failed;
} replay_t;

static replay_t storeReplay(const char *hostData) {

  char key[160];
  replay_t stand = {0};

  text_t at = TEXT`replay/${hostData}`;
  at.into(key, sizeof key);

  bao_entry_t entry = baoRead(key);

  stand.failed = entry.failed;
  stand.found = entry.found;

  if (entry.found) {
    json_t p = entry.payload();
    text_t name = TEXT`${p.get("nv_name").text() ?: ""}`;
    name.into(stand.nvName, sizeof stand.nvName);
    stand.confirmed = p.get("confirmed").number();
    stand.issued = p.get("issued").number();
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

static bool replayStep(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  replay_step_t *step = (replay_step_t *)with;
  yyjson_mut_val *confirmed = yyjson_mut_obj_get(root, "confirmed");

  /* someone confirmed a later stand since we checked */
  if (confirmed != NULL && yyjson_mut_get_sint(confirmed) > step->seen)
    return false;

  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "nv_name"), yyjson_mut_strcpy(doc, step->nvName));
  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "confirmed"), yyjson_mut_sint(doc, step->seen));
  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "issued"), yyjson_mut_sint(doc, step->next));

  return true;
}

/** After a release: `seen` is confirmed, `next` handed out. */
static bool storeReplayConfirm(const char *hostData, const char *nvName, long seen, long next) {

  char key[160];
  replay_step_t step = {nvName, seen, next};

  text_t at = TEXT`replay/${hostData}`;
  at.into(key, sizeof key);

  return baoEdit(key, replayStep, &step);
}

/* ------------------------------------------------------------- EK binding */

/**
 * vtpm/<host_data>.ek: the persistent vTPM's EK, pinned on the first release.
 * Another one means its state was lost or swapped, or SVSM fell back to an
 * ephemeral vTPM; nothing is released until the customer unbinds it.
 */
static bool storeEk(const char *hostData, char *ek, size_t room) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  bao_entry_t entry = baoRead(key);

  ek[0] = 0;

  if (entry.found) {
    text_t got = TEXT`${entry.payload().get("ek").text() ?: ""}`;
    got.into(ek, room);
    entry.release();
  }

  return !entry.failed;
}

static bool ekPin(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  yyjson_mut_val *ek = yyjson_mut_obj_get(root, "ek");

  /* already bound, to this one or another: nothing to do here */
  if (ek != NULL && yyjson_mut_get_len(ek) > 0)
    return false;

  yyjson_mut_obj_remove_str(root, "ek");
  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "ek"), yyjson_mut_strcpy(doc, (const char *)with));
  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "ek_first"), yyjson_mut_sint(doc, (int64_t)time(NULL)));

  return true;
}

static void storePinEk(const char *hostData, const char *ek) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  baoEdit(key, ekPin, (void *)ek);
}

/** The customer's decision that the vTPM may be a new one. */
static bool storeUnbindEk(const char *hostData) {

  char key[160];

  text_t at = TEXT`vtpm/${hostData}`;
  at.into(key, sizeof key);

  json_t unbind = meta_toJSON("{\"ek\":null,\"ek_first\":null}");
  bool done = baoPatch(key, unbind);
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
    fprintf(stderr, "wx-keyagent: cannot log %s for %s\n", step, disk ?: "-");
}

#endif /* WX_STORE_H */

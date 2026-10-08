/**
 * wx-keyagent: the customer's side of confidential VMs.
 *
 * Runs at the customer, never at the provider. Holds nothing itself: the
 * keys and everything a key release depends on live in the customer's
 * OpenBao, history and leases in a database (PostgreSQL or CockroachDB).
 *
 * For now only the health check, which asks each of the three things this
 * stands on - the database, OpenBao and OpenSSL - and says which answered.
 */
#include <meta_http.h>

#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int startWorker(void) {

  if (!baoConfigure())
    fprintf(stderr, "wx-keyagent: no OpenBao token\n");

  return dbConnect();
}

static http_response_t health(http_request_t *req) {

  static char body[512];
  char hash[65];
  bool db = false;

  {
    sql_t q = SQL`select 1`;
    PGresult *r = dbAsk(&q);
    q.release();
    db = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK;
  }

  char where[256];
  text_t at = TEXT`${baoUrl}/v1/sys/health`;
  at.into(where, sizeof where);

  fetch_answer_t bao = meta_get(where);
  int baoStatus = bao.status;
  bao.release();

  sha256Hex("wx-keyagent", 11, hash);

  obj answer = {
    database: db,
    openbao: baoStatus,
    sha256: hash,
  };

  answer.toJSON(body, sizeof body);

  return req.reply(db && baoStatus == 200 ? 200 : 503).json(body);
}

/** Exercises the OpenBao client: mount, write, read, check-and-set, keys. */
static http_response_t selftest(http_request_t *req) {

  static char said[512];
  bool conflict = false;
  unsigned char key[32], back[64];

  bool mount = baoEnsureStateMount();
  baoDestroy("selftest/x");
  bool first = baoWrite("selftest/x", "{\"n\":1}", 0, &conflict);
  bool again = baoWrite("selftest/x", "{\"n\":2}", 0, &conflict);
  bao_entry_t e = baoRead("selftest/x");
  long n = e.payload().get("n").number();
  long version = e.version;
  e.release();
  bool update = baoWrite("selftest/x", "{\"n\":3}", version, NULL);

  randomBytes(key, sizeof key);
  bool put = baoPutKey("selftest/key", key, sizeof key);
  long length = baoGetKey("selftest/key", back, sizeof back);
  bool same = length == 32 && memcmp(key, back, 32) == 0;

  snprintf(said, sizeof said,
           "mount=%d first=%d again=%d(conflict=%d) n=%ld v=%ld update=%d key=%d/%d\n",
           mount, first, again, conflict, n, version, update, put, same);

  return req.reply(200).text(said);
}

/** Exercises the state: patch, replay stand, EK binding, leases. */
static http_response_t storetest(http_request_t *req) {

  static char said[1024];
  char ek[80];

  storeDrop("disks", "t");
  storeDrop("replay", "hd");
  storeDrop("vtpm", "hd");
  storeResetLease("t");

  json_t a = meta_toJSON("{\"status\":\"active\",\"mode\":\"auto\"}");
  json_t b = meta_toJSON("{\"mode\":\"manual\",\"status\":null}");
  bool set1 = storeSet("disks", "t", a);
  bool set2 = storeSet("disks", "t", b);
  a.release();
  b.release();
  bao_entry_t d = storeGet("disks", "t");
  const char *mode = d.payload().get("mode").text();
  bool statusGone = d.payload().get("status").isNothing();
  text_t m = TEXT`${mode ?: "-"}`;
  char modeText[32];
  m.into(modeText, sizeof modeText);
  d.release();

  replay_t r0 = storeReplay("hd");
  const char *fresh = r0.refuses("0x01500021", 0);
  bool c1 = storeReplayConfirm("hd", "0x01500021", 0, 1);
  bool c2 = storeReplayConfirm("hd", "0x01500021", 1, 2);
  replay_t r1 = storeReplay("hd");
  const char *older = r1.refuses("0x01500021", 0);
  const char *same = r1.refuses("0x01500021", 1);
  const char *lost = r1.refuses("0x01500021", 2);
  const char *never = r1.refuses("0x01500021", 3);
  const char *other = r1.refuses("0x01500022", 2);
  bool back = storeReplayConfirm("hd", "0x01500021", 0, 1);

  storePinEk("hd", "ek-one");
  storePinEk("hd", "ek-two");
  storeEk("hd", ek, sizeof ek);
  bool pinned = strcmp(ek, "ek-one") == 0;
  storeUnbindEk("hd");
  storeEk("hd", ek, sizeof ek);
  bool unbound = ek[0] == 0;

  bool l1 = storeTakeLease("t", "rid-a", "chip", 180);
  bool l2 = storeTakeLease("t", "rid-b", "chip", 180);
  bool l3 = storeTakeLease("t", "rid-a", "chip", 180);
  bool holds = storeHoldsLease("t", "rid-a");
  bool reset = storeResetLease("t");
  bool l4 = storeTakeLease("t", "rid-b", "chip", 180);
  bool ended = storeEndLease("t", "rid-b");
  bool gone = !storeHoldsLease("t", "rid-b");
  storeLog("t", "storetest", true, "ok", NULL, "test");

  text_t out = TEXT`set=${set1}/${set2} mode=${modeText} statusGone=${statusGone}
replay fresh=${fresh ?: "ok"} confirm=${c1}/${c2} older=${older ?: "ok"} same=${same ?: "ok"} lost=${lost ?: "ok"} never=${never ?: "ok"} other=${other ?: "ok"} back=${back}
ek pinned=${pinned} unbound=${unbound}
lease a=${l1} b=${l2} a-again=${l3} holds=${holds} reset=${reset} b-after-reset=${l4} ended=${ended} gone=${gone}
`;
  out.into(said, sizeof said);

  return req.reply(200).text(said);
}

static bool bumpOne(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  yyjson_mut_val *n = yyjson_mut_obj_get(root, "n");
  int64_t was = n != NULL ? yyjson_mut_get_sint(n) : 0;

  yyjson_mut_obj_remove_str(root, "n");
  yyjson_mut_obj_put(root, yyjson_mut_str(doc, "n"), yyjson_mut_sint(doc, was + 1));

  return true;
}

/** One increment by read, change, check-and-set; many at once must lose none. */
static http_response_t bump(http_request_t *req) {
  return req.reply(baoEdit("selftest/bump", bumpOne, NULL) ? 200 : 409).text("");
}

/** A slow statement, so that several at once show the connection is shared safely. */
static http_response_t dbtest(http_request_t *req) {

  sql_t q = SQL`select pg_sleep(0.2), count(*) from requests`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r == NULL || PQresultStatus(r) != PGRES_TUPLES_OK)
    return req.reply(500).text(database ? database.lastError() : "no database");

  return req.reply(200).text("ok");
}

int main(void) {

  http.env("WX_DB");
  http.env("WX_OPENBAO_URL");
  http.env("WX_OPENBAO_TOKEN_FILE");

  if (atoi(env("WX_WORKERS", "0")) > 0)
    http.workers(atoi(env("WX_WORKERS", "0")));

  http.once(dbPrepare);
  http.eachWorker(startWorker);

  http.get("/health", health);
  http.get("/selftest", selftest);
  http.get("/dbtest", dbtest);
  http.get("/storetest", storetest);
  http.get("/bump", bump);

  http.listen(atoi(env("WX_PORT", "8095")));
}

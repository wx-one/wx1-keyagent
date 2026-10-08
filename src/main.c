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

#include "bao.h"
#include "db.h"

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
  snprintf(where, sizeof where, "%s/v1/sys/health", env("WX_OPENBAO_URL", "http://127.0.0.1:8200"));

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

  http.listen(atoi(env("WX_PORT", "8095")));
}

/**
 * wx-keyagent: the customer's side of confidential VMs.
 *
 * Runs at the customer, never at the provider. Holds nothing itself: the
 * keys and everything a key release depends on live in the customer's
 * OpenBao, history and leases in a database (PostgreSQL or CockroachDB).
 *
 * The key release for the customer's VMs (release.h) on one port, the API
 * through which the provider files requests and the customer decides them
 * (api.h) on another, and a health check.
 */
#include <meta_http.h>

#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int startWorker(void) {

  if (!baoConfigure())
    fprintf(stderr, "wx-keyagent: no OpenBao token\n");
  else if (!baoEnsureStateMount())
    fprintf(stderr, "wx-keyagent: cannot enable the state mount wx/ in OpenBao\n");

  apiConfigure();

  return dbConnect();
}

static http_response_t health(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");

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

int main(void) {

  http.env("WX_DB");
  http.env("WX_OPENBAO_URL");
  http.env("WX_OPENBAO_TOKEN_FILE");
  http.env("WX_CP_TOKEN_FILE");
  http.env("WX_CUSTOMER_TOKEN_FILE");
  http.env("WX_KBS_ADMIN_URL");
  http.env("WX_KBS_ADMIN_TOKEN_FILE");
  http.env("WX_RELEASE_GUEST_URL");
  http.env("WX_REFS");
  http.env("WX_KDS");
  http.env("WX_SNP_PRODUCT");
  http.env("WX_LEASE_TTL");
  http.env("TZ");

  if (atoi(env("WX_WORKERS", "0")) > 0)
    http.workers(atoi(env("WX_WORKERS", "0")));

  http.once(dbPrepare);
  http.eachWorker(startWorker);

  http.get("/health", health);

  apiRoutes();


}

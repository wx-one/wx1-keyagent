/**
 * wx1-keyagent: the customer's side of confidential VMs.
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

#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* what libraries read from the environment themselves, back in each worker */
static const char *const libraryEnvironment[] = {"SSL_CERT_FILE", "SSL_CERT_DIR", "TZ", NULL};

/* Once, in the launcher: what is missing is said here and not by every
   worker. Without OpenBao - its token and the state mount wx/ - the agent
   has nothing to release and nothing to decide on, so it does not start
   (and its supervisor tries again); without a token or the UI password
   only that door stays closed. What is read here is gone with the
   launcher's execv - the workers read it again for themselves. */
static int checkSettings(void) {

  if (!baoConfigure()) {
    fprintf(stderr, "wx1-keyagent: no OpenBao token in %s, nothing to release without it\n",
            env("WX_OPENBAO_TOKEN_FILE", "/secrets/openbao-token"));
    return 1;
  }

  fetch_answer_t health = baoCall("GET", "sys/health", NULL);
  int reached = health.status;
  health.release();

  if (reached == 0) {
    fprintf(stderr, "wx1-keyagent: OpenBao does not answer at %s\n", baoUrl);
    return 1;
  }

  if (!baoEnsureStateMount()) {
    fprintf(stderr, "wx1-keyagent: the state mount wx/ in OpenBao is missing or not ours: "
                    "bao secrets enable -path=wx -version=2 kv, and a token with "
                    "deploy/openbao-policy.hcl\n");
    return 1;
  }

  apiConfigure(true);
  uiConfigure(true);

  return 0;
}

static int startWorker(void) {

  envRestore(libraryEnvironment);
  tzset();

  if (!baoConfigure())
    return 1;

  apiConfigure(false);
  uiConfigure(false);

  return dbConnect();
}

static http_response_t health(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");

  static char body[512];
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

  /* the trust store this worker's OpenSSL reads - the one fetching AMD's
     certificates over HTTPS - as OpenSSL itself sees it */
  const char *trust = getenv("SSL_CERT_FILE");
  bool trustReadable = trust != NULL && access(trust, R_OK) == 0;

  obj answer = {
    database: db,
    openbao: baoStatus,
    trustStore: trustReadable ? trust : "",
  };

  answer.toJSON(body, sizeof body);

  return req.reply(db && baoStatus == 200 ? 200 : 503).json(body);
}

int main(void) {

  /* every setting, kept here in the master; the workers inherit the copy */
  static const char *const settings[] = {
      "WX_DB", "WX_DB_DRIVER", "WX_OPENBAO_URL", "WX_OPENBAO_TOKEN_FILE",
      "WX_CP_TOKEN_FILE", "WX_CUSTOMER_TOKEN_FILE", "WX_UI_PASSWORD_FILE",
      "WX_KBS_ADMIN_URL", "WX_KBS_ADMIN_TOKEN_FILE", "WX_RELEASE_GUEST_URL", "WX_REFS",
      "WX_KDS", "WX_SNP_PRODUCT", "WX_LEASE_TTL", "WX_API_LISTEN", "WX_RELEASE_LISTEN",
      "WX_RELEASE_TLS", "WX_TLS_CERT", "WX_TLS_KEY", "WX_CP_CLIENT_CA",
      "WX_CP_CLIENT_SUBJECT", "WX_WORKERS", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", NULL};

  envKeep(settings);

  if (atoi(env("WX_WORKERS", "0")) > 0)
    http.workers(atoi(env("WX_WORKERS", "0")));

  http.once(checkSettings);
  http.once(dbMigrate);
  http.eachWorker(startWorker);

  http.get("/health", health);

  apiRoutes();
  uiRoutes();


}

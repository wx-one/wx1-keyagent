/**
 * wx1-keyagent: the customer's side of confidential VMs.
 *
 * Runs at the customer, never at the provider. Holds no key itself: the
 * keys live in the customer's key store - OpenBao or an HSM (keys.h) - and
 * never leave it in the clear; the state they are released on, signed by
 * that store, and history and leases in a database (PostgreSQL or
 * CockroachDB).
 *
 * The key release for the customer's VMs (release.h) on one port, the API
 * through which the provider files requests and the customer decides them
 * (api.h) on another, and a health check.
 */
#include <meta_http.h>

#include "legacy.h"
#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* what libraries read from the environment themselves, back in each worker */
static const char *const libraryEnvironment[] = {"SSL_CERT_FILE", "SSL_CERT_DIR", "TZ", NULL};

/* Once, in the launcher: what is missing is said here and not by every
   worker. Without the key store - reachable, its state key there, and
   wrapping exactly as the guests expect (keys.h) - the agent has nothing to
   release and nothing to decide on, so it does not start (and its
   supervisor tries again); without a token or the UI password only that
   door stays closed. What is read here is gone with the launcher's execv -
   the workers read it again for themselves. */
static int checkSettings(void) {

  const char *wrong = keysConfigure(true);

  if (wrong != NULL) {
    fprintf(stderr, "wx1-keyagent: key store %s: %s\n", keysName(), wrong);
    return 1;
  }

  if (keysPkcs11)
    fprintf(stderr, "wx1-keyagent: key store PKCS#11, the token wraps with %s\n", p11WayNames[p11Way]);

  apiConfigure(true);
  uiConfigure(true);

  return 0;
}

static int startWorker(void) {

  envRestore(libraryEnvironment);
  tzset();

  const char *wrong = keysConfigure(false);

  if (wrong != NULL) {
    fprintf(stderr, "wx1-keyagent: key store %s: %s\n", keysName(), wrong);
    return 1;
  }

  /* which way the token wraps, found again here: what the launcher found
     went with its execv */
  if (keysPkcs11 && (wrong = p11SelfTest()) != NULL) {
    fprintf(stderr, "wx1-keyagent: key store PKCS#11: %s\n", wrong);
    return 1;
  }

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

  bool keys;

  if (keysPkcs11) {
    keys = p11Ready();
  } else {
    char where[256];
    text_t at = TEXT`${baoUrl}/v1/sys/health`;
    at.into(where, sizeof where);

    fetch_answer_t bao = meta_get(where);
    keys = bao.status == 200;
    bao.release();
  }

  /* the trust store this worker's OpenSSL reads - the one fetching AMD's
     certificates over HTTPS - as OpenSSL itself sees it */
  const char *trust = getenv("SSL_CERT_FILE");
  bool trustReadable = trust != NULL && access(trust, R_OK) == 0;

  obj answer = {
    database: db,
    keyStore: keysName(),
    keys: keys,
    trustStore: trustReadable ? trust : "",
  };

  answer.toJSON(body, sizeof body);

  return req.reply(db && keys ? 200 : 503).json(body);
}

int main(void) {

  /* every setting, kept here in the master; the workers inherit the copy */
  static const char *const settings[] = {
      "WX_DB", "WX_DB_DRIVER", "WX_KEYSTORE", "WX_OPENBAO_URL", "WX_OPENBAO_TOKEN_FILE",
      "WX_OPENBAO_TRANSIT", "WX_PKCS11_MODULE", "WX_PKCS11_TOKEN", "WX_PKCS11_PIN_FILE",
      "WX_PKCS11_OAEP", "WX_PKCS11_ENV", "WX_IMPORT_OPENBAO_KV",
      "WX_CP_TOKEN_FILE", "WX_CUSTOMER_TOKEN_FILE", "WX_UI_PASSWORD_FILE",
      "WX_KBS_ADMIN_URL", "WX_KBS_ADMIN_TOKEN_FILE", "WX_RELEASE_GUEST_URL", "WX_REFS",
      "WX_KDS", "WX_SNP_PRODUCT", "WX_LEASE_TTL", "WX_API_LISTEN", "WX_RELEASE_LISTEN",
      "WX_RELEASE_TLS", "WX_TLS_CERT", "WX_TLS_KEY", "WX_CP_CLIENT_CA",
      "WX_CP_CLIENT_SUBJECT", "WX_WORKERS", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", NULL};

  envKeep(settings);
  envKeepListed("WX_PKCS11_ENV");

  if (atoi(env("WX_WORKERS", "0")) > 0)
    http.workers(atoi(env("WX_WORKERS", "0")));

  http.once(checkSettings);
  http.once(dbMigrate);
  http.once(legacyImport);
  http.eachWorker(startWorker);

  http.get("/health", health);

  apiRoutes();
  uiRoutes();


}

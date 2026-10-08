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
#include <meta_pg.h>
#include <meta_fetch.h>

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PGconn *database;

static const char *env(const char *name, const char *otherwise) {

  const char *v = getenv(name);

  return v != NULL && v[0] != 0 ? v : otherwise;
}

static int connectToThings(void) {

  database = meta_pgOpen(env("WX_DB", "postgresql://root@127.0.0.1:26257/keyagent?sslmode=disable"));

  if (database == NULL)
    fprintf(stderr, "wx-keyagent: this worker cannot reach the database\n");

  return 0;
}

/** sha256 of a short text, hex, as the smallest proof OpenSSL is linked. */
static void sha256Hex(const char *text, char out[65]) {

  unsigned char digest[32];
  unsigned int length = 0;

  EVP_Digest(text, strlen(text), digest, &length, EVP_sha256(), NULL);

  for (unsigned int i = 0; i < length; ++i)
    snprintf(out + i * 2, 3, "%02x", digest[i]);
}

static http_response_t health(http_request_t *req) {

  static char body[512];
  char hash[65];
  bool db = false;

  if (database != NULL) {
    PGresult *r = database.query("select 1");
    db = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK;
  }

  char where[256];
  snprintf(where, sizeof where, "%s/v1/sys/health", env("WX_OPENBAO_URL", "http://127.0.0.1:8200"));

  fetch_answer_t bao = meta_get(where);
  int baoStatus = bao.status;
  bao.release();

  sha256Hex("wx-keyagent", hash);

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

  http.eachWorker(connectToThings);

  http.get("/health", health);

  http.listen(atoi(env("WX_PORT", "8095")));
}

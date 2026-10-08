/**
 * The HTTP API.
 *
 * Two callers with two tokens. The provider's control plane may file
 * requests and ask how they went - nothing else. The customer decides them,
 * resets leases and unbinds a vTPM. A control plane token never decides.
 */
#ifndef WX_API_H
#define WX_API_H

#include <meta_http.h>
#include <openssl/crypto.h>

#include "requests.h"

static char cpToken[256];
static char customerToken[256];

static void apiConfigure(void) {

  if (!readSecret(env("WX_CP_TOKEN_FILE", "/secrets/cp-token"), cpToken, sizeof cpToken))
    fprintf(stderr, "wx-keyagent: no control plane token, its API is closed\n");

  if (!readSecret(env("WX_CUSTOMER_TOKEN_FILE", "/secrets/customer-token"), customerToken,
                  sizeof customerToken))
    fprintf(stderr, "wx-keyagent: no customer token, the customer API is closed\n");
}

/** "Bearer <token>", compared in constant time. An empty token opens nothing. */
static bool bearer(http_request_t *req, const char *token) {

  const char *got = req.header("authorization");
  size_t length = strlen(token);

  if (length == 0 || got == NULL || strncmp(got, "Bearer ", 7) != 0)
    return false;

  got += 7;

  return strlen(got) == length && CRYPTO_memcmp(got, token, length) == 0;
}

/**
 * The answer, copied into a buffer that outlives the handler. Filled right
 * before the handler returns, with no wait in between, so tasks of the same
 * worker cannot overwrite each other's.
 */
static http_response_t answer(http_request_t *req, int code, const char *json) {

  static buf_t out;

  buf_t__reset(&out);
  buf_t__put(&out, json);

  return req.reply(code).json(out.broke ? "{\"error\":\"no memory\"}" : out.at);
}

static http_response_t refused(http_request_t *req, int code, const char *why) {

  char text[300];
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(doc);

  yyjson_mut_doc_set_root(doc, o);
  yyjson_mut_obj_add_str(doc, o, "error", why);

  char *json = yyjson_mut_write(doc, 0, NULL);
  text_t t = TEXT`${json ?: "{}"}`;
  t.into(text, sizeof text);

  free(json);
  yyjson_mut_doc_free(doc);

  return answer(req, code, text);
}

static const char *const requestTypes[] = {"create", "attach", "add_host",
                                           "detach", "delete_disk"};

/** POST /api/requests {type, payload}: the control plane files a request. */
static http_response_t apiSubmit(http_request_t *req) {

  if (!bearer(req, cpToken))
    return refused(req, 401, "unauthorized");

  json_t body = req.readJson();
  const char *type = body.get("type").text();
  json_t payload = body.get("payload");
  bool known = false;

  for (size_t i = 0; type != NULL && i < sizeof requestTypes / sizeof requestTypes[0]; ++i)
    known = known || strcmp(type, requestTypes[i]) == 0;

  /* unlock requests come from the key release, never from the provider */
  if (!known || strcmp(payload.kind(), "object") != 0) {
    body.release();
    return refused(req, 400, "bad request");
  }

  long id = submit(type, payload);
  body.release();

  buf_t state = {0};

  if (id < 0 || !requestState(id, &state)) {
    free(state.at);
    return refused(req, 503, "cannot store the request");
  }

  http_response_t done = answer(req, 200, state.at);
  free(state.at);

  return done;
}

/** GET /api/requests/:id: how it went. */
static http_response_t apiState(http_request_t *req) {

  if (!bearer(req, cpToken) && !bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  buf_t state = {0};
  long id = atol(req.param("id"));

  if (id <= 0 || !requestState(id, &state)) {
    free(state.at);
    return refused(req, 404, "no such request");
  }

  http_response_t done = answer(req, 200, state.at);
  free(state.at);

  return done;
}

/** POST /api/customer/requests/:id {"approve": true|false} */
static http_response_t apiDecide(http_request_t *req) {

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  json_t body = req.readJson();
  bool approve = body.get("approve").truth();
  long id = atol(req.param("id"));
  body.release();

  decide(id, approve, "customer (API)");

  buf_t state = {0};

  if (!requestState(id, &state)) {
    free(state.at);
    return refused(req, 404, "no such request");
  }

  http_response_t done = answer(req, 200, state.at);
  free(state.at);

  return done;
}

/** POST /api/customer/disks/:id/lease/reset: the instance is gone, don't wait. */
static http_response_t apiResetLease(http_request_t *req) {

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  if (!storeResetLease(req.param("id")))
    return refused(req, 503, "cannot reset the lease");

  return answer(req, 200, "{\"reset\":true}");
}

/** POST /api/customer/vtpm/:hd/unbind: the customer accepts a new vTPM. */
static http_response_t apiUnbind(http_request_t *req) {

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  if (!isHex(req.param("hd"), 64))
    return refused(req, 400, "bad HOST_DATA");

  if (!storeUnbindEk(req.param("hd")) || !storeDrop("replay", req.param("hd")))
    return refused(req, 503, "cannot unbind");

  return answer(req, 200, "{\"unbound\":true}");
}

static void apiRoutes(void) {
  http.post("/api/requests", apiSubmit);
  http.get("/api/requests/:id", apiState);
  http.post("/api/customer/requests/:id", apiDecide);
  http.post("/api/customer/disks/:id/lease/reset", apiResetLease);
  http.post("/api/customer/vtpm/:hd/unbind", apiUnbind);
}

#endif /* WX_API_H */

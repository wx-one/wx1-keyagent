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

#include "release.h"

static char cpToken[256];
static char customerToken[256];

/**
 * With WX_CP_CLIENT_CA the control plane has to show a client certificate
 * from that CA as well as its token - optionally with this exact subject
 * (WX_CP_CLIENT_SUBJECT, e.g. "/CN=cp.example"). The customer's routes and
 * the UI need none: a browser has no certificate.
 */
static const char *cpClientCa;
static const char *cpClientSubject;

/**
 * The API and the key release listen on ports of their own, and every
 * route checks which one a request came in on: VMs reach the release, and
 * nothing else of this agent.
 */
static int apiPort;
static int releasePort;

static void apiConfigure(bool say) {

  cpClientCa = env("WX_CP_CLIENT_CA", NULL);
  cpClientSubject = env("WX_CP_CLIENT_SUBJECT", NULL);

  if (!readSecret(env("WX_CP_TOKEN_FILE", "/secrets/cp-token"), cpToken, sizeof cpToken) && say)
    fprintf(stderr, "wx1-keyagent: no control plane token, its API is closed\n");

  if (!readSecret(env("WX_CUSTOMER_TOKEN_FILE", "/secrets/customer-token"), customerToken,
                  sizeof customerToken) &&
      say)
    fprintf(stderr, "wx1-keyagent: no customer token, the customer API is closed\n");
}

static bool bearer(http_request_t *req, const char *token);

/** The control plane: its token, and its certificate when one is required. */
static bool fromControlPlane(http_request_t *req) {

  if (!bearer(req, cpToken))
    return false;

  if (cpClientCa == NULL || cpClientCa[0] == 0)
    return true;

  return req->clientVerified &&
         (cpClientSubject == NULL || cpClientSubject[0] == 0 ||
          strcmp(req->clientSubject, cpClientSubject) == 0);
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

static const char *const requestTypes[] = {"create", "create_volume", "attach", "add_host",
                                           "detach", "reprovision", "delete_disk"};

/** POST /api/requests {type, payload}: the control plane files a request. */
static http_response_t apiSubmit(http_request_t *req) {

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

  if (!fromControlPlane(req))
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

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

  if (!fromControlPlane(req) && !bearer(req, customerToken))
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

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

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

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  if (!isDiskId(req.param("id")))
    return refused(req, 400, "bad disk ID");

  if (!storeResetLease(req.param("id")))
    return refused(req, 503, "cannot reset the lease");

  return answer(req, 200, "{\"reset\":true}");
}

/** POST /api/customer/vtpm/:hd/unbind: the customer accepts a new vTPM. */
static http_response_t apiUnbind(http_request_t *req) {

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  if (!isHex(req.param("hd"), 64))
    return refused(req, 400, "bad HOST_DATA");

  if (!storeUnbindEk(req.param("hd")) || !storeDrop("replay", req.param("hd")))
    return refused(req, 503, "cannot unbind");

  return answer(req, 200, "{\"unbound\":true}");
}

typedef struct {
  const char *value[3];
  const char *label;
} pcr_ref_t;

static bool addPcrRef(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  static const char *const keys[] = {"4", "8", "9"};
  pcr_ref_t *ref = (pcr_ref_t *)with;
  yyjson_mut_val *refs = yyjson_mut_obj_get(root, "pcr_refs");

  if (refs == NULL) {
    refs = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, root, "pcr_refs", refs);
  }

  if (!yyjson_mut_is_arr(refs))
    return false;

  /* the same set once is enough */
  yyjson_mut_val *have;
  yyjson_mut_arr_iter it;
  yyjson_mut_arr_iter_init(refs, &it);

  while ((have = yyjson_mut_arr_iter_next(&it)) != NULL) {
    int same = 0;
    for (int k = 0; k < 3; ++k)
      same += yyjson_mut_equals_str(yyjson_mut_obj_get(have, keys[k]), ref->value[k]);
    if (same == 3)
      return false;
  }

  yyjson_mut_val *add = yyjson_mut_obj(doc);
  for (int k = 0; k < 3; ++k)
    yyjson_mut_obj_add_strcpy(doc, add, keys[k], ref->value[k]);
  yyjson_mut_obj_add_strcpy(doc, add, "label", ref->label);

  return yyjson_mut_arr_append(refs, add);
}

/** POST /api/customer/pcr-refs {"4": hex, "8": hex, "9": hex, "label": text} */
static http_response_t apiPcrRef(http_request_t *req) {

  if (req->localPort != apiPort)
    return refused(req, 404, "not found");

  if (!bearer(req, customerToken))
    return refused(req, 401, "unauthorized");

  json_t body = req.readJson();
  pcr_ref_t ref = {{body.get("4").text(), body.get("8").text(), body.get("9").text()},
                   body.get("label").text()};

  if (ref.label[0] == 0)
    ref.label = "taken over by the customer (API)";
  bool valid = isHex(ref.value[0], 64) && isHex(ref.value[1], 64) && isHex(ref.value[2], 64);

  /* a failed edit here mostly means "already there" */
  if (valid)
    baoEdit("settings", addPcrRef, &ref);

  body.release();

  return valid ? answer(req, 200, "{\"taken\":true}") : refused(req, 400, "want PCR 4, 8, 9 as hex");
}

/* -------------------------------------------------------- the key release */

typedef void (*release_step_t)(release_t *out, json_t req);

static http_response_t releaseCall(http_request_t *req, const char *step, release_step_t run,
                                   bool logSuccess) {

  if (req->localPort != releasePort)
    return refused(req, 404, "not found");

  release_t out = {0};
  json_t body = req.readJson();

  out.code = 200;
  buf_t__put(&out.json, "");

  if (strcmp(body.kind(), "object") != 0)
    out.refuse(400, "request is not a JSON object");
  else
    run(&out, body);

  body.release();

  if (out.wrong == NULL && out.json.broke)
    out.refuse(500, "no memory");

  if (out.wrong != NULL || logSuccess) {
    const char *detail = out.wrong;

    if (detail == NULL)
      detail = strstr(out.json.at, "\"key\"") != NULL     ? "key delivered"
               : strstr(out.json.at, "\"ended\"") != NULL ? "lease given back"
                                                           : "lease renewed";

    storeLog(out.disk, step, out.wrong == NULL, detail, out.ctx[0] ? out.ctx : NULL, "");
  }

  http_response_t done = out.wrong != NULL ? refused(req, out.code, out.wrong)
                                           : answer(req, 200, out.json.at);
  free(out.json.at);

  return done;
}

static http_response_t releaseChallenge(http_request_t *req) {
  return releaseCall(req, "challenge", challenge, false);
}

static http_response_t releaseAttest(http_request_t *req) {
  return releaseCall(req, "attest", attest, false);
}

static http_response_t releaseRelease(http_request_t *req) {
  return releaseCall(req, "release", releaseKey, true);
}

/** "addr:port,addr:port"; every entry must name the same port. */
static int listenAll(const char *list, bool tls) {

  char copy[512];
  int port = 0;

  text_t t = TEXT`${list}`;
  t.into(copy, sizeof copy);

  for (char *entry = strtok(copy, ","); entry != NULL; entry = strtok(NULL, ",")) {

    char *colon = strrchr(entry, ':');
    int p = colon != NULL ? atoi(colon + 1) : 0;

    if (p <= 0 || (port != 0 && p != port))
      return -1;

    *colon = 0;
    port = p;

    /* listenOn holds the address rather than copying it */
    if (tls)
      http.listenTls(strdup(entry), p);
    else
      http.listenOn(strdup(entry), p);
  }

  return port;
}

static void apiRoutes(void) {

  /**
   * TLS for the API when there is a certificate: the control plane reaches
   * it over a network the customer does not fully own (a VPN at best). The
   * release stays as configured (WX_RELEASE_TLS=1 for TLS): what it hands
   * out is sealed to an attested guest end to end, and TLS there means a CA
   * the guest image has to pin.
   */
  const char *cert = env("WX_TLS_CERT", NULL), *key = env("WX_TLS_KEY", NULL);
  bool tls = cert != NULL && cert[0] != 0 && key != NULL && key[0] != 0;

  if (tls) {
    http.tls(cert, key);
    if (env("WX_CP_CLIENT_CA", NULL) != NULL)
      http.tlsClients(env("WX_CP_CLIENT_CA", NULL));
  }

  apiPort = listenAll(env("WX_API_LISTEN", "127.0.0.1:8095"), tls);
  releasePort = listenAll(env("WX_RELEASE_LISTEN", "127.0.0.1:8091"),
                          tls && strcmp(env("WX_RELEASE_TLS", "0"), "1") == 0);

  if (apiPort <= 0 || releasePort <= 0 || apiPort == releasePort) {
    fprintf(stderr, "wx1-keyagent: WX_API_LISTEN and WX_RELEASE_LISTEN need one port each, "
                    "and not the same\n");
    exit(1);
  }

  http.post("/v1/challenge", releaseChallenge);
  http.post("/v1/attest", releaseAttest);
  http.post("/v1/release", releaseRelease);

  http.post("/api/requests", apiSubmit);
  http.get("/api/requests/:id", apiState);
  http.post("/api/customer/requests/:id", apiDecide);
  http.post("/api/customer/disks/:id/lease/reset", apiResetLease);
  http.post("/api/customer/vtpm/:hd/unbind", apiUnbind);
  http.post("/api/customer/pcr-refs", apiPcrRef);
}

#endif /* WX_API_H */

/**
 * The customer's web UI: requests, disks, rules and hosts.
 *
 * On the API port, behind Basic auth ("kunde" and the password in
 * WX_UI_PASSWORD_FILE). Every form carries a CSRF token derived from that
 * password, so all workers agree on it without sharing anything.
 */
#ifndef WX_UI_H
#define WX_UI_H

#include "api.h"

#include <ctype.h>
#include <openssl/hmac.h>

static char uiPassword[256];
static char uiExpect[512]; /* "Basic base64(kunde:password)" */
static char uiCsrf[65];

static void uiConfigure(void) {

  if (!readSecret(env("WX_UI_PASSWORD_FILE", "/secrets/ui-password"), uiPassword,
                  sizeof uiPassword)) {
    fprintf(stderr, "wx-keyagent: no UI password, the UI is closed\n");
    return;
  }

  char plain[300], encoded[420];
  text_t t = TEXT`kunde:${uiPassword}`;
  t.into(plain, sizeof plain);
  toBase64((const unsigned char *)plain, strlen(plain), encoded);
  text_t e = TEXT`Basic ${encoded}`;
  e.into(uiExpect, sizeof uiExpect);

  unsigned char mac[32];
  unsigned int length = 0;
  HMAC(EVP_sha256(), uiPassword, (int)strlen(uiPassword), (const unsigned char *)"wx-ui-csrf", 10,
       mac, &length);
  toHex(mac, 32, uiCsrf);
}

static bool uiAuthorized(http_request_t *req) {

  const char *got = req.header("authorization");
  size_t length = strlen(uiExpect);

  return uiPassword[0] != 0 && got != NULL && strlen(got) == length &&
         CRYPTO_memcmp(got, uiExpect, length) == 0;
}

static http_response_t uiLogin(http_request_t *req) {
  return req.reply(401)
      .header("www-authenticate", "Basic realm=\"wx-keyagent\"")
      .text("Anmeldung noetig");
}

/* ----------------------------------------------------------------- forms */

#define FORM_FIELDS 16

typedef struct {
  char *name[FORM_FIELDS];
  char *value[FORM_FIELDS];
  int count;
  char *data;
} form_t;

static int hexDigit(char c) {
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/** Decodes in place: '+' is a space, %XX a byte. */
static void urlDecode(char *s) {

  char *out = s;

  for (; *s != 0; ++s) {
    if (*s == '+') {
      *out++ = ' ';
    } else if (*s == '%' && hexDigit(s[1]) >= 0 && hexDigit(s[2]) >= 0) {
      *out++ = (char)(hexDigit(s[1]) << 4 | hexDigit(s[2]));
      s += 2;
    } else {
      *out++ = *s;
    }
  }

  *out = 0;
}

/** An application/x-www-form-urlencoded body. Free with form.release(). */
static form_t formRead(http_request_t *req) {

  form_t form = {0};
  http_body_t body = req.readBody();

  if (body.refused != NULL || body.length > 256 * 1024)
    return form;

  form.data = (char *)malloc(body.length + 1);

  if (form.data == NULL)
    return form;

  memcpy(form.data, body.bytes, body.length);
  form.data[body.length] = 0;

  for (char *pair = strtok(form.data, "&"); pair != NULL && form.count < FORM_FIELDS;
       pair = strtok(NULL, "&")) {
    char *eq = strchr(pair, '=');
    if (eq != NULL)
      *eq = 0;
    urlDecode(pair);
    form.name[form.count] = pair;
    form.value[form.count] = eq != NULL ? eq + 1 : pair + strlen(pair);
    urlDecode(form.value[form.count]);
    ++form.count;
  }

  return form;
}

static const char *form_t__get(form_t *self, const char *name) {

  for (int i = 0; i < self->count; ++i)
    if (strcmp(self->name[i], name) == 0)
      return self->value[i];

  return "";
}

static void form_t__release(form_t *self) {
  free(self->data);
}

/** A POST from our own page: logged in and with the token. */
static bool formGenuine(form_t *form) {

  const char *got = form.get("csrf");

  return uiCsrf[0] != 0 && strlen(got) == 64 && CRYPTO_memcmp(got, uiCsrf, 64) == 0;
}

static http_response_t uiBack(http_request_t *req, const char *to) {
  return req.reply(303).header("location", to).text("");
}

/* ------------------------------------------------------------------ pages */

static const char uiCss[] =
  ":root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--line:#e3e6eb;--acc:#2456d6;"
  "--ok:#16794c;--bad:#b42318;--warn:#a15c07}"
  "@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--mut:#98a2b3;"
  "--line:#2c323b;--acc:#7aa2ff;--ok:#4fc38a;--bad:#ff8077;--warn:#f0b35a}}"
  "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);"
  "font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}"
  "header{background:var(--card);border-bottom:1px solid var(--line);padding:12px 24px;display:flex;"
  "gap:24px;align-items:center;flex-wrap:wrap}"
  "header b{font-size:16px}nav a{color:var(--mut);text-decoration:none;margin-right:16px}"
  "nav a.on{color:var(--fg);font-weight:600}"
  "main{max-width:1000px;margin:24px auto;padding:0 16px}"
  ".card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;"
  "margin-bottom:14px;overflow-x:auto}"
  "h1{font-size:20px;margin:0 0 14px}h2{font-size:16px;margin:0 0 8px}"
  ".mut{color:var(--mut)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}"
  "code,pre{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}pre{background:var(--bg);"
  "padding:10px;border-radius:6px;overflow:auto;max-height:260px;margin:6px 0}"
  "table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;"
  "border-top:1px solid var(--line);vertical-align:top}"
  "th{color:var(--mut);font-weight:500;border-top:0}"
  ".kv{display:grid;grid-template-columns:160px 1fr;gap:4px 12px;margin:8px 0}"
  ".btn{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:7px 14px;"
  "border-radius:7px;cursor:pointer;font:inherit}"
  ".btn.pri{background:var(--acc);border-color:var(--acc);color:#fff}.btn.dan{color:var(--bad)}"
  ".pill{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;"
  "border:1px solid var(--line)}"
  "input[type=text],input[type=number],textarea,select{font:13px ui-monospace,monospace;padding:6px;"
  "border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}"
  "textarea{width:100%}"
  "details summary{cursor:pointer;color:var(--mut)}"
  "@media (max-width:640px){.kv{grid-template-columns:1fr}}";

static void pageStart(buf_t *out, const char *title, const char *active) {

  static const char *const links[][2] = {
      {"/", "Anfragen"}, {"/disks", "Disks"}, {"/settings", "Regeln & Hosts"}};

  buf_t__put(out, "<!doctype html><html lang=de><head><meta charset=utf-8>"
                  "<meta name=viewport content='width=device-width,initial-scale=1'><title>");
  buf_t__html(out, title);
  buf_t__put(out, " – wx-keyagent</title><style>");
  buf_t__put(out, uiCss);
  buf_t__put(out, "</style></head><body><header><b>wx-keyagent</b><nav>");

  for (int i = 0; i < 3; ++i)
    buf_t__printf(out, "<a href='%s' class='%s'>%s</a>", links[i][0],
                  strcmp(links[i][0], active) == 0 ? "on" : "", links[i][1]);

  buf_t__put(out, "</nav></header><main>");
}

/** Ends the page and answers with it. */
static http_response_t pageEnd(http_request_t *req, buf_t *out) {

  buf_t__put(out, "</main></body></html>");

  static buf_t page;
  buf_t__reset(&page);
  buf_t__add(&page, out->at ?: "", out->length);
  free(out->at);

  return req.reply(200).mime("text/html; charset=utf-8").text(page.broke ? "" : page.at);
}

static void csrfField(buf_t *out) {
  buf_t__printf(out, "<input type=hidden name=csrf value='%s'>", uiCsrf);
}

/** "08.10. 14:03:22" in the agent's local time. */
static void when(buf_t *out, long epoch, const char *format) {

  char text[40];
  struct tm t;
  time_t at = (time_t)epoch;

  localtime_r(&at, &t);
  strftime(text, sizeof text, format, &t);
  buf_t__put(out, text);
}

/** A host by its chip_id, named from the pool if it is there. */
static void chipLabel(buf_t *out, settings_t *settings, const char *chip, const char *hv) {

  json_t pool = settings->data.get("host_pool");

  for (int i = 0; settings->entry.found && i < pool.count(); ++i) {
    json_t h = pool.at(i);

    if (strcmp(h.get("chip_id").text(), chip) == 0) {
      buf_t__put(out, "<b><code>");
      buf_t__html(out, h.get("hv_uuid").text());
      buf_t__put(out, "</code></b>");
      if (h.get("name").text()[0] != 0) {
        buf_t__put(out, " (");
        buf_t__html(out, h.get("name").text());
        buf_t__put(out, ")");
      }
      char prefix[17];
      text_t t = TEXT`${chip}`;
      t.into(prefix, sizeof prefix);
      buf_t__put(out, " <code class=mut>chip ");
      buf_t__html(out, prefix);
      buf_t__put(out, "…</code>");
      return;
    }
  }

  buf_t__put(out, "<span class=warn>Host nicht im Pool</span> ");

  if (hv != NULL && hv[0] != 0) {
    buf_t__put(out, "<code>");
    buf_t__html(out, hv);
    buf_t__put(out, "</code> ");
  }

  /* the provider wrote this one: escaped like everything from a request */
  char prefix[17];
  text_t t = TEXT`${chip}`;
  t.into(prefix, sizeof prefix);
  buf_t__put(out, "<code class=mut>chip ");
  buf_t__html(out, prefix);
  buf_t__put(out, "…</code>");
}

/* --------------------------------------------------------------- requests */

static const char *typeLabel(const char *type) {

  static const char *const labels[][2] = {
      {"create", "Neue Disk fuer neue VM"},
      {"attach", "Bestehende Disk an neue VM haengen"},
      {"add_host", "VM auf weiterem Host erlauben (Umzug)"},
      {"detach", "VM geloescht, Disk bleibt"},
      {"delete_disk", "Disk endgueltig loeschen"},
      {"unlock", "Neue VM-Instanz will die Disk entsperren"}};

  for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
    if (strcmp(labels[i][0], type) == 0)
      return labels[i][1];

  return type;
}

static void statusPill(buf_t *out, const char *status, bool remarks) {

  static const char *const labels[][3] = {
      {"pending", "wartet auf Freigabe", "warn"}, {"deciding", "wird umgesetzt", "warn"},
      {"applied", "umgesetzt", "ok"},             {"denied", "abgelehnt", "bad"},
      {"rejected", "automatisch abgewiesen", "bad"}, {"error", "Fehler", "bad"}};

  const char *label = status, *cls = "";

  for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
    if (strcmp(labels[i][0], status) == 0) {
      label = labels[i][1];
      cls = labels[i][2];
    }

  /* applied with remarks: done, but worth a look */
  if (strcmp(status, "applied") == 0 && remarks) {
    label = "umgesetzt – bitte pruefen";
    cls = "warn";
  }

  buf_t__printf(out, "<span class='pill %s'>%s</span>", cls, label);
}

static void kvRow(buf_t *out, const char *key) {
  buf_t__printf(out, "<span class=mut>%s</span><span>", key);
}

/** The SSH keys in a cloud-config, each marked known or not. */
static void sshKeys(buf_t *out, const char *userData, settings_t *settings) {

  const char *allowed[64];
  int count = settings.keys(allowed, 64);
  bool any = false;

  for (const char *at = userData; (at = strstr(at, "ssh-")) != NULL || false;) {

    const char *end = at;
    while (*end != 0 && *end != '\n' && *end != '\r' && *end != '"' && *end != '\'')
      ++end;

    char line[2048], have[2048];
    size_t n = (size_t)(end - at) < sizeof line - 1 ? (size_t)(end - at) : sizeof line - 1;
    memcpy(line, at, n);
    line[n] = 0;
    keyName(line, have, sizeof have);
    at = end;

    if (strchr(have, ' ') == NULL)
      continue;

    bool known = false;
    for (int a = 0; a < count && !known; ++a) {
      char want[2048];
      keyName(allowed[a], want, sizeof want);
      known = strcmp(want, have) == 0;
    }

    if (!any)
      kvRow(out, "SSH-Keys");
    else
      buf_t__put(out, "<br>");

    char shown[44];
    text_t t = TEXT`${have}`;
    t.into(shown, sizeof shown);
    buf_t__put(out, "<code>");
    buf_t__html(out, shown);
    buf_t__put(out, "…</code> ");
    buf_t__put(out, known ? "<span class=ok>bekannt</span>" : "<span class=warn>nicht in der Liste</span>");
    any = true;
  }

  if (any)
    buf_t__put(out, "</span>");
}

static void fileDetails(buf_t *out, const char *name, json_t content) {

  blob_t f = blobOf(content);

  buf_t__put(out, "<details><summary>");
  buf_t__html(out, name);
  buf_t__put(out, "</summary><pre>");
  buf_t__html(out, f.at ?: "");
  buf_t__put(out, "</pre></details>");

  free(f.at);
}

/** One request as a card; with `actions` the buttons to decide it. */
static void requestCard(buf_t *out, PGresult *r, int row, settings_t *settings, bool actions) {

  long id = atol(PQgetvalue(r, row, 0));
  long created = atol(PQgetvalue(r, row, 1));
  const char *type = PQgetvalue(r, row, 2);
  json_t p = meta_toJSON(PQgetvalue(r, row, 3));
  const char *status = PQgetvalue(r, row, 4);
  const char *reason = PQgetvalue(r, row, 5);
  json_t checks = meta_toJSON(PQgetvalue(r, row, 6));
  const char *by = PQgetvalue(r, row, 7);
  bool remarks = false;

  for (int i = 0; i < checks.count(); ++i)
    remarks = remarks || strcmp(checks.at(i).at(0).kind(), "null") == 0;

  buf_t__printf(out, "<div class=card><h2>#%ld %s ", id, typeLabel(type));
  statusPill(out, status, remarks);
  buf_t__put(out, "</h2><div class=mut>");
  when(out, created, "%d.%m. %H:%M:%S");
  if (by[0] != 0) {
    buf_t__put(out, " · ");
    buf_t__html(out, by);
  }
  buf_t__put(out, "</div><div class=kv>");

  kvRow(out, "VM");
  buf_t__html(out, p.get("vm_name").text());
  buf_t__put(out, " <code class=mut>");
  buf_t__html(out, p.get("vm_uuid").text());
  buf_t__put(out, "</code></span>");

  kvRow(out, "Disk");
  buf_t__put(out, "<code>");
  buf_t__html(out, p.get("disk_id").text());
  buf_t__put(out, "</code></span>");

  if (p.get("chip_id").text()[0] != 0) {
    kvRow(out, "Host");
    chipLabel(out, settings, p.get("chip_id").text(), p.get("hv_uuid").text());
    buf_t__put(out, "</span>");
  }

  if (p.get("report_id").text()[0] != 0) {
    char rid[17];
    text_t t = TEXT`${p.get("report_id").text()}`;
    t.into(rid, sizeof rid);
    kvRow(out, "Instanz");
    buf_t__put(out, "<code>");
    buf_t__html(out, rid);
    buf_t__put(out, "…</code> (SNP REPORT_ID)</span>");
  }

  blob_t userData = blobOf(p.get("files").get("user-data"));
  if (userData.length > 0)
    sshKeys(out, userData.at, settings);
  buf_t__put(out, "</div>");

  for (int i = 0; i < checks.count(); ++i) {
    json_t c = checks.at(i);
    const char *kind = c.at(0).kind();
    bool good = c.at(0).truth();
    const char *cls = strcmp(kind, "null") == 0 ? "warn" : good ? "ok" : "bad";
    const char *mark = strcmp(kind, "null") == 0 ? "⚠" : good ? "✓" : "✗";
    buf_t__printf(out, "<div class=%s>%s ", cls, mark);
    buf_t__html(out, c.at(1).text());
    buf_t__put(out, "</div>");
  }

  if (reason[0] != 0) {
    buf_t__put(out, "<div class=bad>");
    buf_t__html(out, reason);
    buf_t__put(out, "</div>");
  }

  blob_t initdata = blobOf(p.get("initdata"));
  if (initdata.length > 0) {
    char hd[65];
    sha256Hex(initdata.at, (size_t)initdata.length, hd);
    buf_t__printf(out, "<details><summary>initdata (HOST_DATA %.16s…)</summary><pre>", hd);
    buf_t__html(out, initdata.at);
    buf_t__put(out, "</pre></details>");
  }
  free(initdata.at);

  json_t files = p.get("files");
  for (int i = 0; i < files.count(); ++i)
    fileDetails(out, files.keyAt(i), files.at(i));
  free(userData.at);

  if (actions && strcmp(status, "pending") == 0) {
    buf_t__put(out, "<form method=post action='/decide' style='display:flex;gap:8px;margin-top:10px'>");
    csrfField(out);
    buf_t__printf(out, "<input type=hidden name=id value='%ld'>"
                       "<button class='btn pri' name=decision value=approve>Freigeben</button>"
                       "<button class='btn dan' name=decision value=deny>Ablehnen</button></form>", id);
  }

  /* a worker that died while deciding leaves it here; give it back */
  if (actions && strcmp(status, "deciding") == 0) {
    buf_t__put(out, "<form method=post action='/undecided' style='margin-top:10px'>");
    csrfField(out);
    buf_t__printf(out, "<input type=hidden name=id value='%ld'><span class=mut>Haengt seit einer "
                       "Weile? </span><button class=btn>Erneut zur Freigabe stellen</button></form>", id);
  }

  buf_t__put(out, "</div>");

  p.release();
  checks.release();
}

static PGresult *requestRows(const char *which) {

  sql_t q = strcmp(which, "open") == 0
                ? SQL`select id, extract(epoch from created)::INT8, type, payload::TEXT, status, reason,
                        checks::TEXT, decided_by from requests
                      where status in ('pending', 'deciding') order by id`
                : SQL`select id, extract(epoch from created)::INT8, type, payload::TEXT, status, reason,
                        checks::TEXT, decided_by from requests
                      where status not in ('pending', 'deciding') order by id desc limit 20`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r != NULL && PQresultStatus(r) != PGRES_TUPLES_OK) {
    PQclear(r);
    return NULL;
  }

  return r;
}

static http_response_t uiRequests(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  settings_t settings = settingsRead();
  PGresult *open = requestRows("open"), *done = requestRows("done");

  pageStart(&out, "Anfragen", "/");
  buf_t__put(&out, "<h1>Offene Anfragen des Providers</h1>");

  if (open == NULL || done == NULL)
    buf_t__put(&out, "<div class='card bad'>Datenbank nicht erreichbar.</div>");

  for (int i = 0; open != NULL && i < PQntuples(open); ++i)
    requestCard(&out, open, i, &settings, true);

  if (open != NULL && PQntuples(open) == 0)
    buf_t__put(&out, "<div class='card mut'>Keine offenen Anfragen.</div>");

  buf_t__put(&out, "<h1 style='margin-top:28px'>Verlauf</h1>");

  for (int i = 0; done != NULL && i < PQntuples(done); ++i)
    requestCard(&out, done, i, &settings, false);

  if (open != NULL)
    PQclear(open);
  if (done != NULL)
    PQclear(done);
  settings.release();

  return pageEnd(req, &out);
}

/* ------------------------------------------------------------------ disks */

static const char *const modes[][2] = {
    {"always", "immer"}, {"window", "nur im Zeitfenster"}, {"confirm", "nur nach Bestaetigung"}};

static void diskRow(buf_t *out, const char *id, settings_t *settings) {

  bao_entry_t disk = storeGet("disks", id);
  bao_entry_t att = storeGet("attachments", id);
  json_t d = disk.payload(), a = att.payload();
  const char *status = disk.found ? d.get("status").text() : "?";
  const char *mode = d.get("mode").text();

  if (mode[0] == 0)
    mode = "always";

  buf_t__put(out, "<tr><td><code>");
  buf_t__html(out, id);
  buf_t__put(out, "</code><div class=mut>seit ");
  when(out, d.get("created").number(), "%d.%m.%Y");
  buf_t__put(out, "</div></td><td>");
  buf_t__put(out, strcmp(status, "active") == 0    ? "<span class=ok>aktiv</span>"
                  : strcmp(status, "deleted") == 0 ? "<span class=bad>geloescht</span>"
                                                   : "<span class=warn>");
  if (strcmp(status, "active") != 0 && strcmp(status, "deleted") != 0) {
    buf_t__html(out, status);
    buf_t__put(out, "</span>");
  }
  buf_t__put(out, "</td><td>");

  if (att.found) {
    buf_t__html(out, a.get("vm_name").text());
    buf_t__put(out, " <code class=mut>");
    buf_t__html(out, a.get("vm_uuid").text());
    buf_t__put(out, "</code>");
    json_t chips = a.get("chip_ids");
    for (int i = 0; i < chips.count(); ++i) {
      buf_t__put(out, "<br>");
      chipLabel(out, settings, chips.at(i).text(), NULL);
    }
  } else {
    buf_t__put(out, "<span class=mut>an keiner VM (Schluessel wird nicht herausgegeben)</span>");
  }

  buf_t__put(out, "</td><td>");

  if (strcmp(status, "active") == 0) {
    buf_t__put(out, "<form method=post action='/mode' style='display:flex;gap:6px;flex-wrap:wrap'>");
    csrfField(out);
    buf_t__put(out, "<input type=hidden name=disk value='");
    buf_t__html(out, id);
    buf_t__put(out, "'><select name=mode>");
    for (int i = 0; i < 3; ++i)
      buf_t__printf(out, "<option value=%s%s>%s</option>", modes[i][0],
                    strcmp(modes[i][0], mode) == 0 ? " selected" : "", modes[i][1]);
    buf_t__put(out, "</select><input type=text name=window placeholder='Mo-Fr 06:00-22:00' "
                    "style='width:150px' value='");
    buf_t__html(out, d.get("window").text());
    buf_t__printf(out, "'><label class=mut title='Neuer Replay-Stand auch im laufenden Betrieb, "
                       "alle n Sekunden (0: nur beim Booten)'>Replay <input type=number min=0 "
                       "name=replay_interval style='width:80px' value='%ld'>s</label>"
                       "<button class=btn>Setzen</button></form>",
                  d.get("replay_interval").number());
  }

  buf_t__put(out, "</td></tr>");

  disk.release();
  att.release();
}

static void leaseTable(buf_t *out, settings_t *settings) {

  sql_t q = SQL`select disk_id, report_id, chip_id, extract(epoch from expires)::INT8,
      expires > now() from leases order by expires desc`;
  PGresult *r = dbAsk(&q);
  q.release();

  buf_t__put(out, "<h1 style='margin-top:28px'>Laufende Instanzen (Lease)</h1><div class=card>"
                  "<div class=mut>Pro Disk bekommt nur eine VM-Instanz (SNP REPORT_ID) den Schluessel. "
                  "Nach einem Absturz laeuft der Lease ab, oder du gibst ihn hier sofort frei.</div>"
                  "<table><tr><th>Disk</th><th>Instanz</th><th>Host</th><th>Status</th><th></th></tr>");

  for (int i = 0; r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && i < PQntuples(r); ++i) {
    bool live = PQgetvalue(r, i, 4)[0] == 't';
    buf_t__printf(out, "<tr><td><code>%.8s…</code></td><td><code>%.16s…</code></td><td>",
                  PQgetvalue(r, i, 0), PQgetvalue(r, i, 1));
    chipLabel(out, settings, PQgetvalue(r, i, 2), NULL);
    buf_t__put(out, "</td><td>");
    if (live) {
      buf_t__put(out, "<span class=ok>aktiv bis ");
      when(out, atol(PQgetvalue(r, i, 3)), "%H:%M:%S");
      buf_t__put(out, "</span>");
    } else {
      buf_t__put(out, "<span class=mut>abgelaufen</span>");
    }
    buf_t__put(out, "</td><td><form method=post action='/lease'>");
    csrfField(out);
    buf_t__printf(out, "<input type=hidden name=disk value='%s'><button class='btn dan'>"
                       "Lease freigeben</button></form></td></tr>", PQgetvalue(r, i, 0));
  }

  buf_t__put(out, "</table></div>");

  if (r != NULL)
    PQclear(r);
}

static void vtpmRow(buf_t *out, const char *hd) {

  bao_entry_t v = storeGet("vtpm", hd);
  replay_t stand = storeReplay(hd);
  json_t e = v.payload();

  if (!v.found || !isHex(hd, 64)) {
    v.release();
    return;
  }

  buf_t__put(out, "<tr><td>");
  buf_t__html(out, e.get("vm_name").text());
  buf_t__put(out, " <code class=mut>");
  buf_t__html(out, e.get("vm_uuid").text());
  buf_t__put(out, "</code></td><td><code>");
  buf_t__html(out, e.get("disk_id").text());
  buf_t__printf(out, "</code></td><td><code>%.16s…</code></td><td>", hd);

  const char *ek = e.get("ek").text();

  if (ek[0] != 0) {
    char shown[17];
    text_t t = TEXT`${ek}`;
    t.into(shown, sizeof shown);
    buf_t__put(out, "<code>");
    buf_t__html(out, shown);
    buf_t__put(out, "…</code> <span class=mut>seit ");
    when(out, e.get("ek_first").number(), "%d.%m. %H:%M");
    if (stand.found)
      buf_t__printf(out, ", Stand %ld", stand.confirmed);
    buf_t__put(out, "</span><form method=post action='/vtpm-reset'>");
    csrfField(out);
    buf_t__printf(out, "<input type=hidden name=host_data value='%s'><button class='btn dan'>"
                       "EK-Bindung loesen</button></form>", hd);
  } else {
    buf_t__put(out, "<span class=mut>noch nicht gebunden</span>");
  }

  buf_t__put(out, "</td></tr>");
  v.release();
}

static void releaseLog(buf_t *out) {

  sql_t q = SQL`select extract(epoch from ts)::INT8, disk_id, step, ok, detail, ctx->'pcrs'
      from releases order by id desc limit 20`;
  PGresult *r = dbAsk(&q);
  q.release();

  buf_t__put(out, "<h1 style='margin-top:28px'>Schluesselabrufe</h1><div class=card><table><tr>"
                  "<th>Zeit</th><th>Disk</th><th>Schritt</th><th>Ergebnis</th></tr>");

  for (int i = 0; r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && i < PQntuples(r); ++i) {

    bool ok = PQgetvalue(r, i, 3)[0] == 't';
    const char *detail = PQgetvalue(r, i, 4);

    buf_t__put(out, "<tr><td>");
    when(out, atol(PQgetvalue(r, i, 0)), "%d.%m. %H:%M:%S");
    buf_t__printf(out, "</td><td><code>%.8s</code></td><td>", PQgetvalue(r, i, 1));
    buf_t__html(out, PQgetvalue(r, i, 2));
    buf_t__printf(out, "</td><td class=%s>", ok ? "ok" : "bad");
    buf_t__html(out, detail);

    /* a refused boot chain: show it, and offer to approve it */
    if (!ok && strncmp(detail, "boot chain", 10) == 0 && !PQgetisnull(r, i, 5)) {
      json_t pcrs = meta_toJSON(PQgetvalue(r, i, 5));
      const char *p4 = pcrs.get("4").text(), *p8 = pcrs.get("8").text(), *p9 = pcrs.get("9").text();

      if (isHex(p4, 64) && isHex(p8, 64) && isHex(p9, 64)) {
        buf_t__printf(out, "<div class=mut><code>PCR4=%.12s… PCR8=%.12s… PCR9=%.12s…</code></div>"
                           "<form method=post action='/pcr-ref'>", p4, p8, p9);
        csrfField(out);
        buf_t__printf(out, "<input type=hidden name=p4 value='%s'><input type=hidden name=p8 value='%s'>"
                           "<input type=hidden name=p9 value='%s'><button class=btn>Diese Bootkette "
                           "als Referenz freigeben</button></form>", p4, p8, p9);
      }

      pcrs.release();
    }

    buf_t__put(out, "</td></tr>");
  }

  buf_t__put(out, "</table></div>");

  if (r != NULL)
    PQclear(r);
}

static http_response_t uiDisks(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  settings_t settings = settingsRead();
  bool failed = false;
  json_t disks = baoList("disks/", &failed);
  json_t ids = disks.get("data").get("keys");

  pageStart(&out, "Disks", "/disks");
  buf_t__put(&out, "<h1>Disks</h1><div class=card><table><tr><th>Disk</th><th>Status</th>"
                   "<th>Angehaengt an / freigegebene Hosts</th><th>Neue Instanz entsperrt</th></tr>");

  if (failed)
    buf_t__put(&out, "<tr><td colspan=4 class=bad>OpenBao nicht erreichbar.</td></tr>");

  for (int i = 0; i < ids.count(); ++i)
    if (isUuid(ids.at(i).text()))
      diskRow(&out, ids.at(i).text(), &settings);

  if (!failed && ids.count() <= 0)
    buf_t__put(&out, "<tr><td colspan=4 class=mut>Noch keine Disks.</td></tr>");

  buf_t__put(&out, "</table></div>");
  disks.release();

  leaseTable(&out, &settings);

  json_t vtpms = baoList("vtpm/", &failed);
  json_t hds = vtpms.get("data").get("keys");

  buf_t__put(&out, "<h1 style='margin-top:28px'>vTPM der VMs</h1><div class=card><div class=mut>"
                   "Der State des persistenten vTPM ist mit einem Schluessel pro VM verschluesselt, der "
                   "nur hier liegt und nur an den SVSM genau dieser VM geht. Der EK wird beim ersten "
                   "Abruf gebunden: meldet sich die VM spaeter mit einem anderen vTPM (State verloren, "
                   "ausgetauscht oder fluechtiger vTPM), gibt es keinen Disk-Schluessel, bis du die "
                   "Bindung loest. Bei jedem Boot schreibt die VM einen neuen Stand von hier in den "
                   "vTPM; ein zurueckgespielter (aelterer) State wird daran erkannt.</div>"
                   "<table><tr><th>VM</th><th>Disk</th><th>HOST_DATA</th><th>EK</th></tr>");

  for (int i = 0; i < hds.count(); ++i)
    vtpmRow(&out, hds.at(i).text());

  buf_t__put(&out, "</table></div>");
  vtpms.release();

  releaseLog(&out);
  settings.release();

  return pageEnd(req, &out);
}

/* --------------------------------------------------------- rules & hosts */

/** Whether PCR 4/8/9 are among the approved sets in the settings. */
static bool chainApproved(settings_t *settings, const char *p4, const char *p8, const char *p9) {

  json_t refs = settings->data.get("pcr_refs");

  for (int i = 0; settings->entry.found && i < refs.count(); ++i) {
    json_t r = refs.at(i);
    if (strcmp(r.get("4").text(), p4) == 0 && strcmp(r.get("8").text(), p8) == 0 &&
        strcmp(r.get("9").text(), p9) == 0)
      return true;
  }

  return false;
}

/**
 * Boot chains refused in the last 7 days, one row per PCR set: which VM,
 * how often, when last. The log itself scrolls past them within minutes.
 */
static void refusedChains(buf_t *out, settings_t *settings) {

  sql_t q = SQL`select ctx->'pcrs'->>'4', ctx->'pcrs'->>'8', ctx->'pcrs'->>'9', count(*),
      extract(epoch from max(ts))::INT8, min(disk_id), count(distinct disk_id)
    from releases
    where not ok and detail like 'boot chain%' and ts > now() - interval '7 days'
      and length(ctx->'pcrs'->>'9') = 64
    group by 1, 2, 3 order by 5 desc limit 20`;
  PGresult *r = dbAsk(&q);
  q.release();

  buf_t__put(out, "<div class=card><h2>Abgelehnte Bootketten (letzte 7 Tage)</h2><div class=mut>"
                  "VMs, die mit einer Bootkette starten wollten, die du noch nicht freigegeben hast "
                  "- etwa nach einem Kernel-Update in der VM. Erst freigeben, wenn du weisst, warum "
                  "sie sich geaendert hat.</div>");

  int shown = 0;

  for (int i = 0; r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && i < PQntuples(r); ++i) {

    const char *p4 = PQgetvalue(r, i, 0), *p8 = PQgetvalue(r, i, 1), *p9 = PQgetvalue(r, i, 2);

    if (!isHex(p4, 64) || !isHex(p8, 64) || !isHex(p9, 64) || chainApproved(settings, p4, p8, p9))
      continue;

    bao_entry_t att = storeGet("attachments", PQgetvalue(r, i, 5));
    long disks = atol(PQgetvalue(r, i, 6));

    buf_t__printf(out, "<div style='margin-top:10px'><code>PCR4=%.12s… PCR8=%.12s… PCR9=%.12s…</code>"
                       "<div class=mut>", p4, p8, p9);
    if (att.found) {
      buf_t__put(out, "VM ");
      buf_t__html(out, att.payload().get("vm_name").text());
    } else {
      buf_t__printf(out, "Disk %.8s…", PQgetvalue(r, i, 5));
    }
    if (disks > 1)
      buf_t__printf(out, " und %ld weitere", disks - 1);
    buf_t__printf(out, " · %s Versuche · zuletzt ", PQgetvalue(r, i, 3));
    when(out, atol(PQgetvalue(r, i, 4)), "%d.%m. %H:%M");
    buf_t__put(out, "</div><form method=post action='/pcr-ref' style='margin-top:4px'>");
    csrfField(out);
    buf_t__printf(out, "<input type=hidden name=back value=settings><input type=hidden name=p4 value='%s'>"
                       "<input type=hidden name=p8 value='%s'><input type=hidden name=p9 value='%s'>"
                       "<button class=btn>Diese Bootkette freigeben</button></form></div>", p4, p8, p9);
    att.release();
    ++shown;
  }

  if (shown == 0)
    buf_t__put(out, "<div class=mut style='margin-top:8px'>Keine.</div>");

  buf_t__put(out, "</div>");

  if (r != NULL)
    PQclear(r);
}

static http_response_t uiSettings(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  settings_t settings = settingsRead();
  json_t pool = settings.data.get("host_pool"), keys = settings.data.get("allowed_ssh_keys");
  json_t refs = settings.data.get("pcr_refs");

  pageStart(&out, "Regeln & Hosts", "/settings");

  if (settings.failed)
    buf_t__put(&out, "<div class='card bad'>OpenBao nicht erreichbar.</div>");

  buf_t__put(&out, "<h1>Regeln &amp; Hosts</h1><form method=post action='/settings'>");
  csrfField(&out);
  buf_t__printf(&out,
                "<div class=card><h2>Auto-Modus</h2><div class=mut>Ohne Haken braucht jede Anfrage "
                "deine Freigabe. Neue Disks (noch ohne Daten) werden immer sofort angelegt, Hinweise "
                "dazu stehen im Verlauf. Rechte entziehen (VM geloescht) wirkt immer sofort; Disks "
                "loeschen braucht immer eine Freigabe.</div>"
                "<label style='display:block;margin:6px 0'><input type=checkbox name=auto_attach%s> "
                "Bestehende Disk an neue VM, wenn Host im Pool und cloud-init nur Benutzer mit "
                "bekannten SSH-Keys anlegt</label>"
                "<label style='display:block;margin:6px 0'><input type=checkbox name=auto_add_host%s> "
                "Umzug auf Hosts aus dem Pool</label></div>",
                settings.flag("auto_attach") ? " checked" : "",
                settings.flag("auto_add_host") ? " checked" : "");

  buf_t__put(&out, "<div class=card><h2>Host-Pool</h2><div class=mut>Hosts des Providers, denen du "
                   "vertraust (HV-UUID, SNP chip_id, optional ein Name; eine Zeile pro Host)</div>"
                   "<textarea name=host_pool rows=4>");
  for (int i = 0; i < pool.count(); ++i) {
    json_t h = pool.at(i);
    buf_t__html(&out, h.get("hv_uuid").text());
    buf_t__put(&out, " ");
    buf_t__html(&out, h.get("chip_id").text());
    if (h.get("name").text()[0] != 0) {
      buf_t__put(&out, " ");
      buf_t__html(&out, h.get("name").text());
    }
    buf_t__put(&out, "\n");
  }
  buf_t__put(&out, "</textarea></div>");

  buf_t__put(&out, "<div class=card><h2>Bekannte SSH-Keys</h2><div class=mut>Wer einen Key in "
                   "cloud-init hat, kann sich nach dem Entsperren in die VM einloggen und die Daten "
                   "lesen. Auto-Freigaben nur, wenn cloud-init ausschliesslich diese Keys und keine "
                   "Befehle, Dateien oder Passwoerter enthaelt.</div><textarea name=allowed_ssh_keys rows=4>");
  for (int i = 0; i < keys.count(); ++i) {
    buf_t__html(&out, keys.at(i).text());
    buf_t__put(&out, "\n");
  }
  buf_t__put(&out, "</textarea></div><button class='btn pri'>Speichern</button></form>");

  buf_t measurements = {0};
  releaseMeasurements(&measurements, false);
  buf_t__put(&out, "<div class=card style='margin-top:14px'><h2>Referenzwerte des Providers</h2>"
                   "<div class=mut>SVSM/Firmware-Measurements, die Schluessel bekommen duerfen</div><code>");
  buf_t__html(&out, measurements.at ?: "keine");
  buf_t__put(&out, "</code></div>");
  free(measurements.at);

  buf_t__put(&out, "<div class=card><h2>Freigegebene Bootketten (PCR 4/8/9)</h2><div class=mut>"
                   "Bootloader, GRUB-Befehle und Kernel/initrd der VMs. Nur diese duerfen "
                   "Disk-Schluessel bekommen. Neue gibst du unten unter \"Abgelehnte Bootketten\" "
                   "frei.</div>");
  for (int i = 0; i < refs.count(); ++i) {
    json_t r = refs.at(i);
    char p4[13], p8[13], p9[13];
    text_t a = TEXT`${r.get("4").text()}`;
    a.into(p4, sizeof p4);
    text_t b = TEXT`${r.get("8").text()}`;
    b.into(p8, sizeof p8);
    text_t c = TEXT`${r.get("9").text()}`;
    c.into(p9, sizeof p9);
    buf_t__put(&out, "<div><code>PCR4=");
    buf_t__html(&out, p4);
    buf_t__put(&out, "… PCR8=");
    buf_t__html(&out, p8);
    buf_t__put(&out, "… PCR9=");
    buf_t__html(&out, p9);
    buf_t__put(&out, "…</code> <span class=mut>");
    buf_t__html(&out, r.get("label").text());
    buf_t__put(&out, "</span>");
    if (isHex(r.get("4").text(), 64) && isHex(r.get("8").text(), 64) && isHex(r.get("9").text(), 64)) {
      buf_t__put(&out, "<form method=post action='/pcr-ref-remove' style='display:inline;margin-left:8px'>");
      csrfField(&out);
      buf_t__printf(&out, "<input type=hidden name=p4 value='%s'><input type=hidden name=p8 value='%s'>"
                          "<input type=hidden name=p9 value='%s'><button class='btn dan'>Entfernen"
                          "</button></form>", r.get("4").text(), r.get("8").text(), r.get("9").text());
    }
    buf_t__put(&out, "</div>");
  }
  buf_t__put(&out, "</div>");

  refusedChains(&out, &settings);

  settings.release();

  return pageEnd(req, &out);
}

/* ---------------------------------------------------------------- actions */

/** Common to every form: the API port, logged in, our own token. */
static bool uiPost(http_request_t *req, form_t *form, http_response_t *refuse) {

  if (req->localPort != apiPort) {
    *refuse = req.reply(404).text("");
    return false;
  }

  if (!uiAuthorized(req)) {
    *refuse = uiLogin(req);
    return false;
  }

  *form = formRead(req);

  if (!formGenuine(form)) {
    form.release();
    *refuse = req.reply(403).text("ungueltiges Formular");
    return false;
  }

  return true;
}

static http_response_t uiDecide(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  decide(atol(form.get("id")), strcmp(form.get("decision"), "approve") == 0, "Kunde (UI)");
  form.release();

  return uiBack(req, "/");
}

static http_response_t uiUndecided(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  /* only one that has hung for a while: a live decision takes seconds */
  long id = atol(form.get("id"));
  sql_t q = SQL`update requests set status = 'pending'
    where id = ${id} and status = 'deciding' and created < now() - interval '1 minute'`;
  dbDo(&q);
  q.release();
  form.release();

  return uiBack(req, "/");
}

static http_response_t uiMode(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  const char *disk = form.get("disk"), *mode = form.get("mode"), *window = form.get("window");
  long interval = atol(form.get("replay_interval"));
  bool known = false;

  for (int i = 0; i < 3; ++i)
    known = known || strcmp(modes[i][0], mode) == 0;

  if (!isUuid(disk) || !known || interval < 0 || (window[0] != 0 && inWindow(window, time(NULL)) < 0) ||
      (strcmp(mode, "window") == 0 && window[0] == 0)) {
    form.release();
    return req.reply(400).text("Zeitfenster z. B. 'Mo-Fr 06:00-22:00' oder '06:00-22:00'");
  }

  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, o);
  yyjson_mut_obj_add_strcpy(doc, o, "mode", mode);
  yyjson_mut_obj_add_strcpy(doc, o, "window", window);
  yyjson_mut_obj_add_int(doc, o, "replay_interval", interval);
  char *json = yyjson_mut_write(doc, 0, NULL);
  yyjson_mut_doc_free(doc);

  json_t patch = meta_toJSON(json);
  storeSet("disks", disk, patch);
  patch.release();
  free(json);
  form.release();

  return uiBack(req, "/disks");
}

static http_response_t uiLease(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  if (isUuid(form.get("disk")))
    storeResetLease(form.get("disk"));

  form.release();

  return uiBack(req, "/disks");
}

static http_response_t uiVtpmReset(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  const char *hd = form.get("host_data");

  if (isHex(hd, 64)) {
    storeUnbindEk(hd);
    storeDrop("replay", hd);
  }

  form.release();

  return uiBack(req, "/disks");
}

static http_response_t uiPcrRef(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  char label[64] = "vom Kunden uebernommen ";
  time_t now = time(NULL);
  struct tm t;
  localtime_r(&now, &t);
  strftime(label + strlen(label), sizeof label - strlen(label), "%d.%m.%Y %H:%M", &t);

  pcr_ref_t ref = {{form.get("p4"), form.get("p8"), form.get("p9")}, label};

  if (isHex(ref.value[0], 64) && isHex(ref.value[1], 64) && isHex(ref.value[2], 64))
    baoEdit("settings", addPcrRef, &ref);

  bool fromSettings = strcmp(form.get("back"), "settings") == 0;
  form.release();

  return uiBack(req, fromSettings ? "/settings" : "/disks");
}

static bool removePcrRef(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  static const char *const keys[] = {"4", "8", "9"};
  pcr_ref_t *ref = (pcr_ref_t *)with;
  yyjson_mut_val *refs = yyjson_mut_obj_get(root, "pcr_refs");
  size_t count = yyjson_mut_arr_size(refs);

  (void)doc;

  for (size_t i = 0; yyjson_mut_is_arr(refs) && i < count; ++i) {
    yyjson_mut_val *have = yyjson_mut_arr_get(refs, i);
    int same = 0;
    for (int k = 0; k < 3; ++k)
      same += yyjson_mut_equals_str(yyjson_mut_obj_get(have, keys[k]), ref->value[k]);
    if (same == 3) {
      yyjson_mut_arr_remove(refs, i);
      return true;
    }
  }

  return false;
}

static http_response_t uiPcrRefRemove(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  pcr_ref_t ref = {{form.get("p4"), form.get("p8"), form.get("p9")}, ""};

  if (isHex(ref.value[0], 64) && isHex(ref.value[1], 64) && isHex(ref.value[2], 64))
    baoEdit("settings", removePcrRef, &ref);

  form.release();

  return uiBack(req, "/settings");
}

/** One line per host: "<hv-uuid> <chip_id> [name ...]"; anything else is dropped. */
static void poolFrom(yyjson_mut_doc *doc, yyjson_mut_val *pool, char *text) {

  for (char *line = strtok(text, "\r\n"); line != NULL; line = strtok(NULL, "\r\n")) {

    char hv[64] = "", chip[200] = "";
    int used = 0;

    if (sscanf(line, " %63s %199s %n", hv, chip, &used) < 2)
      continue;

    for (char *c = hv; *c; ++c)
      *c = (char)tolower((unsigned char)*c);
    for (char *c = chip; *c; ++c)
      *c = (char)tolower((unsigned char)*c);

    if (!isUuid(hv) || !isHex(chip, 128))
      continue;

    yyjson_mut_val *h = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, h, "hv_uuid", hv);
    yyjson_mut_obj_add_strcpy(doc, h, "chip_id", chip);
    yyjson_mut_obj_add_strcpy(doc, h, "name", used > 0 ? line + used : "");
    yyjson_mut_arr_append(pool, h);
  }
}

static http_response_t uiSaveSettings(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(doc), *pool = yyjson_mut_arr(doc), *keys = yyjson_mut_arr(doc);
  yyjson_mut_doc_set_root(doc, o);

  /* checkboxes only arrive when ticked */
  bool attach = false, addHost = false;
  for (int i = 0; i < form.count; ++i) {
    attach = attach || strcmp(form.name[i], "auto_attach") == 0;
    addHost = addHost || strcmp(form.name[i], "auto_add_host") == 0;
  }
  yyjson_mut_obj_add_bool(doc, o, "auto_attach", attach);
  yyjson_mut_obj_add_bool(doc, o, "auto_add_host", addHost);

  char *poolText = strdup(form.get("host_pool"));
  if (poolText != NULL)
    poolFrom(doc, pool, poolText);
  free(poolText);
  yyjson_mut_obj_add_val(doc, o, "host_pool", pool);

  char *keyText = strdup(form.get("allowed_ssh_keys"));
  for (char *line = keyText != NULL ? strtok(keyText, "\r\n") : NULL; line != NULL;
       line = strtok(NULL, "\r\n")) {
    while (*line == ' ')
      ++line;
    if (*line != 0)
      yyjson_mut_arr_add_strcpy(doc, keys, line);
  }
  free(keyText);
  yyjson_mut_obj_add_val(doc, o, "allowed_ssh_keys", keys);

  char *json = yyjson_mut_write(doc, 0, NULL);
  yyjson_mut_doc_free(doc);

  json_t patch = meta_toJSON(json);
  storeSet("settings", NULL, patch);
  patch.release();
  free(json);
  form.release();

  return uiBack(req, "/settings");
}

static void uiRoutes(void) {
  http.get("/", uiRequests);
  http.get("/disks", uiDisks);
  http.get("/settings", uiSettings);
  http.post("/decide", uiDecide);
  http.post("/undecided", uiUndecided);
  http.post("/mode", uiMode);
  http.post("/lease", uiLease);
  http.post("/vtpm-reset", uiVtpmReset);
  http.post("/pcr-ref", uiPcrRef);
  http.post("/pcr-ref-remove", uiPcrRefRemove);
  http.post("/settings", uiSaveSettings);
}

#endif /* WX_UI_H */

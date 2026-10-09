/**
 * The customer's web UI: requests, disks, the key release log, settings.
 *
 * On the API port, behind Basic auth ("kunde" and the password in
 * WX_UI_PASSWORD_FILE). Every form carries a CSRF token derived from that
 * password, so all workers agree on it without sharing anything.
 *
 * Rendered on the server, without JavaScript: tabs are links, every change
 * a form. The stylesheet and the fonts come from the agent itself (/ui/...),
 * so the page asks no other server for anything.
 */
#ifndef WX_UI_H
#define WX_UI_H

#include "api.h"
#include "assets.h"
#include "de.h"

#include <ctype.h>
#include <openssl/hmac.h>

#ifndef WX_VERSION
#define WX_VERSION "dev"
#endif

static char uiPassword[256];
static char uiExpect[512]; /* "Basic base64(kunde:password)" */
static char uiCsrf[65];

static void uiConfigure(bool say) {

  if (!readSecret(env("WX_UI_PASSWORD_FILE", "/secrets/ui-password"), uiPassword,
                  sizeof uiPassword)) {
    if (say)
      fprintf(stderr, "wx1-keyagent: no UI password, the UI is closed\n");
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
      .header("www-authenticate", "Basic realm=\"wx1-keyagent\", charset=\"UTF-8\"")
      .mime("text/plain; charset=utf-8")
      .text("Anmeldung nötig: Benutzer kunde und das Passwort der UI.");
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

static bool form_t__has(form_t *self, const char *name) {

  for (int i = 0; i < self->count; ++i)
    if (strcmp(self->name[i], name) == 0)
      return true;

  return false;
}

static void form_t__release(form_t *self) {
  free(self->data);
}

/** A POST from our own page: logged in and with the token. */
static bool formGenuine(form_t *form) {

  const char *got = form.get("csrf");

  return uiCsrf[0] != 0 && strlen(got) == 64 && CRYPTO_memcmp(got, uiCsrf, 64) == 0;
}

/**
 * Where a form sends the browser back to: the page it came from (its field
 * "back"), if that is one of ours - a path with a query of plain words,
 * never another host. Otherwise `fallback`.
 */
static http_response_t uiBack(http_request_t *req, form_t *form, const char *fallback) {

  const char *back = form != NULL ? form.get("back") : "";
  bool ours = back[0] == '/' && back[1] != '/' && strlen(back) < 120;

  for (const char *c = back; ours && *c != 0; ++c)
    ours = isalnum((unsigned char)*c) || strchr("/?=&_-", *c) != NULL;

  /* the header keeps a pointer, and the form is freed before nginx sends
     it: the target is copied. One request at a time per worker. */
  static char to[128];
  snprintf(to, sizeof to, "%s", ours ? back : fallback);

  return req.reply(303).header("location", to).text("");
}

/* ----------------------------------------------------------------- design */

/*
 * wx-one: the violet and the teal of the logo, Barlow, quiet surfaces.
 * Colours only as variables, so the dark scheme is the same sheet.
 */
static const char uiCss[] =
  "@font-face{font-family:Barlow;font-weight:400;font-style:normal;font-display:swap;"
  "src:url(/ui/barlow-400.woff2) format('woff2')}"
  "@font-face{font-family:Barlow;font-weight:600;font-style:normal;font-display:swap;"
  "src:url(/ui/barlow-600.woff2) format('woff2')}"
  "@font-face{font-family:Barlow;font-weight:700;font-style:normal;font-display:swap;"
  "src:url(/ui/barlow-700.woff2) format('woff2')}"

  ":root{--brand:#5a2f90;--brand-hover:#4a2577;--teal:#00b5ba;--accent:#00787d;--accent-bg:#e3f6f7;"
  "--bg:#f4f5f8;--card:#fff;--soft:#f7f8fb;--ink:#141733;--mut:#5d6378;--line:#e2e4ec;"
  "--ok:#137a48;--ok-bg:#e7f5ee;--warn:#965800;--warn-bg:#fdf2df;--bad:#b42318;--bad-bg:#fdebe9;"
  "--logo-ink:#231f20;--shadow:0 1px 2px rgba(20,23,51,.05),0 2px 8px rgba(20,23,51,.04);"
  "color-scheme:light}"
  "@media (prefers-color-scheme:dark){:root{--brand:#8a61d1;--brand-hover:#9c79dc;--accent:#43ccd1;"
  "--accent-bg:#10343c;--bg:#0e1022;--card:#161a33;--soft:#1b1f3d;--ink:#e9eaf4;--mut:#9ea3bf;"
  "--line:#292e50;--ok:#51c48d;--ok-bg:#12301f;--warn:#efb45a;--warn-bg:#382810;--bad:#ff8b82;"
  "--bad-bg:#3b1717;--logo-ink:#e9eaf4;--shadow:none;color-scheme:dark}}"

  "*{box-sizing:border-box}"
  "html{-webkit-text-size-adjust:100%}"
  "body{margin:0;background:var(--bg);color:var(--ink);"
  "font:400 15px/1.5 Barlow,'Segoe UI',system-ui,-apple-system,Arial,sans-serif}"
  "a{color:var(--accent)}"
  "code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}"
  "code{overflow-wrap:anywhere}"
  "h1,h2,h3{font-weight:600;letter-spacing:-.01em;margin:0}"
  ".wrap{max-width:1120px;margin:0 auto;padding:0 20px}"

  /* the bar on top */
  ".top{background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}"
  ".top::before{content:'';display:block;height:3px;"
  "background:linear-gradient(90deg,#493290,#65308f 55%,#00b5ba)}"
  ".top .wrap{display:flex;align-items:center;gap:22px;min-height:60px;flex-wrap:wrap}"
  ".brand{display:flex;align-items:center;gap:12px;color:var(--ink);text-decoration:none}"
  ".brand svg{height:36px;width:auto;display:block}"
  ".brand .product{border-left:1px solid var(--line);padding-left:12px;line-height:1.15}"
  ".brand .product b{display:block;font-weight:600;font-size:16px}"
  ".brand .product span{font-size:12px;color:var(--mut)}"
  ".nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}"
  ".nav a{color:var(--mut);text-decoration:none;padding:8px 12px;border-radius:8px;font-weight:600;"
  "display:flex;align-items:center;gap:7px}"
  ".nav a:hover{color:var(--ink);background:var(--soft)}"
  ".nav a.on{color:var(--brand);background:var(--accent-bg)}"
  "@media (prefers-color-scheme:dark){.nav a.on{color:var(--ink)}}"

  /* page */
  "main{padding:28px 0 56px}"
  ".head{margin-bottom:18px}"
  ".head h1{font-size:27px}"
  ".lead{color:var(--mut);margin:6px 0 0;max-width:76ch}"
  ".count{display:inline-block;min-width:20px;padding:0 6px;border-radius:99px;font-size:12px;"
  "line-height:20px;text-align:center;font-weight:600;background:var(--soft);color:var(--mut)}"
  ".count.hot{background:var(--warn-bg);color:var(--warn)}"

  /* tabs */
  ".tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin:0 0 20px;overflow-x:auto;"
  "scrollbar-width:thin}"
  ".tabs a{display:flex;align-items:center;gap:7px;padding:10px 14px;color:var(--mut);"
  "text-decoration:none;font-weight:600;white-space:nowrap;border-bottom:2px solid transparent;"
  "margin-bottom:-1px}"
  ".tabs a:hover{color:var(--ink)}"
  ".tabs a.on{color:var(--ink);border-bottom-color:var(--teal)}"

  /* surfaces */
  ".card{background:var(--card);border:1px solid var(--line);border-radius:12px;"
  "box-shadow:var(--shadow);padding:18px 20px;margin-bottom:14px}"
  ".card>h2{font-size:17px;margin-bottom:4px}"
  ".card>.lead{margin:0 0 14px;font-size:14px}"
  ".section{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);"
  "font-weight:600;margin:28px 0 10px}"
  ".empty{text-align:center;color:var(--mut);padding:36px 20px}"
  ".empty b{display:block;color:var(--ink);font-size:16px;margin-bottom:2px}"
  ".mut{color:var(--mut)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}"
  ".small{font-size:13px}"

  /* pills */
  ".pill{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;"
  "padding:3px 10px;border-radius:99px;white-space:nowrap;background:var(--soft);color:var(--mut)}"
  ".pill::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor}"
  ".pill.ok{background:var(--ok-bg);color:var(--ok)}"
  ".pill.warn{background:var(--warn-bg);color:var(--warn)}"
  ".pill.bad{background:var(--bad-bg);color:var(--bad)}"
  ".tag{display:inline-block;font-size:11.5px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;"
  "color:var(--accent);background:var(--accent-bg);padding:2px 8px;border-radius:5px}"

  /* a request */
  ".req{border-left:4px solid var(--line)}"
  ".req.t-warn{border-left-color:#e9a23b}.req.t-bad{border-left-color:#d9534f}.req.t-ok{border-left-color:#3aa876}"
  ".req-h{display:flex;gap:14px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}"
  ".req-h h3{font-size:18px;margin:6px 0 2px}"
  ".req-meta{color:var(--mut);font-size:13px}"
  ".facts{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:14px 0 0}"
  ".facts dt{color:var(--mut)}.facts dd{margin:0;min-width:0}"
  ".notes{list-style:none;margin:14px 0 0;padding:0;display:grid;gap:6px}"
  ".notes li{display:flex;gap:10px;align-items:flex-start;padding:8px 12px;border-radius:8px;"
  "font-size:14px}"
  ".notes li::before{flex:none;width:18px;height:18px;border-radius:50%;font-size:12px;font-weight:700;"
  "display:inline-flex;align-items:center;justify-content:center;margin-top:1px;color:#fff}"
  ".notes .warn{background:var(--warn-bg);color:var(--ink)}.notes .warn::before{content:'!';background:#d38b1c}"
  ".notes .bad{background:var(--bad-bg);color:var(--ink)}.notes .bad::before{content:'\\2715';background:#d9534f}"
  ".notes .ok{background:var(--ok-bg);color:var(--ink)}.notes .ok::before{content:'\\2713';background:#3aa876}"
  ".passed{list-style:none;margin:8px 0 0;padding:0;columns:2 320px;column-gap:24px;font-size:13.5px}"
  ".passed li{break-inside:avoid;padding:2px 0 2px 22px;position:relative}"
  ".passed li::before{content:'\\2713';position:absolute;left:2px;color:var(--ok);font-weight:700}"
  ".passed li.bad::before{content:'\\2715';color:var(--bad)}"
  ".passed li.warn::before{content:'!';color:var(--warn)}"
  "details{margin-top:12px}"
  "details>summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:14px;list-style:none;"
  "display:inline-flex;align-items:center;gap:6px}"
  "details>summary::-webkit-details-marker{display:none}"
  "details>summary::before{content:'\\25B8';transition:transform .15s}"
  "details[open]>summary::before{transform:rotate(90deg)}"
  "pre{background:var(--soft);border:1px solid var(--line);padding:10px 12px;border-radius:8px;"
  "overflow:auto;max-height:300px;margin:8px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}"
  ".file{margin-top:10px}.file b{font-size:13px;color:var(--mut);font-weight:600}"
  ".req-a{display:flex;gap:10px;align-items:center;margin-top:16px;padding-top:14px;"
  "border-top:1px solid var(--line);flex-wrap:wrap}"
  ".req-a .hint{color:var(--mut);font-size:13px;margin-right:auto}"
  ".req .lead.small{margin-top:8px}"

  /* controls */
  ".btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:var(--card);"
  "color:var(--ink);padding:8px 16px;border-radius:8px;cursor:pointer;font:600 14px/1.2 inherit;"
  "text-decoration:none}"
  ".btn:hover{background:var(--soft)}"
  ".btn.pri{background:var(--brand);border-color:var(--brand);color:#fff}"
  ".btn.pri:hover{background:var(--brand-hover);border-color:var(--brand-hover)}"
  ".btn.dan{color:var(--bad)}.btn.dan:hover{background:var(--bad-bg);border-color:transparent}"
  ".btn.sm{padding:5px 11px;font-size:13px}"
  ".btn.danger{background:var(--bad);border-color:var(--bad);color:#fff}"
  ".btn.danger:hover{filter:brightness(.92);background:var(--bad)}"
  ".host{margin-top:8px}"
  "label.check .mut{display:block;font-size:14px}"
  ".btn:focus-visible,.tabs a:focus-visible,.nav a:focus-visible,input:focus-visible,select:focus-visible,"
  "textarea:focus-visible,summary:focus-visible{outline:2px solid var(--teal);outline-offset:2px}"
  "input[type=text],input[type=number],textarea,select{font:inherit;font-size:14px;padding:7px 10px;"
  "border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}"
  "textarea{width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;"
  "line-height:1.5}"
  "label.check{display:flex;gap:12px;align-items:flex-start;padding:12px 0;border-top:1px solid var(--line)}"
  "label.check:first-of-type{border-top:0}"
  "label.check input{margin-top:4px;width:17px;height:17px;accent-color:var(--brand)}"
  "label.check b{display:block;font-weight:600}"
  ".row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}"
  ".bar{display:flex;justify-content:flex-end;margin-top:14px}"
  "form.inline{display:inline}"

  /* tables */
  ".tbl-wrap{overflow-x:auto;margin:0 -20px;padding:0 20px}"
  "table{width:100%;border-collapse:collapse;font-size:14px}"
  "th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);"
  "font-weight:600;padding:0 12px 10px 0;white-space:nowrap}"
  "td{padding:12px 12px 12px 0;border-top:1px solid var(--line);vertical-align:top}"
  "td .sub{color:var(--mut);font-size:12.5px;margin-top:2px}"
  "tr.refused td:first-child{box-shadow:inset 3px 0 0 #d9534f;padding-left:12px}"
  "td:first-child{padding-left:12px}th:first-child{padding-left:12px}"
  ".times{font-weight:600;color:var(--bad)}"
  ".chain{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:12.5px}"
  ".chain span{color:var(--mut)}"

  "footer.foot{border-top:1px solid var(--line);color:var(--mut);font-size:12.5px;padding:18px 0 28px}"
  "footer.foot .wrap{display:flex;gap:16px;justify-content:space-between;flex-wrap:wrap}"

  "@media (max-width:720px){.facts{grid-template-columns:1fr;gap:0 0}.facts dd{margin-bottom:8px}"
  ".brand .product span{display:none}.nav{margin-left:0;width:100%}.head h1{font-size:23px}"
  ".card{padding:16px}.tbl-wrap{margin:0 -16px;padding:0 16px}.req-a .hint{width:100%}"
  ".req-a .btn{flex:1;justify-content:center}}";

/* The wx-one logo; its word mark follows the colour scheme. */
static const char uiLogo[] =
  "<svg viewBox='0 0 1296 481' role='img' aria-label='WX-ONE'><defs><linearGradient id='wxg' "
  "gradientUnits='userSpaceOnUse' x1='180.455' y1='246.3' x2='661.4' y2='246.3'><stop offset='0' "
  "stop-color='#493290'/><stop offset='1' stop-color='#65308F'/></linearGradient></defs>"
  "<g transform='translate(-180.5,-5.8)'><path fill='url(#wxg)' d='m 596,375.1 -128.8,-128.8 87,-87 "
  "v 0 L 508,113 421,200 236.3,15.4 v 0 c -5.9,-5.9 -14.1,-9.6 -23.1,-9.6 -18.1,0 -32.7,14.6 "
  "-32.7,32.7 v 415.6 c 0,18.1 14.6,32.7 32.7,32.7 9,0 17.2,-3.7 23.1,-9.6 v 0 L 421,292.5 "
  "605.6,477.1 c 5.9,5.9 14.1,9.6 23.2,9.6 18.1,0 32.7,-14.6 32.7,-32.7 V 314.7 H 596 Z m "
  "-350.1,0 V 117.5 l 128.8,128.8 z'/><path fill='#00B5BA' d='m 661.4,38.5 c 0,-13.2 -8,-25.2 "
  "-20.2,-30.2 -4,-1.7 -8.3,-2.5 -12.5,-2.5 -8.5,0 -16.9,3.3 -23.1,9.6 l -1.3,1.3 -75,75 46.3,46.3 "
  "20.4,-20.4 v 167.1 h 65.4 z'/><g fill='var(--logo-ink)' transform='matrix(1.5546835,0,0,"
  "1.5546835,429.09359,-598.49744)'><path d='m 195.7,519.9 17.3,54.6 h 0.9 l 14.7,-54.6 h 18.5 l "
  "15.1,54.6 h 0.7 l 17.7,-54.6 h 16.1 l -24.4,67.8 h -21.1 l -13.1,-50.9 h -0.7 L 224,587.7 h "
  "-20.9 l -23.7,-67.8 z'/><path d='m 322.4,519.9 17.8,26.1 h 4.3 l 17.8,-26.1 h 17.4 L 357,552 l "
  "24,35.7 h -17.8 l -18.5,-28 h -4.8 l -18.5,28 H 303.6 L 327.8,552.4 305,519.9 Z'/><path d='m "
  "419.2,546.4 v 13.5 h -38.6 v -13.5 z'/><path d='m 467.3,589.5 c -20.6,0 -38,-14.2 -38,-35.6 "
  "0,-21.3 17.4,-35.6 38,-35.6 20.6,0 38,14.2 38,35.6 0,21.3 -17.4,35.6 -38,35.6 z m 0,-13.2 c "
  "12.8,0 22.7,-8.5 22.7,-22.5 0,-14 -9.9,-22.4 -22.7,-22.4 -12.8,0 -22.7,8.5 -22.7,22.4 0,14.1 "
  "9.9,22.5 22.7,22.5 z'/><path d='m 531.1,519.9 40.6,45.6 v -45.6 h 15.2 v 67.8 H 572.3 L "
  "531.7,542 v 45.8 H 516.6 V 520 h 14.5 z'/><path d='m 660.7,519.9 v 13.9 h -46.2 v 12.5 h 41.6 "
  "v 13.9 h -41.6 v 13.5 h 48 v 14.1 H 599.2 V 520 h 61.5 z'/></g></g></svg>";

/* the stylesheet and the fonts: no login, nothing in them is anyone's */
static http_response_t uiAsset(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");

  const char *name = req.param("name");

  if (strcmp(name, "ui.css") == 0)
    return req.reply(200)
        .header("cache-control", "max-age=3600")
        .mime("text/css; charset=utf-8")
        .text(uiCss);

  /* the sizes live in assets.c with the bytes: not constants here */
  const struct {
    const char *name;
    const unsigned char *bytes;
    size_t length;
  } fonts[] = {{"barlow-400.woff2", asset_barlow_400, asset_barlow_400_size},
               {"barlow-600.woff2", asset_barlow_600, asset_barlow_600_size},
               {"barlow-700.woff2", asset_barlow_700, asset_barlow_700_size}};

  for (size_t i = 0; i < sizeof fonts / sizeof fonts[0]; ++i)
    if (strcmp(name, fonts[i].name) == 0)
      return req.reply(200)
          .header("cache-control", "max-age=604800, immutable")
          .bytes("font/woff2", fonts[i].bytes, fonts[i].length);

  return req.reply(404).text("");
}

/* ------------------------------------------------------------------ pages */

/** How many requests wait for the customer: the number at "Anfragen". */
static long openRequests(void) {

  sql_t q = SQL`select count(*) from requests where status in ('pending', 'deciding')`;
  PGresult *r = dbAsk(&q);
  q.release();

  long n = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK ? atol(PQgetvalue(r, 0, 0)) : 0;

  if (r != NULL)
    PQclear(r);

  return n;
}

static void pageStart(buf_t *out, const char *title, const char *active) {

  static const char *const links[][2] = {
      {"/", "Anfragen"}, {"/disks", "Disks &amp; VMs"}, {"/log", "Protokoll"}, {"/settings", "Einstellungen"}};
  long open = openRequests();

  buf_t__put(out, "<!doctype html><html lang=de><head><meta charset=utf-8>"
                  "<meta name=viewport content='width=device-width,initial-scale=1'>"
                  "<meta name=robots content=noindex><meta name=referrer content=no-referrer><title>");
  buf_t__html(out, title);
  buf_t__put(out, " · wx1 Keyagent</title><link rel=stylesheet href='/ui/ui.css?v=" WX_VERSION "'>"
                  "</head><body><header class=top><div class=wrap><a class=brand href='/'>");
  buf_t__put(out, uiLogo);
  buf_t__put(out, "<span class=product><b>Keyagent</b><span>Schlüsselfreigabe für vertrauliche VMs"
                  "</span></span></a><nav class=nav>");

  for (int i = 0; i < 4; ++i) {
    buf_t__printf(out, "<a href='%s'%s>%s", links[i][0],
                  strcmp(links[i][0], active) == 0 ? " class=on aria-current=page" : "", links[i][1]);
    if (i == 0 && open > 0)
      buf_t__printf(out, "<span class='count hot' title='warten auf deine Entscheidung'>%ld</span>", open);
    buf_t__put(out, "</a>");
  }

  buf_t__put(out, "</nav></div></header><main><div class=wrap>");
}

static void pageHead(buf_t *out, const char *title, const char *lead) {

  buf_t__put(out, "<div class=head><h1>");
  buf_t__put(out, title);
  buf_t__put(out, "</h1>");

  if (lead != NULL)
    buf_t__printf(out, "<p class=lead>%s</p>", lead);

  buf_t__put(out, "</div>");
}

typedef struct {
  const char *key, *label;
  long count;
  bool hot;
} tab_t;

/** Tabs as links: ?tab=<key> on `path`; the first is the one without a tab. */
static void tabs(buf_t *out, const char *path, const char *current, const tab_t *list, int n) {

  buf_t__put(out, "<nav class=tabs aria-label='Ansicht'>");

  for (int i = 0; i < n; ++i) {
    bool on = strcmp(list[i].key, current) == 0;
    if (i == 0)
      buf_t__printf(out, "<a href='%s'", path);
    else
      buf_t__printf(out, "<a href='%s?tab=%s'", path, list[i].key);
    buf_t__printf(out, "%s>%s", on ? " class=on aria-current=page" : "", list[i].label);
    if (list[i].count > 0)
      buf_t__printf(out, "<span class='count%s'>%ld</span>", list[i].hot ? " hot" : "", list[i].count);
    buf_t__put(out, "</a>");
  }

  buf_t__put(out, "</nav>");
}

/** The tab asked for, if it is one of `list`; else the first. */
static const char *tabOf(http_request_t *req, const tab_t *list, int n) {

  const char *want = req.query("tab");

  for (int i = 0; i < n; ++i)
    if (strcmp(list[i].key, want) == 0)
      return list[i].key;

  return list[0].key;
}

/** Ends the page and answers with it. */
static http_response_t pageEnd(http_request_t *req, buf_t *out) {

  buf_t__put(out, "</div></main><footer class=foot><div class=wrap><span>wx1 Keyagent " WX_VERSION
                  " · läuft bei dir, nicht beim Provider</span><span>Schlüssel und Bindungen liegen "
                  "in deinem OpenBao</span></div></footer></body></html>");

  static buf_t page;
  buf_t__reset(&page);
  buf_t__add(&page, out->at ?: "", out->length);
  free(out->at);

  return req.reply(200)
      .header("cache-control", "no-store")
      .header("x-frame-options", "DENY")
      .header("content-security-policy",
              "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
              "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
      .mime("text/html; charset=utf-8")
      .text(page.broke ? "" : page.at);
}

/** The hidden fields of every form: the token, and the page to come back to. */
static void formFields(buf_t *out, http_request_t *req) {

  buf_t__printf(out, "<input type=hidden name=csrf value='%s'>", uiCsrf);
  buf_t__put(out, "<input type=hidden name=back value='");
  buf_t__html(out, req->path);
  if (req->queryString[0] != 0) {
    buf_t__put(out, "?");
    buf_t__html(out, req->queryString);
  }
  buf_t__put(out, "'>");
}

/** "08.10. 14:03" in the agent's local time. */
static void when(buf_t *out, long epoch, const char *format) {

  char text[40];
  struct tm t;
  time_t at = (time_t)epoch;

  localtime_r(&at, &t);
  strftime(text, sizeof text, format, &t);
  buf_t__put(out, text);
}

/** "vor 5 Minuten", "vor 3 Stunden", or the date. */
static void ago(buf_t *out, long epoch) {

  long d = (long)time(NULL) - epoch;

  if (d < 60)
    buf_t__put(out, "gerade eben");
  else if (d < 3600)
    buf_t__printf(out, "vor %ld Minute%s", d / 60, d / 60 == 1 ? "" : "n");
  else if (d < 86400)
    buf_t__printf(out, "vor %ld Stunde%s", d / 3600, d / 3600 == 1 ? "" : "n");
  else
    when(out, epoch, "%d.%m.%Y %H:%M");
}

/** The first `n` characters of `text`, escaped, with an ellipsis if it was longer. */
static void shortHtml(buf_t *out, const char *text, size_t n) {

  char cut[80];
  size_t length = strlen(text ?: "");

  if (n >= sizeof cut)
    n = sizeof cut - 1;

  memcpy(cut, text ?: "", length < n ? length : n);
  cut[length < n ? length : n] = 0;
  buf_t__html(out, cut);

  if (length > n)
    buf_t__put(out, "…");
}

/** A host by its chip_id, named from the pool if it is there. */
static void chipLabel(buf_t *out, settings_t *settings, const char *chip, const char *hv) {

  json_t pool = settings->data.get("host_pool");

  for (int i = 0; settings->entry.found && i < pool.count(); ++i) {
    json_t h = pool.at(i);

    if (strcmp(h.get("chip_id").text(), chip) == 0) {
      if (h.get("name").text()[0] != 0) {
        buf_t__put(out, "<b>");
        buf_t__html(out, h.get("name").text());
        buf_t__put(out, "</b> ");
      }
      buf_t__put(out, "<code>");
      buf_t__html(out, h.get("hv_uuid").text());
      buf_t__put(out, "</code> <span class='pill ok'>im Pool</span><div class=sub>Chip <code>");
      shortHtml(out, chip, 16);
      buf_t__put(out, "</code></div>");
      return;
    }
  }

  /* the provider wrote this one: escaped like everything from a request */
  if (hv != NULL && hv[0] != 0) {
    buf_t__put(out, "<code>");
    buf_t__html(out, hv);
    buf_t__put(out, "</code> ");
  }
  buf_t__put(out, "<span class='pill warn'>nicht im Pool</span><div class=sub>Chip <code>");
  shortHtml(out, chip, 16);
  buf_t__put(out, "</code></div>");
}

/* --------------------------------------------------------------- requests */

static const char *typeLabel(const char *type) {

  static const char *const labels[][2] = {
      {"create", "Neue VM mit Systemdisk"},
      {"create_volume", "Neues Volume"},
      {"attach", "Volume an VM hängen"},
      {"add_host", "VM auf weiterem Host erlauben"},
      {"detach", "Disk von VM getrennt"},
      {"reprovision", "Hauptdisk neu installieren"},
      {"delete_disk", "Disk endgültig löschen"},
      {"unlock", "Neue VM-Instanz will die Disk entsperren"}};

  for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
    if (strcmp(labels[i][0], type) == 0)
      return labels[i][1];

  return type;
}

/* What each kind of request means for the customer, in one sentence. */
static const char *typeExplains(const char *type) {

  static const char *const says[][2] = {
      {"create", "Der Provider legt eine VM an. Ihre Systemdisk bekommt einen eigenen Schlüssel, "
                 "der nur an genau diese VM geht."},
      {"create_volume", "Ein Datenträger ohne VM. Sein Schlüssel geht an niemanden, bis er an eine VM "
                        "gehängt wird."},
      {"attach", "Die VM bekommt danach den Schlüssel dieses Volumes, und damit seine Daten."},
      {"add_host", "Die VM darf danach auch auf diesem Host starten und ihren Schlüssel bekommen."},
      {"detach", "Die VM bekommt den Schlüssel nicht mehr. Wirkt sofort, der Schlüssel bleibt erhalten."},
      {"reprovision", "Der alte Schlüssel wird vernichtet, die bisherigen Daten sind danach unlesbar."},
      {"delete_disk", "Der Schlüssel wird vernichtet, die Daten der Disk sind danach unlesbar, "
                      "auch in Backups."},
      {"unlock", "Eine neu gestartete Instanz der VM will den Schlüssel, und die Disk verlangt deine "
                 "Bestätigung."}};

  for (size_t i = 0; i < sizeof says / sizeof says[0]; ++i)
    if (strcmp(says[i][0], type) == 0)
      return says[i][1];

  return "";
}

static bool destroys(const char *type) {
  return strcmp(type, "reprovision") == 0 || strcmp(type, "delete_disk") == 0;
}

/* the kinds of requests, one tab each */
static const struct {
  const char *key, *label, *lead;
  const char *types[2];
} reqGroups[] = {
    {"vms", "VMs &amp; Volumes",
     "Neue VMs und Volumes legt der Agent sofort an: sie haben noch keine Daten. Was dabei auffiel, "
     "steht hier als Hinweis.",
     {"create", "create_volume"}},
    {"anbindung", "Anhängen &amp; Trennen",
     "Welche VM den Schlüssel welches Volumes bekommt. Trennen wirkt immer sofort.", {"attach", "detach"}},
    {"hosts", "Hosts", "Auf welchen Hosts des Providers eine VM starten darf.", {"add_host", NULL}},
    {"loeschen", "Neuinstallation &amp; Löschen",
     "Anfragen, nach denen Daten unwiderruflich unlesbar sind. Sie brauchen immer deine Freigabe.",
     {"reprovision", "delete_disk"}},
    {"entsperren", "Entsperren",
     "Neue Instanzen von VMs, deren Disk eine Bestätigung verlangt.", {"unlock", NULL}},
};

#define REQ_GROUPS ((int)(sizeof reqGroups / sizeof reqGroups[0]))

static int groupOf(const char *type) {

  for (int g = 0; g < REQ_GROUPS; ++g)
    for (int t = 0; t < 2; ++t)
      if (reqGroups[g].types[t] != NULL && strcmp(reqGroups[g].types[t], type) == 0)
        return g;

  return -1;
}

static void statusPill(buf_t *out, const char *status, bool remarks) {

  static const char *const labels[][3] = {
      {"pending", "Wartet auf dich", "warn"}, {"deciding", "Wird umgesetzt", "warn"},
      {"applied", "Umgesetzt", "ok"},         {"denied", "Abgelehnt", "bad"},
      {"rejected", "Abgewiesen", "bad"},      {"error", "Fehler", "bad"}};

  const char *label = status, *cls = "";

  for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
    if (strcmp(labels[i][0], status) == 0) {
      label = labels[i][1];
      cls = labels[i][2];
    }

  /* applied with remarks: done, but worth a look */
  if (strcmp(status, "applied") == 0 && remarks) {
    label = "Umgesetzt · bitte prüfen";
    cls = "warn";
  }

  buf_t__printf(out, "<span class='pill %s'>%s</span>", cls, label);
}

/** The SSH keys in a cloud-config, each marked known or not; false if there are none. */
static bool sshKeys(buf_t *out, const char *userData, settings_t *settings) {

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
      buf_t__put(out, "<dt>SSH-Keys</dt><dd>");

    buf_t__put(out, "<div><code>");
    shortHtml(out, have, 40);
    buf_t__put(out, known ? "</code> <span class='pill ok'>bekannt</span></div>"
                          : "</code> <span class='pill warn'>unbekannt</span></div>");
    any = true;
  }

  if (any)
    buf_t__put(out, "</dd>");

  return any;
}

static void fileBlock(buf_t *out, const char *name, json_t content) {

  blob_t f = blobOf(content);

  buf_t__put(out, "<div class=file><b>");
  buf_t__html(out, name);
  buf_t__put(out, "</b><pre>");
  buf_t__html(out, f.at ?: "");
  buf_t__put(out, "</pre></div>");

  free(f.at);
}

/* the columns requestRows selects */
enum { R_ID, R_CREATED, R_TYPE, R_PAYLOAD, R_STATUS, R_REASON, R_CHECKS, R_BY, R_DECIDED };

/** One request; with `actions` the buttons to decide it. */
static void requestCard(buf_t *out, http_request_t *req, PGresult *r, int row, settings_t *settings,
                        bool actions) {

  long id = atol(PQgetvalue(r, row, R_ID));
  long created = atol(PQgetvalue(r, row, R_CREATED));
  const char *type = PQgetvalue(r, row, R_TYPE);
  json_t p = meta_toJSON(PQgetvalue(r, row, R_PAYLOAD));
  const char *status = PQgetvalue(r, row, R_STATUS);
  const char *reason = PQgetvalue(r, row, R_REASON);
  json_t checks = meta_toJSON(PQgetvalue(r, row, R_CHECKS));
  const char *by = PQgetvalue(r, row, R_BY);
  bool decided = !PQgetisnull(r, row, R_DECIDED);
  int remarks = 0, failures = 0, passed = 0;
  int g = groupOf(type);

  for (int i = 0; i < checks.count(); ++i) {
    const char *kind = checks.at(i).at(0).kind();
    if (strcmp(kind, "null") == 0)
      ++remarks;
    else if (checks.at(i).at(0).truth())
      ++passed;
    else
      ++failures;
  }

  bool open = strcmp(status, "pending") == 0 || strcmp(status, "deciding") == 0;
  const char *tone = open ? "warn"
                     : strcmp(status, "applied") == 0 ? (remarks > 0 ? "warn" : "ok")
                                                      : "bad";

  buf_t__printf(out, "<article class='card req t-%s' id='r%ld'><div class=req-h><div>", tone, id);
  if (g >= 0)
    buf_t__printf(out, "<span class=tag>%s</span>", reqGroups[g].label);
  buf_t__printf(out, "<h3>%s</h3><div class=req-meta>Nr. %ld · eingegangen ", typeLabel(type), id);
  ago(out, created);
  if (decided && by[0] != 0) {
    buf_t__put(out, " · entschieden von ");
    buf_t__html(out, by);
    buf_t__put(out, " ");
    ago(out, atol(PQgetvalue(r, row, R_DECIDED)));
  }
  buf_t__put(out, "</div></div>");
  statusPill(out, status, remarks > 0);
  buf_t__put(out, "</div>");

  if (open && typeExplains(type)[0] != 0)
    buf_t__printf(out, "<p class='lead small'>%s</p>", typeExplains(type));

  /* what it is about */
  buf_t__put(out, "<dl class=facts>");

  if (p.get("vm_uuid").text()[0] != 0 || p.get("vm_name").text()[0] != 0) {
    /* a request about a VM that exists names it by UUID only: the name is in its binding */
    char vmDisk[64], name[128] = "";
    text_t vd = TEXT`vm-${p.get("vm_uuid").text()}`;
    vd.into(vmDisk, sizeof vmDisk);
    if (p.get("vm_name").text()[0] == 0 && isDiskId(vmDisk)) {
      bao_entry_t att = storeGet("attachments", vmDisk);
      if (att.found) {
        text_t n = TEXT`${att.payload().get("vm_name").text()}`;
        n.into(name, sizeof name);
      }
      att.release();
    }
    buf_t__put(out, "<dt>VM</dt><dd><b>");
    buf_t__html(out, p.get("vm_name").text()[0] != 0 ? p.get("vm_name").text()
                     : name[0] != 0                  ? name
                                                     : "ohne Namen");
    buf_t__put(out, "</b><div class=sub><code>");
    buf_t__html(out, p.get("vm_uuid").text());
    buf_t__put(out, "</code></div></dd>");
  }

  const char *disk = p.get("disk_id").text();
  if (disk[0] == 0 && strcmp(type, "create") == 0 && isUuid(p.get("vm_uuid").text()))
    buf_t__put(out, "<dt>Disk</dt><dd>Systemdisk der VM <span class=mut>(heißt nach ihr)</span></dd>");
  else if (disk[0] != 0) {
    buf_t__put(out, "<dt>Disk</dt><dd><code>");
    buf_t__html(out, disk);
    buf_t__printf(out, "</code> <span class=mut>%s</span></dd>",
                  strncmp(disk, "vm-", 3) == 0 ? "Systemdisk" : "Volume");
  }

  if (p.get("chip_id").text()[0] != 0) {
    buf_t__put(out, "<dt>Host</dt><dd>");
    chipLabel(out, settings, p.get("chip_id").text(), p.get("hv_uuid").text());
    buf_t__put(out, "</dd>");
  }

  if (p.get("report_id").text()[0] != 0) {
    buf_t__put(out, "<dt>Instanz</dt><dd><code>");
    shortHtml(out, p.get("report_id").text(), 16);
    buf_t__put(out, "</code> <span class=mut>SNP REPORT_ID</span></dd>");
  }

  blob_t userData = blobOf(p.get("files").get("user-data"));
  if (userData.length > 0)
    sshKeys(out, userData.at, settings);
  free(userData.at);

  buf_t__put(out, "</dl>");

  /* what needs a look: failed checks, remarks, the reason it ended so */
  if (failures > 0 || remarks > 0 || reason[0] != 0) {
    buf_t__put(out, "<ul class=notes>");
    for (int i = 0; i < checks.count(); ++i) {
      json_t c = checks.at(i);
      bool remark = strcmp(c.at(0).kind(), "null") == 0;
      if (!remark && c.at(0).truth())
        continue;
      buf_t__printf(out, "<li class=%s><span>", remark ? "warn" : "bad");
      deHtml(out, c.at(1).text());
      buf_t__put(out, "</span></li>");
    }
    if (reason[0] != 0 && strcmp(reason, "denied by the customer") != 0) {
      buf_t__put(out, "<li class=bad><span>");
      deHtml(out, reason);
      buf_t__put(out, "</span></li>");
    }
    buf_t__put(out, "</ul>");
  }

  if (passed > 0) {
    buf_t__printf(out, "<details><summary>%d Prüfung%s bestanden</summary><ul class=passed>", passed,
                  passed == 1 ? "" : "en");
    for (int i = 0; i < checks.count(); ++i) {
      json_t c = checks.at(i);
      if (strcmp(c.at(0).kind(), "null") == 0 || !c.at(0).truth())
        continue;
      buf_t__put(out, "<li>");
      deHtml(out, c.at(1).text());
      buf_t__put(out, "</li>");
    }
    buf_t__put(out, "</ul></details>");
  }

  /* what the provider sent, as it sent it */
  blob_t initdata = blobOf(p.get("initdata"));
  json_t files = p.get("files");
  if (initdata.length > 0 || files.count() > 0) {
    buf_t__put(out, "<details><summary>Was der Provider geschickt hat</summary>");
    if (initdata.length > 0) {
      char hd[65];
      sha256Hex(initdata.at, (size_t)initdata.length, hd);
      buf_t__printf(out, "<div class=file><b>initdata · HOST_DATA <code>%.16s…</code></b><pre>", hd);
      buf_t__html(out, initdata.at);
      buf_t__put(out, "</pre></div>");
    }
    for (int i = 0; i < files.count(); ++i)
      fileBlock(out, files.keyAt(i), files.at(i));
    buf_t__put(out, "</details>");
  }
  free(initdata.at);

  if (actions && strcmp(status, "pending") == 0) {
    buf_t__put(out, "<form method=post action='/decide' class=req-a>");
    formFields(out, req);
    buf_t__printf(out, "<input type=hidden name=id value='%ld'><span class=hint>%s</span>"
                       "<button class='btn dan' name=decision value=deny>Ablehnen</button>"
                       "<button class='btn %s' name=decision value=approve>%s</button></form>",
                  id,
                  destroys(type)  ? "Danach sind die Daten endgültig unlesbar."
                  : remarks > 0   ? "Bitte die Hinweise oben prüfen."
                                  : "Freigeben setzt die Anfrage sofort um.",
                  destroys(type) ? "danger" : "pri",
                  destroys(type) ? "Endgültig freigeben" : remarks > 0 ? "Trotzdem freigeben" : "Freigeben");
  }

  /* a worker that died while deciding leaves it here; give it back */
  if (actions && strcmp(status, "deciding") == 0) {
    buf_t__put(out, "<form method=post action='/undecided' class=req-a>");
    formFields(out, req);
    buf_t__printf(out, "<input type=hidden name=id value='%ld'><span class=hint>Hängt das schon eine "
                       "Weile?</span><button class=btn>Erneut zur Freigabe stellen</button></form>", id);
  }

  buf_t__put(out, "</article>");

  p.release();
  checks.release();
}

static PGresult *requestRows(bool open) {

  sql_t q = open ? SQL`select id, extract(epoch from created)::INT8, type, payload::TEXT, status, reason,
                        checks::TEXT, decided_by, extract(epoch from decided)::INT8 from requests
                      where status in ('pending', 'deciding') order by id`
                 : SQL`select id, extract(epoch from created)::INT8, type, payload::TEXT, status, reason,
                        checks::TEXT, decided_by, extract(epoch from decided)::INT8 from requests
                      where status not in ('pending', 'deciding') order by id desc limit 300`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r != NULL && PQresultStatus(r) != PGRES_TUPLES_OK) {
    PQclear(r);
    return NULL;
  }

  return r;
}

static void emptyState(buf_t *out, const char *title, const char *text) {
  buf_t__printf(out, "<div class='card empty'><b>%s</b>%s</div>", title, text);
}

static http_response_t uiRequests(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  settings_t settings = settingsRead();
  PGresult *open = requestRows(true), *done = requestRows(false);
  int nOpen = open != NULL ? PQntuples(open) : 0, nDone = done != NULL ? PQntuples(done) : 0;

  /* the tabs: everything open, each kind, everything decided */
  tab_t list[REQ_GROUPS + 2];
  list[0] = (tab_t){"offen", "Offen", nOpen, true};
  for (int g = 0; g < REQ_GROUPS; ++g) {
    long n = 0;
    for (int i = 0; i < nOpen; ++i)
      n += groupOf(PQgetvalue(open, i, R_TYPE)) == g;
    list[g + 1] = (tab_t){reqGroups[g].key, reqGroups[g].label, n, true};
  }
  list[REQ_GROUPS + 1] = (tab_t){"verlauf", "Verlauf", 0, false};

  const char *tab = tabOf(req, list, REQ_GROUPS + 2);
  int g = -1;
  for (int i = 0; i < REQ_GROUPS; ++i)
    if (strcmp(reqGroups[i].key, tab) == 0)
      g = i;

  pageStart(&out, "Anfragen", "/");
  pageHead(&out, "Anfragen des Providers",
           "Was der Provider an deinen VMs und Disks ändern will. Alles, was einer VM einen Schlüssel "
           "gibt oder Daten vernichtet, braucht deine Freigabe, außer eine Regel unter Einstellungen "
           "erlaubt es.");
  tabs(&out, "/", tab, list, REQ_GROUPS + 2);

  if (open == NULL || done == NULL)
    buf_t__put(&out, "<ul class=notes><li class=bad><span>Die Datenbank ist nicht erreichbar, "
                     "Anfragen können gerade nicht angezeigt werden.</span></li></ul>");

  if (strcmp(tab, "offen") == 0) {

    for (int i = 0; i < nOpen; ++i)
      requestCard(&out, req, open, i, &settings, true);

    if (open != NULL && nOpen == 0)
      emptyState(&out, "Nichts zu entscheiden",
                 "Sobald der Provider etwas anfragt, das deine Freigabe braucht, steht es hier.");

  } else if (g >= 0) {

    buf_t__printf(&out, "<p class=lead>%s</p>", reqGroups[g].lead);

    int shown = 0;
    for (int i = 0; i < nOpen; ++i)
      if (groupOf(PQgetvalue(open, i, R_TYPE)) == g) {
        if (shown++ == 0)
          buf_t__put(&out, "<h2 class=section>Offen</h2>");
        requestCard(&out, req, open, i, &settings, true);
      }

    int past = 0;
    for (int i = 0; i < nDone && past < 50; ++i)
      if (groupOf(PQgetvalue(done, i, R_TYPE)) == g) {
        if (past++ == 0)
          buf_t__put(&out, "<h2 class=section>Erledigt</h2>");
        requestCard(&out, req, done, i, &settings, false);
      }

    if (shown == 0 && past == 0)
      emptyState(&out, "Noch keine Anfragen dieser Art", "");

  } else {

    for (int i = 0; i < nDone && i < 50; ++i)
      requestCard(&out, req, done, i, &settings, false);

    if (done != NULL && nDone == 0)
      emptyState(&out, "Noch nichts entschieden", "Erledigte Anfragen erscheinen hier, die neuesten zuerst.");
    else if (nDone > 50)
      buf_t__put(&out, "<p class='mut small'>Die 50 neuesten. Ältere stehen in der Datenbank "
                       "(Tabelle requests) und über die API.</p>");
  }

  if (open != NULL)
    PQclear(open);
  if (done != NULL)
    PQclear(done);
  settings.release();

  return pageEnd(req, &out);
}

/* ------------------------------------------------------------------ disks */

static const char *const modes[][3] = {
    {"always", "Immer", "Jede neue Instanz bekommt den Schlüssel, wenn alle Prüfungen stimmen."},
    {"window", "Nur im Zeitfenster", "Außerhalb des Fensters wartet eine neue Instanz auf deine Bestätigung."},
    {"confirm", "Nur nach Bestätigung", "Jede neue Instanz wartet, bis du sie unter Anfragen freigibst."}};

static void diskRow(buf_t *out, http_request_t *req, const char *id, settings_t *settings, bool system) {

  bao_entry_t disk = storeGet("disks", id);
  bao_entry_t att = storeGet("attachments", id);
  json_t d = disk.payload(), a = att.payload();
  const char *status = disk.found ? d.get("status").text() : "?";
  const char *mode = d.get("mode").text();
  int m = 0;

  for (int i = 0; i < 3; ++i)
    if (strcmp(modes[i][0], mode) == 0)
      m = i;

  /* a system disk is named by its VM: shown as the VM, with the disk below */
  if (system) {
    buf_t__put(out, "<tr><td><b>");
    buf_t__html(out, att.found && a.get("vm_name").text()[0] != 0 ? a.get("vm_name").text() : "ohne Namen");
    buf_t__put(out, "</b><div class=sub><code>");
    buf_t__html(out, id);
    buf_t__put(out, "</code></div>");
  } else {
    buf_t__put(out, "<tr><td><code>");
    buf_t__html(out, id);
    buf_t__put(out, "</code>");
  }
  if (d.get("created").number() > 0) {
    buf_t__put(out, "<div class=sub>angelegt ");
    when(out, d.get("created").number(), "%d.%m.%Y");
    buf_t__put(out, "</div>");
  }
  if (strcmp(status, "deleted") == 0)
    buf_t__put(out, "<span class='pill bad'>gelöscht</span>");
  else if (strcmp(status, "active") != 0) {
    buf_t__put(out, "<span class='pill warn'>");
    buf_t__html(out, status);
    buf_t__put(out, "</span>");
  } else if (system && !att.found)
    buf_t__put(out, "<span class='pill warn'>VM gelöscht</span>");
  buf_t__put(out, "</td><td>");

  if (!system) {
    if (att.found) {
      buf_t__put(out, "<b>");
      buf_t__html(out, a.get("vm_name").text()[0] != 0 ? a.get("vm_name").text() : "ohne Namen");
      buf_t__put(out, "</b><div class=sub><code>");
      buf_t__html(out, a.get("vm_uuid").text());
      buf_t__put(out, "</code></div>");
    } else {
      buf_t__put(out, "<span class=mut>an keiner VM</span><div class=sub>Der Schlüssel geht an niemanden.</div>");
    }
    buf_t__put(out, "</td><td>");
  }

  json_t chips = a.get("chip_ids");
  for (int i = 0; att.found && i < chips.count(); ++i) {
    buf_t__put(out, i > 0 ? "<div class=host>" : "<div>");
    chipLabel(out, settings, chips.at(i).text(), NULL);
    buf_t__put(out, "</div>");
  }
  if (!att.found || chips.count() <= 0)
    buf_t__put(out, "<span class=mut>–</span>");

  buf_t__put(out, "</td><td>");

  if (strcmp(status, "active") == 0) {
    buf_t__printf(out, "<b>%s</b>", modes[m][1]);
    if (m == 1) {
      buf_t__put(out, "<div class=sub>");
      buf_t__html(out, d.get("window").text());
      buf_t__put(out, "</div>");
    }
    if (d.get("replay_interval").number() > 0)
      buf_t__printf(out, "<div class=sub>Replay-Stand alle %ld s</div>", d.get("replay_interval").number());

    buf_t__put(out, "<details><summary>Ändern</summary><form method=post action='/mode'>");
    formFields(out, req);
    buf_t__put(out, "<input type=hidden name=disk value='");
    buf_t__html(out, id);
    buf_t__put(out, "'><div class=row><select name=mode aria-label='Wann entsperren'>");
    for (int i = 0; i < 3; ++i)
      buf_t__printf(out, "<option value=%s%s>%s</option>", modes[i][0], i == m ? " selected" : "",
                    modes[i][1]);
    buf_t__put(out, "</select><input type=text name=window placeholder='Mo-Fr 06:00-22:00' size=16 "
                    "aria-label='Zeitfenster' value='");
    buf_t__html(out, d.get("window").text());
    buf_t__printf(out, "'></div><div class=row><label class=small title='Neuer Replay-Stand auch im "
                       "laufenden Betrieb, alle n Sekunden (0: nur beim Booten)'>Replay-Stand alle "
                       "<input type=number min=0 name=replay_interval size=6 value='%ld'> s</label>"
                       "<button class='btn sm pri'>Speichern</button></div></form></details>",
                  d.get("replay_interval").number());
  }

  buf_t__put(out, "</td></tr>");

  disk.release();
  att.release();
}

static void diskTable(buf_t *out, http_request_t *req, json_t ids, const char *prefix, settings_t *settings) {

  bool system = strcmp(prefix, "vm-") == 0;

  buf_t__put(out, system ? "<div class=tbl-wrap><table><thead><tr><th>VM</th><th>Hosts</th>"
                           "<th>Neue Instanz entsperren</th></tr></thead><tbody>"
                         : "<div class=tbl-wrap><table><thead><tr><th>Volume</th><th>An VM</th><th>Hosts</th>"
                           "<th>Neue Instanz entsperren</th></tr></thead><tbody>");

  for (int i = 0; i < ids.count(); ++i)
    if (isDiskId(ids.at(i).text()) && strncmp(ids.at(i).text(), prefix, strlen(prefix)) == 0)
      diskRow(out, req, ids.at(i).text(), settings, system);

  buf_t__put(out, "</tbody></table></div>");
}

static int countPrefix(json_t ids, const char *prefix) {

  int n = 0;

  for (int i = 0; i < ids.count(); ++i)
    n += isDiskId(ids.at(i).text()) && strncmp(ids.at(i).text(), prefix, strlen(prefix)) == 0;

  return n;
}

/** The VM a disk belongs to, by name, or the disk ID cut short. */
static void diskOwner(buf_t *out, const char *diskId) {

  bao_entry_t att = storeGet("attachments", diskId);

  if (att.found && att.payload().get("vm_name").text()[0] != 0) {
    buf_t__put(out, "<b>");
    buf_t__html(out, att.payload().get("vm_name").text());
    buf_t__put(out, "</b><div class=sub><code>");
    shortHtml(out, diskId, 15);
    buf_t__put(out, "</code></div>");
  } else {
    buf_t__put(out, "<code>");
    shortHtml(out, diskId, 15);
    buf_t__put(out, "</code>");
  }

  att.release();
}

static void leaseTable(buf_t *out, http_request_t *req, settings_t *settings) {

  sql_t q = SQL`select disk_id, report_id, chip_id, extract(epoch from expires)::INT8,
      expires > now(), extract(epoch from first_seen)::INT8 from leases order by expires desc`;
  PGresult *r = dbAsk(&q);
  q.release();

  buf_t__put(out, "<div class=card><h2>Laufende Instanzen</h2><p class=lead>Pro Disk bekommt nur eine "
                  "laufende Instanz einer VM (erkannt an ihrer SNP REPORT_ID) den Schlüssel. Die Lease "
                  "verlängert sich, solange sie läuft. Nach einem Absturz läuft sie von selbst ab, oder du "
                  "gibst sie hier sofort frei.</p>");

  int n = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK ? PQntuples(r) : 0;

  if (n == 0) {
    buf_t__put(out, "<div class=empty><b>Keine laufenden Instanzen</b></div></div>");
    if (r != NULL)
      PQclear(r);
    return;
  }

  buf_t__put(out, "<div class=tbl-wrap><table><thead><tr><th>VM / Disk</th><th>Instanz</th><th>Host</th>"
                  "<th>Lease</th><th></th></tr></thead><tbody>");

  for (int i = 0; i < n; ++i) {
    bool live = PQgetvalue(r, i, 4)[0] == 't';
    buf_t__put(out, "<tr><td>");
    diskOwner(out, PQgetvalue(r, i, 0));
    buf_t__put(out, "</td><td><code>");
    shortHtml(out, PQgetvalue(r, i, 1), 16);
    buf_t__put(out, "</code><div class=sub>läuft seit ");
    when(out, atol(PQgetvalue(r, i, 5)), "%d.%m. %H:%M");
    buf_t__put(out, "</div></td><td>");
    chipLabel(out, settings, PQgetvalue(r, i, 2), NULL);
    buf_t__put(out, "</td><td>");
    if (live) {
      buf_t__put(out, "<span class='pill ok'>aktiv</span><div class=sub>bis ");
      when(out, atol(PQgetvalue(r, i, 3)), "%H:%M:%S");
      buf_t__put(out, "</div>");
    } else {
      buf_t__put(out, "<span class=pill>abgelaufen</span>");
    }
    buf_t__put(out, "</td><td><form method=post action='/lease'>");
    formFields(out, req);
    buf_t__put(out, "<input type=hidden name=disk value='");
    buf_t__html(out, PQgetvalue(r, i, 0));
    buf_t__put(out, "'><button class='btn sm dan'>Freigeben</button></form></td></tr>");
  }

  buf_t__put(out, "</tbody></table></div></div>");
  PQclear(r);
}

static void vtpmRow(buf_t *out, http_request_t *req, const char *hd) {

  bao_entry_t v = storeGet("vtpm", hd);
  replay_t stand = storeReplay(hd);
  json_t e = v.payload();

  if (!v.found || !isHex(hd, 64)) {
    v.release();
    return;
  }

  buf_t__put(out, "<tr><td><b>");
  buf_t__html(out, e.get("vm_name").text()[0] != 0 ? e.get("vm_name").text() : "ohne Namen");
  buf_t__put(out, "</b><div class=sub><code>");
  buf_t__html(out, e.get("vm_uuid").text());
  buf_t__put(out, "</code></div></td><td><code>");
  buf_t__html(out, e.get("disk_id").text());
  buf_t__printf(out, "</code><div class=sub>HOST_DATA <code>%.16s…</code></div></td><td>", hd);

  const char *ek = e.get("ek").text();

  if (ek[0] != 0) {
    buf_t__put(out, "<span class='pill ok'>gebunden</span><div class=sub>EK <code>");
    shortHtml(out, ek, 16);
    buf_t__put(out, "</code> seit ");
    when(out, e.get("ek_first").number(), "%d.%m.%Y");
    buf_t__put(out, "</div>");
    if (stand.found)
      buf_t__printf(out, "<div class=sub>Replay-Stand %ld</div>", stand.confirmed);
    buf_t__put(out, "</td><td><form method=post action='/vtpm-reset'>");
    formFields(out, req);
    buf_t__printf(out, "<input type=hidden name=host_data value='%s'><button class='btn sm dan'>"
                       "Bindung lösen</button></form>", hd);
  } else {
    buf_t__put(out, "<span class=pill>noch nicht gebunden</span><div class=sub>beim ersten Start der VM</div>"
                    "</td><td>");
  }

  buf_t__put(out, "</td></tr>");
  v.release();
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

  long live = 0;
  {
    sql_t q = SQL`select count(*) from leases where expires > now()`;
    PGresult *r = dbAsk(&q);
    q.release();
    if (r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK)
      live = atol(PQgetvalue(r, 0, 0));
    if (r != NULL)
      PQclear(r);
  }

  tab_t list[] = {{"disks", "Disks", (long)(countPrefix(ids, "vm-") + countPrefix(ids, "vol-")), false},
                  {"instanzen", "Laufende Instanzen", live, false},
                  {"vtpm", "vTPM", 0, false}};
  const char *tab = tabOf(req, list, 3);

  pageStart(&out, "Disks & VMs", "/disks");
  pageHead(&out, "Disks &amp; VMs",
           "Jede Disk hat einen eigenen Schlüssel in deinem OpenBao. Er geht nur an die VM, an die sie "
           "gebunden ist, auf Hosts, die du freigegeben hast, mit einer Bootkette, die du kennst.");
  tabs(&out, "/disks", tab, list, 3);

  if (failed)
    buf_t__put(&out, "<ul class=notes><li class=bad><span>OpenBao ist nicht erreichbar, die Disks "
                     "können gerade nicht angezeigt werden.</span></li></ul>");

  if (strcmp(tab, "disks") == 0) {

    int system = countPrefix(ids, "vm-"), volumes = countPrefix(ids, "vol-");

    buf_t__put(&out, "<div class=card><h2>Systemdisks</h2><p class=lead>Die Hauptdisk einer VM. Sie heißt "
                     "nach ihrer VM und gehört nur zu ihr.</p>");
    if (system > 0)
      diskTable(&out, req, ids, "vm-", &settings);
    else
      buf_t__put(&out, "<div class=empty>Noch keine.</div>");
    buf_t__put(&out, "</div>");

    buf_t__put(&out, "<div class=card><h2>Volumes</h2><p class=lead>Datenträger mit eigener ID. Sie können "
                     "von VM zu VM wandern, jedes Anhängen braucht eine Anfrage.</p>");
    if (volumes > 0)
      diskTable(&out, req, ids, "vol-", &settings);
    else
      buf_t__put(&out, "<div class=empty>Noch keine.</div>");
    buf_t__put(&out, "</div>");

  } else if (strcmp(tab, "instanzen") == 0) {

    leaseTable(&out, req, &settings);

  } else {

    json_t vtpms = baoList("vtpm/", &failed);
    json_t hds = vtpms.get("data").get("keys");

    buf_t__put(&out, "<div class=card><h2>Persistenter vTPM</h2><p class=lead>Der Zustand des vTPM einer VM "
                     "ist mit einem Schlüssel verschlüsselt, der nur hier liegt und nur an den SVSM genau "
                     "dieser VM geht. Beim ersten Abruf wird sein Endorsement Key (EK) gebunden: meldet sich "
                     "die VM später mit einem anderen vTPM, etwa nach verlorenem Zustand, bekommt sie keinen "
                     "Disk-Schlüssel, bis du die Bindung löst. Ein zurückgespielter, älterer Zustand fällt am "
                     "Replay-Stand auf.</p>");

    if (hds.count() > 0) {
      buf_t__put(&out, "<div class=tbl-wrap><table><thead><tr><th>VM</th><th>Disk</th><th>EK</th><th></th>"
                       "</tr></thead><tbody>");
      for (int i = 0; i < hds.count(); ++i)
        vtpmRow(&out, req, hds.at(i).text());
      buf_t__put(&out, "</tbody></table></div>");
    } else {
      buf_t__put(&out, "<div class=empty>Noch keine VM mit persistentem vTPM.</div>");
    }

    buf_t__put(&out, "</div>");
    vtpms.release();
  }

  disks.release();
  settings.release();

  return pageEnd(req, &out);
}

/* -------------------------------------------------------- the release log */

static const char *stepLabel(const char *step) {
  return strcmp(step, "challenge") == 0 ? "Anmeldung"
         : strcmp(step, "attest") == 0  ? "Attestierung"
         : strcmp(step, "release") == 0 ? "Schlüsselabruf"
                                        : step;
}

/** The PCR 4/8/9 of a boot chain, cut short. */
static void chainShort(buf_t *out, const char *p4, const char *p8, const char *p9) {
  buf_t__printf(out, "<div class=chain><span>PCR 4</span><code>%.16s…</code><span>PCR 8</span>"
                     "<code>%.16s…</code><span>PCR 9</span><code>%.16s…</code></div>", p4, p8, p9);
}

static http_response_t uiLog(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  long refused = 0;
  {
    sql_t q = SQL`select count(*) from releases where not ok and ts > now() - interval '24 hours'`;
    PGresult *r = dbAsk(&q);
    q.release();
    if (r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK)
      refused = atol(PQgetvalue(r, 0, 0));
    if (r != NULL)
      PQclear(r);
  }

  tab_t list[] = {{"alle", "Alle", 0, false}, {"abgelehnt", "Abgelehnt (24 h)", refused, true}};
  const char *tab = tabOf(req, list, 2);
  bool onlyRefused = strcmp(tab, "abgelehnt") == 0;

  sql_t q = onlyRefused ? SQL`select extract(epoch from ts)::INT8, disk_id, step, ok, detail, ctx->'pcrs'
                              from releases where not ok and ts > now() - interval '24 hours'
                              order by id desc limit 100`
                        : SQL`select extract(epoch from ts)::INT8, disk_id, step, ok, detail, ctx->'pcrs'
                              from releases order by id desc limit 100`;
  PGresult *r = dbAsk(&q);
  q.release();

  pageStart(&out, "Protokoll", "/log");
  pageHead(&out, "Protokoll der Schlüsselabrufe",
           "Jeder Versuch einer VM, ihren Schlüssel zu bekommen: wer, wann, und warum es nicht geklappt hat.");
  tabs(&out, "/log", tab, list, 2);

  int n = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK ? PQntuples(r) : 0;

  if (r == NULL || PQresultStatus(r) != PGRES_TUPLES_OK)
    buf_t__put(&out, "<ul class=notes><li class=bad><span>Die Datenbank ist nicht erreichbar.</span></li></ul>");
  else if (n == 0)
    emptyState(&out, onlyRefused ? "Nichts abgelehnt" : "Noch keine Abrufe",
               onlyRefused ? "In den letzten 24 Stunden wurde kein Abruf abgewiesen." : "");
  else {
    buf_t__put(&out, "<div class=card><div class=tbl-wrap><table><thead><tr><th>Zeit</th><th>VM / Disk</th>"
                     "<th>Schritt</th><th>Ergebnis</th></tr></thead><tbody>");

    for (int i = 0; i < n; ++i) {

      bool ok = PQgetvalue(r, i, 3)[0] == 't';
      const char *detail = PQgetvalue(r, i, 4);

      /* the same again and again (a VM retrying every few minutes): one row */
      int same = i;
      while (same + 1 < n && strcmp(PQgetvalue(r, same + 1, 1), PQgetvalue(r, i, 1)) == 0 &&
             strcmp(PQgetvalue(r, same + 1, 2), PQgetvalue(r, i, 2)) == 0 &&
             strcmp(PQgetvalue(r, same + 1, 3), PQgetvalue(r, i, 3)) == 0 &&
             strcmp(PQgetvalue(r, same + 1, 4), detail) == 0)
        ++same;

      buf_t__printf(&out, "<tr%s><td class=mono>", ok ? "" : " class=refused");
      when(&out, atol(PQgetvalue(r, i, 0)), "%d.%m. %H:%M:%S");
      if (same > i) {
        buf_t__put(&out, "<div class=sub>seit ");
        when(&out, atol(PQgetvalue(r, same, 0)), "%d.%m. %H:%M");
        buf_t__put(&out, "</div>");
      }
      buf_t__put(&out, "</td><td>");
      if (PQgetvalue(r, i, 1)[0] != 0)
        diskOwner(&out, PQgetvalue(r, i, 1));
      else
        buf_t__put(&out, "<span class=mut>–</span>");
      buf_t__printf(&out, "</td><td>%s</td><td>", stepLabel(PQgetvalue(r, i, 2)));
      buf_t__printf(&out, "<span class='pill %s'>%s</span>", ok ? "ok" : "bad", ok ? "ok" : "abgewiesen");
      if (same > i)
        buf_t__printf(&out, " <span class=%s>%d×</span>", ok ? "mut" : "times", same - i + 1);
      buf_t__put(&out, "<div>");
      deHtml(&out, detail);
      buf_t__put(&out, "</div>");

      /* a refused boot chain: show it, and where to approve it */
      if (!ok && strncmp(detail, "boot chain", 10) == 0 && !PQgetisnull(r, i, 5)) {
        json_t pcrs = meta_toJSON(PQgetvalue(r, i, 5));
        const char *p4 = pcrs.get("4").text(), *p8 = pcrs.get("8").text(), *p9 = pcrs.get("9").text();
        if (isHex(p4, 64) && isHex(p8, 64) && isHex(p9, 64)) {
          chainShort(&out, p4, p8, p9);
          buf_t__put(&out, "<div class=sub><a href='/settings?tab=bootketten'>Unter Einstellungen → "
                           "Bootketten prüfen und freigeben</a></div>");
        }
        pcrs.release();
      }

      buf_t__put(&out, "</td></tr>");
      i = same;
    }

    buf_t__put(&out, "</tbody></table></div></div>");
  }

  if (r != NULL)
    PQclear(r);

  return pageEnd(req, &out);
}

/* --------------------------------------------------------------- settings */

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
static PGresult *refusedChainRows(void) {

  sql_t q = SQL`select ctx->'pcrs'->>'4', ctx->'pcrs'->>'8', ctx->'pcrs'->>'9', count(*),
      extract(epoch from max(ts))::INT8, min(disk_id), count(distinct disk_id)
    from releases
    where not ok and detail like 'boot chain%' and ts > now() - interval '7 days'
      and length(ctx->'pcrs'->>'9') = 64
    group by 1, 2, 3 order by 5 desc limit 20`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r != NULL && PQresultStatus(r) != PGRES_TUPLES_OK) {
    PQclear(r);
    return NULL;
  }

  return r;
}

static bool refusedRowOpen(PGresult *r, int i, settings_t *settings) {

  const char *p4 = PQgetvalue(r, i, 0), *p8 = PQgetvalue(r, i, 1), *p9 = PQgetvalue(r, i, 2);

  return isHex(p4, 64) && isHex(p8, 64) && isHex(p9, 64) && !chainApproved(settings, p4, p8, p9);
}

static void refusedChains(buf_t *out, http_request_t *req, PGresult *r, settings_t *settings) {

  buf_t__put(out, "<div class=card><h2>Abgelehnte Bootketten</h2><p class=lead>VMs der letzten 7 Tage, "
                  "die mit einer Bootkette starten wollten, die du noch nicht freigegeben hast, etwa nach "
                  "einem Kernel-Update in der VM. Erst freigeben, wenn du weißt, warum sie sich geändert hat.</p>");

  int shown = 0;

  for (int i = 0; r != NULL && i < PQntuples(r); ++i) {

    if (!refusedRowOpen(r, i, settings))
      continue;

    const char *p4 = PQgetvalue(r, i, 0), *p8 = PQgetvalue(r, i, 1), *p9 = PQgetvalue(r, i, 2);
    long disks = atol(PQgetvalue(r, i, 6));

    buf_t__put(out, shown > 0 ? "<div class='req-a'>" : "<div>");
    buf_t__put(out, "<div class=row><div>");
    diskOwner(out, PQgetvalue(r, i, 5));
    if (disks > 1)
      buf_t__printf(out, "<div class=sub>und %ld weitere Disks</div>", disks - 1);
    buf_t__printf(out, "<div class=sub>%s Versuche, zuletzt ", PQgetvalue(r, i, 3));
    when(out, atol(PQgetvalue(r, i, 4)), "%d.%m. %H:%M");
    buf_t__put(out, "</div></div></div>");
    chainShort(out, p4, p8, p9);
    buf_t__put(out, "<form method=post action='/pcr-ref' class=bar>");
    formFields(out, req);
    buf_t__printf(out, "<input type=hidden name=p4 value='%s'><input type=hidden name=p8 value='%s'>"
                       "<input type=hidden name=p9 value='%s'><button class='btn pri sm'>Diese Bootkette "
                       "freigeben</button></form></div>", p4, p8, p9);
    ++shown;
  }

  if (shown == 0)
    buf_t__put(out, "<div class=empty><b>Keine</b>Alle Bootketten der letzten 7 Tage sind freigegeben.</div>");

  buf_t__put(out, "</div>");
}

static void approvedChains(buf_t *out, http_request_t *req, settings_t *settings) {

  json_t refs = settings->data.get("pcr_refs");

  buf_t__put(out, "<div class=card><h2>Freigegebene Bootketten</h2><p class=lead>Bootloader, GRUB-Befehle "
                  "und Kernel/initrd der VMs, gemessen in PCR 4, 8 und 9 des vTPM. Nur VMs mit einer dieser "
                  "Ketten bekommen ihren Disk-Schlüssel.</p>");

  if (refs.count() <= 0) {
    buf_t__put(out, "<div class=empty><b>Keine</b>Ohne freigegebene Bootkette prüft der Agent die Kette "
                    "nicht.</div></div>");
    return;
  }

  buf_t__put(out, "<div class=tbl-wrap><table><thead><tr><th>Bezeichnung</th><th>Werte</th><th></th></tr>"
                  "</thead><tbody>");

  for (int i = 0; i < refs.count(); ++i) {
    json_t r = refs.at(i);
    const char *p4 = r.get("4").text(), *p8 = r.get("8").text(), *p9 = r.get("9").text();
    bool whole = isHex(p4, 64) && isHex(p8, 64) && isHex(p9, 64);

    buf_t__put(out, "<tr><td>");
    buf_t__html(out, r.get("label").text()[0] != 0 ? r.get("label").text() : "ohne Bezeichnung");
    buf_t__put(out, "</td><td>");
    if (whole)
      chainShort(out, p4, p8, p9);
    else
      buf_t__put(out, "<span class=warn>unvollständig</span>");
    buf_t__put(out, "</td><td>");
    if (whole) {
      buf_t__put(out, "<form method=post action='/pcr-ref-remove'>");
      formFields(out, req);
      buf_t__printf(out, "<input type=hidden name=p4 value='%s'><input type=hidden name=p8 value='%s'>"
                         "<input type=hidden name=p9 value='%s'><button class='btn sm dan'>Entfernen"
                         "</button></form>", p4, p8, p9);
    }
    buf_t__put(out, "</td></tr>");
  }

  buf_t__put(out, "</tbody></table></div></div>");
}

static http_response_t uiSettings(http_request_t *req) {

  if (req->localPort != apiPort)
    return req.reply(404).text("");
  if (!uiAuthorized(req))
    return uiLogin(req);

  buf_t out = {0};
  settings_t settings = settingsRead();
  json_t pool = settings.data.get("host_pool"), keys = settings.data.get("allowed_ssh_keys");
  PGresult *refused = refusedChainRows();
  long nRefused = 0;

  for (int i = 0; refused != NULL && i < PQntuples(refused); ++i)
    nRefused += refusedRowOpen(refused, i, &settings);

  tab_t list[] = {{"automatik", "Automatik", 0, false},
                  {"hosts", "Host-Pool", pool.count() > 0 ? pool.count() : 0, false},
                  {"keys", "SSH-Keys", keys.count() > 0 ? keys.count() : 0, false},
                  {"bootketten", "Bootketten", nRefused, true},
                  {"referenz", "Referenzwerte", 0, false}};
  const char *tab = tabOf(req, list, 5);

  pageStart(&out, "Einstellungen", "/settings");
  pageHead(&out, "Einstellungen",
           "Wem du vertraust: welchen Hosts, welchen SSH-Keys, welchen Bootketten. Daraus folgt, was der "
           "Agent ohne dich entscheiden darf.");
  tabs(&out, "/settings", tab, list, 5);

  if (settings.failed)
    buf_t__put(&out, "<ul class=notes><li class=bad><span>OpenBao ist nicht erreichbar, die Einstellungen "
                     "können gerade nicht gelesen werden.</span></li></ul>");

  if (strcmp(tab, "automatik") == 0) {

    buf_t__put(&out, "<form method=post action='/settings' class=card><h2>Was ohne dich geschehen darf</h2>"
                     "<p class=lead>Ohne Haken braucht jede dieser Anfragen deine Freigabe.</p>");
    formFields(&out, req);
    buf_t__printf(&out,
                  "<input type=hidden name=section value=auto>"
                  "<label class=check><input type=checkbox name=auto_attach%s><span><b>Volume an neue VM "
                  "hängen</b><span class=mut>wenn der Host im Pool ist und cloud-init nur Benutzer mit "
                  "bekannten SSH-Keys anlegt, ohne Befehle, Dateien oder Passwörter</span></span></label>"
                  "<label class=check><input type=checkbox name=auto_add_host%s><span><b>VM auf weiterem "
                  "Host erlauben</b><span class=mut>wenn der Host im Pool ist</span></span></label>"
                  "<div class=bar><button class='btn pri'>Speichern</button></div></form>",
                  settings.flag("auto_attach") ? " checked" : "",
                  settings.flag("auto_add_host") ? " checked" : "");

    buf_t__put(&out, "<div class=card><h2>Immer gleich</h2><ul class=notes>"
                     "<li class=ok><span>Neue VMs und Volumes werden sofort angelegt: sie haben noch keine "
                     "Daten. Auffälliges steht als Hinweis bei der Anfrage.</span></li>"
                     "<li class=ok><span>Eine gelöschte VM oder ein abgehängtes Volume verliert den Zugriff "
                     "sofort.</span></li>"
                     "<li class=warn><span>Neu installieren und Löschen vernichten Schlüssel und brauchen "
                     "immer deine Freigabe. Ein Provider kann so die Backups deiner Daten nicht unlesbar "
                     "machen.</span></li></ul></div>");

  } else if (strcmp(tab, "hosts") == 0) {

    buf_t__put(&out, "<div class=card><h2>Host-Pool</h2><p class=lead>Hosts des Providers, denen du "
                     "vertraust. Ein Host ist an seiner HV-UUID und der chip_id seines AMD-Prozessors "
                     "erkennbar; die chip_id kann er nicht fälschen, sie steckt im signierten Report.</p>");

    if (pool.count() > 0) {
      buf_t__put(&out, "<div class=tbl-wrap><table><thead><tr><th>Name</th><th>HV-UUID</th><th>chip_id</th>"
                       "</tr></thead><tbody>");
      for (int i = 0; i < pool.count(); ++i) {
        json_t h = pool.at(i);
        buf_t__put(&out, "<tr><td>");
        buf_t__html(&out, h.get("name").text()[0] != 0 ? h.get("name").text() : "–");
        buf_t__put(&out, "</td><td><code>");
        buf_t__html(&out, h.get("hv_uuid").text());
        buf_t__put(&out, "</code></td><td><code>");
        shortHtml(&out, h.get("chip_id").text(), 24);
        buf_t__put(&out, "</code></td></tr>");
      }
      buf_t__put(&out, "</tbody></table></div>");
    } else {
      buf_t__put(&out, "<div class=empty><b>Noch kein Host</b>Ohne Host im Pool wird nichts automatisch "
                       "freigegeben.</div>");
    }

    buf_t__put(&out, "<details><summary>Bearbeiten</summary><form method=post action='/settings'>");
    formFields(&out, req);
    buf_t__put(&out, "<input type=hidden name=section value=pool><p class='mut small'>Eine Zeile pro Host: "
                     "<code>&lt;HV-UUID&gt; &lt;chip_id&gt; [Name]</code>. Zeilen in anderer Form werden "
                     "verworfen.</p><textarea name=host_pool rows=6 spellcheck=false>");
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
    buf_t__put(&out, "</textarea><div class=bar><button class='btn pri'>Speichern</button></div>"
                     "</form></details></div>");

  } else if (strcmp(tab, "keys") == 0) {

    buf_t__put(&out, "<div class=card><h2>Bekannte SSH-Keys</h2><p class=lead>Wer einen Key in cloud-init "
                     "hat, kann sich nach dem Entsperren in die VM einloggen und die Daten lesen. Automatisch "
                     "freigegeben wird nur, wenn cloud-init ausschließlich diese Keys anlegt.</p>");

    if (keys.count() > 0) {
      buf_t__put(&out, "<div class=tbl-wrap><table><thead><tr><th>Key</th><th>Kommentar</th></tr></thead><tbody>");
      for (int i = 0; i < keys.count(); ++i) {
        const char *k = keys.at(i).text();
        char name[2048];
        keyName(k, name, sizeof name);
        const char *comment = strlen(k) > strlen(name) ? k + strlen(name) : "";
        while (*comment == ' ')
          ++comment;
        buf_t__put(&out, "<tr><td><code>");
        shortHtml(&out, name, 48);
        buf_t__put(&out, "</code></td><td>");
        buf_t__html(&out, comment[0] != 0 ? comment : "–");
        buf_t__put(&out, "</td></tr>");
      }
      buf_t__put(&out, "</tbody></table></div>");
    } else {
      buf_t__put(&out, "<div class=empty><b>Noch kein Key</b>Ohne bekannten Key wird nichts automatisch "
                       "angehängt.</div>");
    }

    buf_t__put(&out, "<details><summary>Bearbeiten</summary><form method=post action='/settings'>");
    formFields(&out, req);
    buf_t__put(&out, "<input type=hidden name=section value=keys><p class='mut small'>Eine Zeile pro Key, "
                     "wie in <code>authorized_keys</code>.</p><textarea name=allowed_ssh_keys rows=6 "
                     "spellcheck=false>");
    for (int i = 0; i < keys.count(); ++i) {
      buf_t__html(&out, keys.at(i).text());
      buf_t__put(&out, "\n");
    }
    buf_t__put(&out, "</textarea><div class=bar><button class='btn pri'>Speichern</button></div>"
                     "</form></details></div>");

  } else if (strcmp(tab, "bootketten") == 0) {

    refusedChains(&out, req, refused, &settings);
    approvedChains(&out, req, &settings);

  } else {

    buf_t measurements = {0};
    releaseMeasurements(&measurements, false);
    buf_t__put(&out, "<div class=card><h2>Referenzwerte des Providers</h2><p class=lead>Die Measurements "
                     "von Firmware und SVSM, die einen Schlüssel bekommen dürfen. Der Provider veröffentlicht "
                     "sie mit jedem Build; jede VM beweist sie mit ihrem von AMD signierten Report.</p><pre>");
    buf_t__html(&out, measurements.at != NULL && measurements.at[0] != 0 ? measurements.at : "keine");
    buf_t__put(&out, "</pre></div>");
    free(measurements.at);
  }

  if (refused != NULL)
    PQclear(refused);
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
    *refuse = req.reply(403).mime("text/plain; charset=utf-8").text("Ungültiges Formular. Bitte die Seite neu laden.");
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
  http_response_t back = uiBack(req, &form, "/");
  form.release();

  return back;
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
  http_response_t back = uiBack(req, &form, "/");
  form.release();

  return back;
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

  if (!isDiskId(disk) || !known || interval < 0 || (window[0] != 0 && inWindow(window, time(NULL)) < 0) ||
      (strcmp(mode, "window") == 0 && window[0] == 0)) {
    form.release();
    return req.reply(400)
        .mime("text/plain; charset=utf-8")
        .text("Das Zeitfenster bitte so angeben: 'Mo-Fr 06:00-22:00' oder '06:00-22:00'.");
  }

  storeSet("disks", disk, {mode: mode, window: window, replay_interval: interval});
  http_response_t back = uiBack(req, &form, "/disks");
  form.release();

  return back;
}

static http_response_t uiLease(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  if (isDiskId(form.get("disk")))
    storeResetLease(form.get("disk"));

  http_response_t back = uiBack(req, &form, "/disks?tab=instanzen");
  form.release();

  return back;
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

  http_response_t back = uiBack(req, &form, "/disks?tab=vtpm");
  form.release();

  return back;
}

static http_response_t uiPcrRef(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  char label[64] = "freigegeben ";
  time_t now = time(NULL);
  struct tm t;
  localtime_r(&now, &t);
  strftime(label + strlen(label), sizeof label - strlen(label), "%d.%m.%Y %H:%M", &t);

  pcr_ref_t ref = {{form.get("p4"), form.get("p8"), form.get("p9")}, label};

  if (isHex(ref.value[0], 64) && isHex(ref.value[1], 64) && isHex(ref.value[2], 64))
    baoEdit("settings", addPcrRef, &ref);

  http_response_t back = uiBack(req, &form, "/settings?tab=bootketten");
  form.release();

  return back;
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

  http_response_t back = uiBack(req, &form, "/settings?tab=bootketten");
  form.release();

  return back;
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

/** One tab's form at a time: only what that tab shows is written. */
static http_response_t uiSaveSettings(http_request_t *req) {

  form_t form;
  http_response_t no;

  if (!uiPost(req, &form, &no))
    return no;

  const char *section = form.get("section");
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, o);

  if (strcmp(section, "auto") == 0) {
    /* checkboxes only arrive when ticked */
    yyjson_mut_obj_add_bool(doc, o, "auto_attach", form.has("auto_attach"));
    yyjson_mut_obj_add_bool(doc, o, "auto_add_host", form.has("auto_add_host"));
  }

  if (strcmp(section, "pool") == 0) {
    yyjson_mut_val *pool = yyjson_mut_arr(doc);
    char *poolText = strdup(form.get("host_pool"));
    if (poolText != NULL)
      poolFrom(doc, pool, poolText);
    free(poolText);
    yyjson_mut_obj_add_val(doc, o, "host_pool", pool);
  }

  if (strcmp(section, "keys") == 0) {
    yyjson_mut_val *keys = yyjson_mut_arr(doc);
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
  }

  if (yyjson_mut_obj_size(o) > 0) {
    char *json = yyjson_mut_write(doc, 0, NULL);
    json_t patch = meta_toJSON(json);
    storeSet("settings", NULL, patch);
    patch.release();
    free(json);
  }

  yyjson_mut_doc_free(doc);
  http_response_t back = uiBack(req, &form, "/settings");
  form.release();

  return back;
}

static void uiRoutes(void) {
  http.get("/", uiRequests);
  http.get("/disks", uiDisks);
  http.get("/log", uiLog);
  http.get("/settings", uiSettings);
  http.get("/ui/:name", uiAsset);
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

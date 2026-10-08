/**
 * initdata.toml, read strictly.
 *
 * Only the shape the provider writes: `version` and `algorithm` at the top,
 * then `[data]` with `"key" = "value"` lines, blank lines between. Anything
 * else - another table, escapes, a key twice - is refused rather than read
 * the way some other TOML reader might read it: what the guest checks and
 * what this agent approves have to be the same text.
 */
#ifndef WX_INITDATA_H
#define WX_INITDATA_H

#include "util.h"

#include <meta_text.h>

#define INITDATA_PAIRS 32

typedef struct {
  char key[INITDATA_PAIRS][96];
  char value[INITDATA_PAIRS][512];
  int count;
  char why[160];
} initdata_t;

/** A quoted string without escapes at `*at`; moves past it. */
static bool initdataQuoted(const char **at, const char *end, char *into, size_t room) {

  const char *p = *at;
  size_t n = 0;

  if (p >= end || *p != '"')
    return false;

  for (++p; p < end && *p != '"'; ++p) {
    if (*p == '\\' || (unsigned char)*p < 0x20 || n + 1 >= room)
      return false;
    into[n++] = *p;
  }

  if (p >= end)
    return false;

  into[n] = 0;
  *at = p + 1;

  return true;
}

static void initdataSkipBlanks(const char **at, const char *end) {
  while (*at < end && (**at == ' ' || **at == '\t'))
    ++*at;
}

static bool initdataRefuse(initdata_t *self, int line, const char *what) {

  text_t why = TEXT`line ${line}: ${what}`;
  why.into(self->why, sizeof self->why);

  return false;
}

static bool initdata_t__parse(initdata_t *self, const char *text, size_t length) {

  const char *at = text, *end = text + length;
  bool inData = false;
  int line = 0;

  self->count = 0;
  self->why[0] = 0;

  if (memchr(text, 0, length) != NULL)
    return initdataRefuse(self, 0, "contains a NUL byte");

  while (at < end) {

    const char *eol = (const char *)memchr(at, '\n', (size_t)(end - at));
    const char *stop = eol != NULL ? eol : end;
    char key[96], value[512];

    ++line;

    if (stop > at && stop[-1] == '\r')
      return initdataRefuse(self, line, "carriage return");

    initdataSkipBlanks(&at, stop);

    if (at == stop) {
      /* blank */
    } else if (!inData && (size_t)(stop - at) == 6 && memcmp(at, "[data]", 6) == 0) {
      inData = true;
    } else {
      const char *k = at;

      if (inData) {
        if (!initdataQuoted(&at, stop, key, sizeof key))
          return initdataRefuse(self, line, "expected \"key\" = \"value\"");
      } else {
        while (at < stop && ((*at >= 'a' && *at <= 'z') || *at == '_'))
          ++at;
        if (at == k || (size_t)(at - k) >= sizeof key)
          return initdataRefuse(self, line, "expected a key");
        memcpy(key, k, (size_t)(at - k));
        key[at - k] = 0;
        if (strcmp(key, "version") != 0 && strcmp(key, "algorithm") != 0)
          return initdataRefuse(self, line, "unknown key before [data]");
      }

      initdataSkipBlanks(&at, stop);

      if (at >= stop || *at != '=')
        return initdataRefuse(self, line, "expected =");

      ++at;
      initdataSkipBlanks(&at, stop);

      if (!initdataQuoted(&at, stop, value, sizeof value))
        return initdataRefuse(self, line, "expected a quoted value without escapes");

      initdataSkipBlanks(&at, stop);

      if (at != stop)
        return initdataRefuse(self, line, "something after the value");

      if (inData) {
        for (int i = 0; i < self->count; ++i)
          if (strcmp(self->key[i], key) == 0)
            return initdataRefuse(self, line, "key given twice");

        if (self->count == INITDATA_PAIRS)
          return initdataRefuse(self, line, "too many keys");

        memcpy(self->key[self->count], key, sizeof key);
        memcpy(self->value[self->count], value, sizeof value);
        ++self->count;
      } else if (strcmp(key, "algorithm") == 0 && strcmp(value, "sha256") != 0) {
        return initdataRefuse(self, line, "algorithm is not sha256");
      }
    }

    at = eol != NULL ? eol + 1 : end;
  }

  if (!inData)
    return initdataRefuse(self, line, "no [data]");

  return true;
}

/** The value under `key` in [data], or NULL. */
static const char *initdata_t__get(initdata_t *self, const char *key) {

  for (int i = 0; i < self->count; ++i)
    if (strcmp(self->key[i], key) == 0)
      return self->value[i];

  return NULL;
}

#endif /* WX_INITDATA_H */

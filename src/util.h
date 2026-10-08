/**
 * Small things everything else here uses: settings from the environment,
 * secrets from files, a growable text buffer, and encodings.
 */
#ifndef WX_UTIL_H
#define WX_UTIL_H

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** A setting, with what it is when nobody set it. Empty counts as unset. */
static const char *env(const char *name, const char *otherwise) {

  const char *v = getenv(name);

  return v != NULL && v[0] != 0 ? v : otherwise;
}

/**
 * The first line of a file, for secrets: tokens and passwords are kept in
 * files the operator controls rather than in the environment, where every
 * process listing and crash report can see them. Read once per worker.
 */
static bool readSecret(const char *path, char *into, size_t room) {

  if (room == 0)
    return false;

  FILE *in = fopen(path, "r");

  if (in == NULL)
    return false;

  if (fgets(into, (int)room, in) == NULL)
    into[0] = 0;

  fclose(in);
  into[strcspn(into, "\r\n")] = 0;

  return into[0] != 0;
}

/* ------------------------------------------------------------ text buffer */

/**
 * A growable piece of text that is always NUL-terminated.
 *
 * `broke` remembers an allocation that failed, so a page built from a
 * hundred appends checks once at the end rather than a hundred times.
 */
typedef struct {
  char *at;
  size_t length;
  size_t room;
  bool broke;
} buf_t;

static void buf_t__reset(buf_t *self) {

  self->length = 0;
  self->broke = false;

  if (self->at != NULL)
    self->at[0] = 0;
}

static bool buf_t__grow(buf_t *self, size_t more) {

  if (self->broke)
    return false;

  if (self->length + more + 1 <= self->room)
    return true;

  size_t room = self->room ? self->room : 1024;

  while (room < self->length + more + 1)
    room *= 2;

  char *at = (char *)realloc(self->at, room);

  if (at == NULL) {
    self->broke = true;
    return false;
  }

  self->at = at;
  self->room = room;

  return true;
}

static void buf_t__add(buf_t *self, const char *text, size_t length) {

  if (!buf_t__grow(self, length))
    return;

  memcpy(self->at + self->length, text, length);
  self->length += length;
  self->at[self->length] = 0;
}

static void buf_t__put(buf_t *self, const char *text) {
  buf_t__add(self, text ?: "", strlen(text ?: ""));
}

__attribute__((format(printf, 2, 3)))
static void buf_t__printf(buf_t *self, const char *format, ...) {

  va_list args;
  int need;

  va_start(args, format);
  need = vsnprintf(NULL, 0, format, args);
  va_end(args);

  if (need < 0 || !buf_t__grow(self, (size_t)need))
    return;

  va_start(args, format);
  vsnprintf(self->at + self->length, (size_t)need + 1, format, args);
  va_end(args);

  self->length += (size_t)need;
}

/** Text that goes into HTML, element content or a quoted attribute. */
static void buf_t__html(buf_t *self, const char *text) {

  for (const char *at = text ?: ""; *at != 0; ++at)
    switch (*at) {
    case '<': buf_t__put(self, "&lt;"); break;
    case '>': buf_t__put(self, "&gt;"); break;
    case '&': buf_t__put(self, "&amp;"); break;
    case '"': buf_t__put(self, "&quot;"); break;
    case '\'': buf_t__put(self, "&#39;"); break;
    default: buf_t__add(self, at, 1);
    }
}

/* ------------------------------------------------------------ identifiers */

static bool isUuid(const char *s) {

  if (s == NULL || strlen(s) != 36)
    return false;

  for (int i = 0; i < 36; ++i) {
    bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash ? s[i] != '-' : !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  }

  return true;
}

static bool isHex(const char *s, size_t length) {

  if (s == NULL || strlen(s) != length)
    return false;

  for (size_t i = 0; i < length; ++i)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;

  return true;
}

/** Lowercase hex of any even, non-zero length. */
static bool isHexText(const char *s) {

  size_t length = s != NULL ? strlen(s) : 0;

  return length > 0 && length % 2 == 0 && isHex(s, length);
}

/* -------------------------------------------------------------- encodings */

static void toHex(const unsigned char *bytes, size_t length, char *into) {

  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0; i < length; ++i) {
    into[i * 2] = digits[bytes[i] >> 4];
    into[i * 2 + 1] = digits[bytes[i] & 15];
  }

  into[length * 2] = 0;
}

/** Hex to bytes; the number of bytes, or -1 for anything that is not hex. */
static long fromHex(const char *hex, unsigned char *into, size_t room) {

  size_t length = strlen(hex);

  if (length % 2 != 0 || length / 2 > room)
    return -1;

  for (size_t i = 0; i < length / 2; ++i) {
    unsigned int byte;

    if (sscanf(hex + i * 2, "%2x", &byte) != 1)
      return -1;

    into[i] = (unsigned char)byte;
  }

  return (long)(length / 2);
}

/** Standard base64 with padding; `into` needs 4 * ceil(length / 3) + 1. */
static void toBase64(const unsigned char *bytes, size_t length, char *into) {
  EVP_EncodeBlock((unsigned char *)into, bytes, (int)length);
}

/**
 * Base64 to bytes, the number of bytes or -1. Whitespace is not accepted -
 * what arrives here comes from a program, not a person.
 */
static long fromBase64(const char *text, unsigned char *into, size_t room) {

  size_t length = strlen(text);
  int got;

  if (length % 4 != 0 || length / 4 * 3 > room)
    return -1;

  got = EVP_DecodeBlock(into, (const unsigned char *)text, (int)length);

  if (got < 0)
    return -1;

  /* EVP_DecodeBlock counts the padding as bytes; take them back off */
  if (length > 0 && text[length - 1] == '=')
    --got;
  if (length > 1 && text[length - 2] == '=')
    --got;

  return got;
}

static void sha256(const void *data, size_t length, unsigned char out[32]) {

  unsigned int written = 0;

  EVP_Digest(data, length, out, &written, EVP_sha256(), NULL);
}

static void sha256Hex(const void *data, size_t length, char out[65]) {

  unsigned char digest[32];

  sha256(data, length, digest);
  toHex(digest, 32, out);
}

/** Random bytes from OpenSSL's generator; false only if it has none. */
static bool randomBytes(unsigned char *into, size_t length) {
  return RAND_bytes(into, (int)length) == 1;
}

static bool randomHex(size_t bytes, char *into) {

  unsigned char raw[64];

  if (bytes > sizeof raw || !randomBytes(raw, bytes))
    return false;

  toHex(raw, bytes, into);

  return true;
}

#endif /* WX_UTIL_H */

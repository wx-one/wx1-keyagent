/**
 * Whether user-data may be approved without the customer looking at it.
 *
 * cloud-init runs as root in the unlocked VM: whatever brings in access or
 * code gives the sender the plaintext. So automatically only a narrow form:
 * users with known SSH keys, no commands, no files, no passwords. Everything
 * else the customer reads and decides on.
 */
#ifndef WX_CLOUDINIT_H
#define WX_CLOUDINIT_H

#include "util.h"

#include <meta_text.h>
#include <yaml.h>

static const char *const safeTop[] = {"hostname", "fqdn",  "users",  "ssh_pwauth",
                                      "disable_root", "timezone", "locale"};
static const char *const safeUser[] = {"name",   "sudo",        "shell",
                                       "groups", "lock_passwd", "ssh_authorized_keys",
                                       "gecos"};

/** Why not, one reason per line; empty when it may go automatically. */
typedef struct {
  buf_t why;
  int count;
} cloudinit_t;

static void cloudinit_t__no(cloudinit_t *self, const char *reason) {

  if (self->count++ > 0)
    buf_t__put(&self->why, "\n");

  buf_t__put(&self->why, reason);
}

static bool listed(const char *const *list, size_t count, const char *name) {

  for (size_t i = 0; i < count; ++i)
    if (strcmp(list[i], name) == 0)
      return true;

  return false;
}

static const char *yamlScalar(yaml_node_t *node) {
  return node != NULL && node->type == YAML_SCALAR_NODE ? (const char *)node->data.scalar.value
                                                        : NULL;
}

/** YAML 1.1 false, as PyYAML and with it cloud-init read it. */
static bool yamlFalse(yaml_node_t *node) {

  static const char *const no[] = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"};
  const char *v = yamlScalar(node);

  return v != NULL && node->data.scalar.style == YAML_PLAIN_SCALAR_STYLE &&
         listed(no, sizeof no / sizeof no[0], v);
}

/** "type base64" of an authorized_keys line: the part that names the key. */
static void keyName(const char *line, char *into, size_t room) {

  size_t n = 0;
  int spaces = 0;

  for (; *line == ' ' || *line == '\t'; ++line) {}

  for (; *line != 0 && n + 1 < room; ++line) {
    if (*line == ' ' || *line == '\t') {
      if (++spaces == 2)
        break;
      while (line[1] == ' ' || line[1] == '\t')
        ++line;
      into[n++] = ' ';
      continue;
    }
    into[n++] = *line;
  }

  into[n] = 0;
}

static void cloudinitUser(cloudinit_t *self, yaml_document_t *doc, yaml_node_t *user,
                          const char *const *allowed, int allowedCount) {

  char reason[256];
  const char *name = "?";

  if (user->type != YAML_MAPPING_NODE) {
    text_t why = TEXT`user entry ${yamlScalar(user) ?: "(not a mapping)"} cannot be checked`;
    why.into(reason, sizeof reason);
    self.no(reason);
    return;
  }

  for (yaml_node_pair_t *p = user->data.mapping.pairs.start; p < user->data.mapping.pairs.top; ++p)
    if (strcmp(yamlScalar(yaml_document_get_node(doc, p->key)) ?: "", "name") == 0)
      name = yamlScalar(yaml_document_get_node(doc, p->value)) ?: "?";

  for (yaml_node_pair_t *p = user->data.mapping.pairs.start; p < user->data.mapping.pairs.top; ++p) {

    const char *key = yamlScalar(yaml_document_get_node(doc, p->key)) ?: "?";
    yaml_node_t *value = yaml_document_get_node(doc, p->value);

    if (!listed(safeUser, sizeof safeUser / sizeof safeUser[0], key)) {
      text_t why = TEXT`user ${name}: '${key}'`;
      why.into(reason, sizeof reason);
      self.no(reason);
    } else if (strcmp(key, "lock_passwd") == 0 && yamlFalse(value)) {
      text_t why = TEXT`user ${name}: password login`;
      why.into(reason, sizeof reason);
      self.no(reason);
    } else if (strcmp(key, "ssh_authorized_keys") == 0) {

      if (value == NULL || value->type != YAML_SEQUENCE_NODE) {
        text_t why = TEXT`user ${name}: ssh_authorized_keys is not a list`;
        why.into(reason, sizeof reason);
        self.no(reason);
        continue;
      }

      for (yaml_node_item_t *k = value->data.sequence.items.start;
           k < value->data.sequence.items.top; ++k) {

        const char *line = yamlScalar(yaml_document_get_node(doc, *k));
        char have[2048];
        bool known = false;

        keyName(line ?: "", have, sizeof have);

        for (int a = 0; a < allowedCount && !known; ++a) {
          char want[2048];
          keyName(allowed[a], want, sizeof want);
          known = want[0] != 0 && strcmp(want, have) == 0;
        }

        if (!known) {
          text_t why = TEXT`unknown SSH key ${have}`;
          why.into(reason, 72);
          self.no(reason);
        }
      }
    }
  }
}

static cloudinit_t cloudinitCheck(const char *userData, size_t length,
                                  const char *const *allowed, int allowedCount) {

  cloudinit_t self = {0};
  yaml_parser_t parser;
  yaml_document_t doc;

  if (length < 13 || memcmp(userData, "#cloud-config", 13) != 0 ||
      (length > 13 && userData[13] != '\n' && userData[13] != '\r')) {
    self.no("user-data is not #cloud-config (a script, for one)");
    return self;
  }

  if (!yaml_parser_initialize(&parser)) {
    self.no("cannot read user-data");
    return self;
  }

  yaml_parser_set_input_string(&parser, (const unsigned char *)userData, length);

  if (!yaml_parser_load(&parser, &doc)) {
    char reason[256];
    text_t why = TEXT`user-data cannot be read: ${parser.problem ?: "?"}`;
    why.into(reason, sizeof reason);
    self.no(reason);
    yaml_parser_delete(&parser);
    return self;
  }

  /* a second document is something nobody here looked at */
  {
    yaml_document_t more;

    if (yaml_parser_load(&parser, &more)) {
      if (yaml_document_get_root_node(&more) != NULL)
        self.no("user-data holds more than one document");
      yaml_document_delete(&more);
    } else {
      self.no("user-data cannot be read after the first document");
    }
  }

  yaml_node_t *root = yaml_document_get_root_node(&doc);

  if (root != NULL && root->type != YAML_MAPPING_NODE)
    self.no("user-data is not a mapping");

  if (root != NULL && root->type == YAML_MAPPING_NODE)
    for (yaml_node_pair_t *p = root->data.mapping.pairs.start; p < root->data.mapping.pairs.top;
         ++p) {

      const char *key = yamlScalar(yaml_document_get_node(&doc, p->key)) ?: "?";
      yaml_node_t *value = yaml_document_get_node(&doc, p->value);
      char reason[256];

      if (!listed(safeTop, sizeof safeTop / sizeof safeTop[0], key)) {
        text_t why = TEXT`contains '${key}'`;
        why.into(reason, sizeof reason);
        self.no(reason);
      } else if (strcmp(key, "ssh_pwauth") == 0 && !yamlFalse(value)) {
        self.no("allows SSH with a password");
      } else if (strcmp(key, "users") == 0) {
        if (value == NULL || value->type != YAML_SEQUENCE_NODE) {
          self.no("users is not a list");
          continue;
        }
        for (yaml_node_item_t *u = value->data.sequence.items.start;
             u < value->data.sequence.items.top; ++u)
          cloudinitUser(&self, &doc, yaml_document_get_node(&doc, *u), allowed, allowedCount);
      }
    }

  if (allowedCount == 0)
    self.no("no known SSH keys set");

  yaml_document_delete(&doc);
  yaml_parser_delete(&parser);

  return self;
}

#endif /* WX_CLOUDINIT_H */

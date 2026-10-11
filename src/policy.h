/**
 * The customer's KBS: its resource policy, written from the bindings and set
 * through the KBS admin API after every change to them, and the vTPM state
 * keys, which the agent makes and the KBS alone gives out - to the SVSM of
 * exactly that VM. Where the KBS keeps them is the KBS's configuration
 * (on OpenBao's kv/, in a KMS, on its disk); the agent writes them through
 * the same API either way and never reads them back.
 *
 * The verifier is patched not to enforce the VMPL itself: it is checked here.
 */
#ifndef WX_POLICY_H
#define WX_POLICY_H

#include "store.h"

static const char policyHead[] = `
  package policy

  import rego.v1

  default allow := false

  evidence := input.submods.cpu0["ear.veraison.annotated-evidence"]

  snp := evidence.snp

  path := data["resource-path"]

  # the provider's reference values (SVSM + firmware), taken over by the customer
  allowed_measurements := {`;

static const char policyMiddle[] = `
  }

  # bindings of the attached disks: exact initdata (HOST_DATA) and allowed hosts
  disks := `;

static const char policyTail[] = `


  platform_ok if {
      snp.measurement in allowed_measurements
      snp.policy_debug_allowed == false
      snp.policy_migrate_ma == false
  }

  # disk/<disk-id>/key only for the guest Linux (VMPL2) of the VM the disk is
  # attached to, and only on allowed hosts. A disk attached nowhere gets nothing.
  allow if {
      data.plugin == "resource"
      platform_ok
      snp.vmpl == 2
      count(path) == 3
      path[0] == "disk"
      path[2] == "key"
      b := disks[path[1]]
      evidence.init_data == b.host_data
      snp.chip_id in b.chip_ids
  }

  # vtpm/<HOST_DATA>/state: the state key of a persistent vTPM, one per VM. Only for
  # the SVSM (VMPL0) of exactly that VM, while a disk is attached to it, on allowed hosts.
  allow if {
      data.plugin == "resource"
      platform_ok
      snp.vmpl == 0
      count(path) == 3
      path[0] == "vtpm"
      path[2] == "state"
      path[1] == evidence.init_data
      some b in disks
      b.host_data == evidence.init_data
      snp.chip_id in b.chip_ids
  }
  `;

/**
 * The measurements of the provider's reference file (`key=value` lines),
 * those under `keys`, as `"m1", "m2"` into `out`. Answers how many.
 */
static int refMeasurements(buf_t *out, const char *const *keys, int keyCount) {

  FILE *in = fopen(env("WX_REFS", "/refs/manifest.txt"), "r");
  char line[512];
  int count = 0;

  if (in == NULL)
    return 0;

  while (fgets(line, sizeof line, in) != NULL) {

    char *eq = strchr(line, '=');

    line[strcspn(line, "\r\n")] = 0;

    if (eq == NULL)
      continue;

    *eq = 0;

    for (char *c = eq + 1; *c != 0; ++c)
      if (*c >= 'A' && *c <= 'F')
        *c = (char)(*c - 'A' + 'a');

    for (int k = 0; k < keyCount; ++k)
      if (strcmp(line, keys[k]) == 0 && isHexText(eq + 1)) {
        if (count++ > 0)
          buf_t__put(out, ", ");
        buf_t__printf(out, "\"%s\"", eq + 1);
      }
  }

  fclose(in);

  return count;
}

/**
 * The bindings, one disk per line: the policy engine (regorus) takes at
 * most 1024 characters per line. Only IDs and hashes that are what they
 * claim go in, so nothing here needs escaping.
 */
static bool policyDisks(buf_t *out) {

  bool failed = false;
  json_t list = stateList("attachments/", &failed);
  int written = 0;

  if (failed) {
    list.release();
    return false;
  }

  buf_t__put(out, "{");

  for (int i = 0; i < list.count(); ++i) {

    const char *id = list[i].text();
    entry_t att = storeGet("attachments", id ?: "");

    if (att.failed) {
      failed = true;
      break;
    }

    json_t a = att.payload();
    json_t chips = a.chip_ids;
    const char *hd = a.host_data.text();

    if (att.found && isDiskId(id) && isHex(hd, 64)) {

      buf_t__printf(out, "%s\n \"%s\": {\"host_data\": \"%s\", \"chip_ids\": [", written++ ? "," : "",
                    id, hd);

      int c = 0;
      for (int k = 0; k < chips.count(); ++k)
        if (isHex(chips[k].text(), 128))
          buf_t__printf(out, "%s\n  \"%s\"", c++ ? "," : "", chips[k].text());

      buf_t__put(out, "]}");
    }

    att.release();
  }

  buf_t__put(out, "\n}");
  list.release();

  return !failed;
}

/**
 * A write to the KBS admin API: `path` below /kbs/v0/, the body as given.
 * NULL, or what went wrong (`what` names it).
 */
static const char *kbsAdmin(const char *path, const char *mime, const void *body, size_t length,
                            const char *what) {

  static char token[256], why[160];
  char url[512], bearer[300];

  if (!readSecret(env("WX_KBS_ADMIN_TOKEN_FILE", "/secrets/kbs-admin-token"), token, sizeof token))
    return "no KBS admin token";

  text_t at = TEXT`${env("WX_KBS_ADMIN_URL", "http://127.0.0.1:8090")}/kbs/v0/${path}`;
  at.into(url, sizeof url);
  text_t auth = TEXT`Bearer ${token}`;
  auth.into(bearer, sizeof bearer);

  fetch_answer_t got = meta_fetch("POST", url)
                           .header("authorization", bearer)
                           .header("content-type", mime)
                           .bytes(body, length)
                           .send();

  const char *wrong = NULL;

  if (got.status == 0) {
    wrong = "KBS not reachable";
  } else if (!got.ok) {
    snprintf(why, sizeof why, "KBS refused %s (%d)", what, got.status);
    wrong = why;
  }

  got.release();

  return wrong;
}

/**
 * A new state key for the VM's vTPM, overwriting one it had: the old state
 * cannot be read any more. NULL, or what went wrong.
 */
static const char *kbsNewVtpmKey(const char *hostData) {

  unsigned char raw[32];
  char path[128];

  if (!isHex(hostData, 64))
    return "bad HOST_DATA";

  if (!randomBytes(raw, sizeof raw))
    return "no randomness";

  text_t at = TEXT`resource/vtpm/${hostData}/state`;
  at.into(path, sizeof path);

  const char *wrong = kbsAdmin(path, "application/octet-stream", raw, sizeof raw, "the vTPM state key");
  OPENSSL_cleanse(raw, sizeof raw);

  return wrong;
}

/** Writes the policy and sets it in the KBS; NULL, or what went wrong. */
static const char *pushPolicy(void) {

  static const char *const both[] = {"igvm_measurement", "igvm_persist_measurement"};
  buf_t policy = {0};

  buf_t__put(&policy, policyHead);
  refMeasurements(&policy, both, 2);
  buf_t__put(&policy, policyMiddle);

  if (!policyDisks(&policy)) {
    free(policy.at);
    return "cannot read the bindings (database)";
  }

  buf_t__put(&policy, policyTail);

  if (policy.broke) {
    free(policy.at);
    return "no memory";
  }

  /* base64url without padding, as the KBS wants it */
  char *encoded = (char *)malloc(policy.length / 3 * 4 + 8);

  if (encoded == NULL) {
    free(policy.at);
    return "no memory";
  }

  toBase64((const unsigned char *)policy.at, policy.length, encoded);

  for (char *c = encoded; *c != 0; ++c)
    *c = *c == '+' ? '-' : *c == '/' ? '_' : *c;

  encoded[strcspn(encoded, "=")] = 0;
  json_t body = {policy: encoded};
  char *text = body.owned();
  body.release();

  free(encoded);
  free(policy.at);

  const char *wrong = text == NULL ? "no memory"
                                   : kbsAdmin("resource-policy", "application/json", text, strlen(text),
                                              "the policy");
  free(text);

  return wrong;
}

#endif /* WX_POLICY_H */

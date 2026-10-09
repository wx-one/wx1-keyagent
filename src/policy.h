/**
 * The customer's KBS resource policy, written from the bindings in OpenBao
 * and set through the KBS admin API after every change to them.
 *
 * The verifier is patched not to enforce the VMPL itself: it is checked here.
 */
#ifndef WX_POLICY_H
#define WX_POLICY_H

#include "store.h"

static const char policyHead[] =
  "package policy\n"
  "\n"
  "import rego.v1\n"
  "\n"
  "default allow := false\n"
  "\n"
  "evidence := input.submods.cpu0[\"ear.veraison.annotated-evidence\"]\n"
  "\n"
  "snp := evidence.snp\n"
  "\n"
  "path := data[\"resource-path\"]\n"
  "\n"
  "# the provider's reference values (SVSM + firmware), taken over by the customer\n"
  "allowed_measurements := {";

static const char policyMiddle[] =
  "}\n"
  "\n"
  "# bindings of the attached disks: exact initdata (HOST_DATA) and allowed hosts\n"
  "disks := ";

static const char policyTail[] =
  "\n"
  "\n"
  "platform_ok if {\n"
  "\tsnp.measurement in allowed_measurements\n"
  "\tsnp.policy_debug_allowed == false\n"
  "\tsnp.policy_migrate_ma == false\n"
  "}\n"
  "\n"
  "# disk/<disk-id>/key only for the guest Linux (VMPL2) of the VM the disk is\n"
  "# attached to, and only on allowed hosts. A disk attached nowhere gets nothing.\n"
  "allow if {\n"
  "\tdata.plugin == \"resource\"\n"
  "\tplatform_ok\n"
  "\tsnp.vmpl == 2\n"
  "\tcount(path) == 3\n"
  "\tpath[0] == \"disk\"\n"
  "\tpath[2] == \"key\"\n"
  "\tb := disks[path[1]]\n"
  "\tevidence.init_data == b.host_data\n"
  "\tsnp.chip_id in b.chip_ids\n"
  "}\n"
  "\n"
  "# vtpm/<HOST_DATA>/state: the state key of a persistent vTPM, one per VM. Only for\n"
  "# the SVSM (VMPL0) of exactly that VM, while a disk is attached to it, on allowed hosts.\n"
  "allow if {\n"
  "\tdata.plugin == \"resource\"\n"
  "\tplatform_ok\n"
  "\tsnp.vmpl == 0\n"
  "\tcount(path) == 3\n"
  "\tpath[0] == \"vtpm\"\n"
  "\tpath[2] == \"state\"\n"
  "\tpath[1] == evidence.init_data\n"
  "\tsome b in disks\n"
  "\tb.host_data == evidence.init_data\n"
  "\tsnp.chip_id in b.chip_ids\n"
  "}\n";

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
  json_t keys = baoList("attachments/", &failed);
  json_t list = keys.get("data").get("keys");
  int written = 0;

  if (failed)
    return false;

  buf_t__put(out, "{");

  for (int i = 0; i < list.count(); ++i) {

    const char *id = list.at(i).text();
    bao_entry_t att = storeGet("attachments", id ?: "");

    if (att.failed) {
      failed = true;
      break;
    }

    json_t a = att.payload();
    json_t chips = a.get("chip_ids");
    const char *hd = a.get("host_data").text();

    if (att.found && isDiskId(id) && isHex(hd, 64)) {

      buf_t__printf(out, "%s\n \"%s\": {\"host_data\": \"%s\", \"chip_ids\": [", written++ ? "," : "",
                    id, hd);

      int c = 0;
      for (int k = 0; k < chips.count(); ++k)
        if (isHex(chips.at(k).text(), 128))
          buf_t__printf(out, "%s\n  \"%s\"", c++ ? "," : "", chips.at(k).text());

      buf_t__put(out, "]}");
    }

    att.release();
  }

  buf_t__put(out, "\n}");
  keys.release();

  return !failed;
}

/** Writes the policy and sets it in the KBS; NULL, or what went wrong. */
static const char *pushPolicy(void) {

  static const char *const both[] = {"igvm_measurement", "igvm_persist_measurement"};
  static char token[256];
  buf_t policy = {0}, body = {0};
  const char *wrong = NULL;

  buf_t__put(&policy, policyHead);
  refMeasurements(&policy, both, 2);
  buf_t__put(&policy, policyMiddle);

  if (!policyDisks(&policy)) {
    free(policy.at);
    return "cannot read the bindings (OpenBao)";
  }

  buf_t__put(&policy, policyTail);

  if (policy.broke) {
    free(policy.at);
    return "no memory";
  }

  if (!readSecret(env("WX_KBS_ADMIN_TOKEN_FILE", "/secrets/kbs-admin-token"), token,
                  sizeof token)) {
    free(policy.at);
    return "no KBS admin token";
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
  buf_t__printf(&body, "{\"policy\":\"%s\"}", encoded);

  free(encoded);
  free(policy.at);

  char url[512], bearer[300];
  text_t at = TEXT`${env("WX_KBS_ADMIN_URL", "http://127.0.0.1:8090")}/kbs/v0/resource-policy`;
  at.into(url, sizeof url);
  text_t auth = TEXT`Bearer ${token}`;
  auth.into(bearer, sizeof bearer);

  fetch_answer_t got = freshCall("POST", url).header("authorization", bearer).json(body.at).send();

  if (!got.ok)
    wrong = got.status == 0 ? "KBS not reachable" : "KBS refused the policy";

  got.release();
  free(body.at);

  return wrong;
}

#endif /* WX_POLICY_H */

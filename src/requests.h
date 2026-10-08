/**
 * Requests from the provider's control plane: "create a disk", "attach it to
 * a VM", "allow another host", ... with public data only (initdata,
 * cloud-init, chip_id). They are checked here, approved by the customer or an
 * auto rule, and only then do keys and bindings appear in the customer's
 * OpenBao and KBS policy. The provider sees "applied" or "rejected", never a
 * key.
 *
 * Taking rights away (detach) applies at once; giving them needs an approval
 * or a rule.
 *
 * Two kinds of disk, named as the platform names them:
 *   vm-<uuid>   the one disk bound to that VM, its system disk. It has no ID
 *               of its own, is created with the VM (create) and never
 *               attached to another one. When the VM goes (detach), its
 *               binding goes at once and the customer is asked whether to
 *               shred the key.
 *   vol-<uuid>  a volume of its own (create_volume), attached to at most one
 *               VM at a time (attach, detach), bound to that VM's HOST_DATA.
 *               Attached with "boot": true it is the VM's main disk instead of
 *               a system disk: named in the initdata as wx.disk.root, "new"
 *               until it has been booted from once and "existing" after, and
 *               with the VM's vTPM. Any other volume is the customer's own
 *               business inside the VM; the release serves it all the same.
 *
 * reprovision installs the VM's main disk afresh: never automatic, and the
 * old key and the old vTPM state are shredded before the new binding exists,
 * so nothing of the old installation can be read again.
 */
#ifndef WX_REQUESTS_H
#define WX_REQUESTS_H

#include "cloudinit.h"
#include "initdata.h"
#include "policy.h"
#include "store.h"

/* ---------------------------------------------------------------- checks */

/** What was checked: [[true|false|null, text], ...]; null is a remark. */
typedef struct {
  yyjson_mut_doc *doc;
  yyjson_mut_val *list;
  buf_t failed;
  int failures;
} checks_t;

static checks_t checksNew(void) {

  checks_t self = {0};

  self.doc = yyjson_mut_doc_new(NULL);
  self.list = yyjson_mut_arr(self.doc);
  yyjson_mut_doc_set_root(self.doc, self.list);

  return self;
}

static void checks_t__add(checks_t *self, yyjson_mut_val *verdict, const char *text) {

  yyjson_mut_val *item = yyjson_mut_arr(self->doc);

  yyjson_mut_arr_append(item, verdict);
  yyjson_mut_arr_append(item, yyjson_mut_strcpy(self->doc, text));
  yyjson_mut_arr_append(self->list, item);
}

static bool checks_t__ok(checks_t *self, bool good, const char *text) {

  self->add(yyjson_mut_bool(self->doc, good), text);

  if (!good) {
    if (self->failures++ > 0)
      buf_t__put(&self->failed, "; ");
    buf_t__put(&self->failed, text);
  }

  return good;
}

static void checks_t__note(checks_t *self, const char *text) {
  self->add(yyjson_mut_null(self->doc), text);
}

/** The list as JSON; the caller frees it. */
static char *checks_t__json(checks_t *self) {
  return yyjson_mut_write(self->doc, 0, NULL);
}

static void checks_t__release(checks_t *self) {
  yyjson_mut_doc_free(self->doc);
  free(self->failed.at);
}

/* ------------------------------------------------------------ the payload */

/** A base64 field, decoded and NUL-terminated; free `.at`. */
typedef struct {
  char *at;
  long length;
} blob_t;

static blob_t blobOf(json_t field) {

  blob_t blob = {NULL, -1};
  const char *text = field.text();

  if (text == NULL)
    return blob;

  size_t room = strlen(text) / 4 * 3 + 1;

  blob.at = (char *)malloc(room);

  if (blob.at == NULL)
    return blob;

  blob.length = fromBase64(text, (unsigned char *)blob.at, room - 1);
  blob.at[blob.length >= 0 ? blob.length : 0] = 0;

  return blob;
}

static const char *releaseGuestUrl(void) {
  return env("WX_RELEASE_GUEST_URL", "http://192.168.122.1:8091");
}

/* --------------------------------------------------------------- settings */

/**
 * settings in OpenBao: auto_attach, auto_add_host, host_pool
 * [{hv_uuid, chip_id, name}], allowed_ssh_keys [...]. The HV UUID comes from
 * the provider and only names a host; what counts is the chip_id, signed by
 * AMD into every report.
 */
typedef struct {
  bao_entry_t entry;
  json_t data;
  bool failed;
} settings_t;

static settings_t settingsRead(void) {

  settings_t self = {0};

  self.entry = storeGet("settings", NULL);
  self.failed = self.entry.failed;

  if (self.entry.found)
    self.data = self.entry.payload();

  return self;
}

static bool settings_t__flag(settings_t *self, const char *name) {
  return self->entry.found && self->data.get(name).truth();
}

static bool settings_t__inPool(settings_t *self, const char *chip) {

  json_t pool = self->data.get("host_pool");

  for (int i = 0; self->entry.found && i < pool.count(); ++i)
    if (strcmp(pool.at(i).get("chip_id").text() ?: "", chip ?: "") == 0)
      return true;

  return false;
}

/** The chip_id the pool has for a HV UUID, or NULL. */
static const char *settings_t__chipOf(settings_t *self, const char *hv) {

  json_t pool = self->data.get("host_pool");

  for (int i = 0; self->entry.found && hv != NULL && i < pool.count(); ++i)
    if (strcmp(pool.at(i).get("hv_uuid").text() ?: "", hv) == 0)
      return pool.at(i).get("chip_id").text();

  return NULL;
}

static int settings_t__keys(settings_t *self, const char **into, int room) {

  json_t keys = self->data.get("allowed_ssh_keys");
  int n = 0;

  for (int i = 0; self->entry.found && i < keys.count() && n < room; ++i)
    if (keys.at(i).text() != NULL)
      into[n++] = keys.at(i).text();

  return n;
}

static void settings_t__release(settings_t *self) {
  self->entry.release();
}

/* ------------------------------------------------------------- validation */

/** Whether files.<name> in the payload has the SHA-256 `want`. */
static bool fileMatches(json_t p, const char *name, const char *want) {

  char got[65];
  blob_t file = blobOf(p.get("files").get(name));
  bool same = false;

  if (file.length >= 0) {
    sha256Hex(file.at, (size_t)file.length, got);
    same = strcmp(got, want) == 0;
  }

  free(file.at);

  return same;
}

/**
 * initdata and the files it names. `state` is "new" or "existing": a disk
 * once attached is encrypted and never "new" again, or an empty disk slipped
 * in under the old name would be formatted with the customer's key. NULL
 * for a volume, which the initdata does not name.
 */
static void checkInitdata(checks_t *checks, json_t p, const char *disk, const char *state,
                          char hostData[65]) {

  char text[256];
  blob_t raw = blobOf(p.get("initdata"));
  initdata_t *doc = (initdata_t *)calloc(1, sizeof(initdata_t));

  hostData[0] = 0;

  if (doc == NULL || raw.length < 0 || !doc.parse(raw.at, (size_t)raw.length)) {
    text_t why = TEXT`initdata cannot be read: ${doc != NULL ? doc->why : "no memory"}`;
    why.into(text, sizeof text);
    checks.ok(false, text);
    free(raw.at);
    free(doc);
    return;
  }

  sha256Hex(raw.at, (size_t)raw.length, hostData);

  const char *vm = p.get("vm_uuid").text();
  checks.ok(isUuid(vm), "VM UUID valid");
  checks.ok(strcmp(doc.get("vm.uuid") ?: "", vm ?: "-") == 0, "initdata names this VM UUID");

  /* a volume is attached to a running VM: its initdata cannot name it */
  if (state != NULL) {
    char root[128];
    text_t want = TEXT`${disk}:${state}`;
    want.into(root, sizeof root);
    text_t says = TEXT`initdata names the disk as '${state}'`;
    says.into(text, sizeof text);
    checks.ok(strcmp(doc.get("wx.disk.root") ?: "", root) == 0, text);
  }

  checks.ok(strcmp(doc.get("wx.release.url") ?: "", releaseGuestUrl()) == 0,
            "initdata names our key release");

  checks.ok(doc.get("user-data.sha256") != NULL && doc.get("meta-data.sha256") != NULL,
            "initdata names the hashes of user-data and meta-data");

  for (int i = 0; i < doc->count; ++i) {

    size_t length = strlen(doc->key[i]);

    if (length <= 7 || strcmp(doc->key[i] + length - 7, ".sha256") != 0)
      continue;

    char name[96];
    memcpy(name, doc->key[i], length - 7);
    name[length - 7] = 0;

    text_t matches = TEXT`${name} matches its hash in initdata`;
    matches.into(text, sizeof text);
    checks.ok(fileMatches(p, name, doc->value[i]), text);
  }

  checks.ok(isHex(p.get("chip_id").text(), 128), "chip_id valid");

  free(raw.at);
  free(doc);
}

/** Whether the user-data would pass an auto rule; the reasons go in as remarks. */
static bool checkCloudInit(checks_t *checks, json_t p, settings_t *settings) {

  const char *keys[64];
  int count = settings.keys(keys, 64);
  blob_t userData = blobOf(p.get("files").get("user-data"));
  cloudinit_t verdict = cloudinitCheck(userData.at ?: "", userData.length > 0 ? (size_t)userData.length : 0,
                                       keys, count);

  for (char *line = verdict.why.at; line != NULL && *line != 0;) {
    char *next = strchr(line, '\n');
    char text[320];

    if (next != NULL)
      *next = 0;

    text_t no = TEXT`no auto approval: ${line}`;
    no.into(text, sizeof text);
    checks.note(text);

    line = next != NULL ? next + 1 : NULL;
  }

  free(verdict.why.at);
  free(userData.at);

  return verdict.count == 0;
}

/**
 * Which disk a request means, into `out`: create makes the VM's system disk,
 * vm-<vm_uuid>; everything else names its disk_id, or without one the VM's
 * system disk again.
 */
static const char *diskOf(const char *type, json_t p, char out[48]) {

  const char *disk = p.get("disk_id").text();

  if (strcmp(type, "create") == 0 || disk[0] == 0) {
    text_t t = TEXT`vm-${p.get("vm_uuid").text()}`;
    t.into(out, 48);
  } else {
    text_t t = TEXT`${disk}`;
    t.into(out, 48);
  }

  return out;
}

/**
 * Checks a request against the current state. Answers whether an auto rule
 * lets it through; failed checks reject it whatever the rule says.
 */
static bool validate(checks_t *checks, const char *type, json_t p) {

  char diskBuf[48];
  settings_t settings = settingsRead();
  const char *diskId = diskOf(type, p, diskBuf);
  bao_entry_t disk = storeGet("disks", diskId);
  bao_entry_t att = storeGet("attachments", diskId);
  bool active = disk.found && strcmp(disk.payload().get("status").text() ?: "", "active") == 0;
  const char *attachedTo = att.found ? att.payload().get("vm_uuid").text() : NULL;
  const char *chip = p.get("chip_id").text();
  bool inPool = settings.inPool(chip);
  bool automatic = false;
  char hostData[65];

  if (!checks.ok(!settings.failed && !disk.failed && !att.failed, "state readable (OpenBao)"))
    goto done;

  /* HV UUID (from the provider) and chip_id (from the report) have to agree
     with the pool, or the host changed its chip or the mapping is wrong: the
     customer decides, no rule does */
  const char *known = settings.chipOf(p.get("hv_uuid").text());
  if (known != NULL && strcmp(known, chip ?: "") != 0) {
    checks.note("chip_id does NOT match the HV UUID in the host pool (hardware swapped?)");
    inPool = false;
  }

  bool system = isSystemDisk(diskId);

  if (strcmp(type, "create") != 0)
    checks.ok(isDiskId(diskId), "disk ID valid (vm-<uuid> or vol-<uuid>)");

  if (strcmp(type, "create") == 0) {
    const char *named = p.get("disk_id").text();
    checks.ok(named[0] == 0 || strcmp(named, diskId) == 0,
              "no disk ID of its own (a system disk is named by its VM)");
    checks.ok(isDiskId(diskId), "VM UUID valid");
    checks.ok(!disk.found, "the VM has no system disk yet");
    checkCloudInit(checks, p, &settings);
    checkInitdata(checks, p, diskId, "new", hostData);
    /* a new disk holds no data yet, nothing to take: always automatic. The
       remarks stay on the request, to look at before data goes onto it */
    automatic = true;
  } else if (strcmp(type, "create_volume") == 0) {
    checks.ok(!system, "a volume is named vol-<uuid>");
    checks.ok(!disk.found, "volume ID not taken yet");
    /* no VM, no data: nothing to take */
    automatic = true;
  } else if (strcmp(type, "attach") == 0) {
    checks.ok(active, "disk exists");
    checks.ok(!system, "not a system disk (that belongs to its VM)");
    checks.ok(!att.found, "disk attached to no other VM");
    bool safe = checkCloudInit(checks, p, &settings);
    bool boot = p.get("boot").truth();

    char vmDisk[48];
    text_t vd = TEXT`vm-${p.get("vm_uuid").text()}`;
    vd.into(vmDisk, sizeof vmDisk);
    bao_entry_t vm = storeGet("attachments", vmDisk);

    if (boot) {
      /* the VM's main disk: once booted from, it is encrypted and never
         "new" again - or an empty volume slipped in under its name would be
         formatted with the customer's key */
      bool booted = disk.found && disk.payload().get("booted").truth();
      checkInitdata(checks, p, diskId, booted ? "existing" : "new", hostData);
      checks.ok(!vm.found, "the VM has no system disk (it boots from this volume)");
    } else {
      checkInitdata(checks, p, diskId, NULL, hostData);

      /* a volume joins the VM as it is: the binding of the VM's system disk
         knows its HOST_DATA, and the provider cannot name another one */
      if (vm.found)
        checks.ok(strcmp(vm.payload().get("host_data").text(), hostData) == 0,
                  "initdata is the VM's own (as bound to its system disk)");
      else
        checks.note("the VM has no system disk here; bound to the initdata as sent");
    }

    vm.release();

    automatic = settings.flag("auto_attach") && safe && inPool;
  } else if (strcmp(type, "add_host") == 0) {
    checks.ok(att.found, "disk is attached to a VM");
    checks.ok(attachedTo != NULL && strcmp(attachedTo, p.get("vm_uuid").text() ?: "") == 0,
              "request names this VM");
    checks.ok(isHex(chip, 128), "chip_id valid");
    automatic = settings.flag("auto_add_host") && inPool;
  } else if (strcmp(type, "detach") == 0) {
    checks.ok(attachedTo != NULL && strcmp(attachedTo, p.get("vm_uuid").text() ?: "") == 0,
              "disk is attached to this VM");
    automatic = true;
  } else if (strcmp(type, "unlock") == 0) {
    checks.ok(att.found, "disk is attached to a VM");
  } else if (strcmp(type, "reprovision") == 0) {
    /* what is on the disk is gone after this: the customer decides, always */
    bool main = att.found && (isSystemDisk(diskId) || att.payload().get("main").truth());
    checks.ok(active, "disk exists");
    checks.ok(attachedTo != NULL && strcmp(attachedTo, p.get("vm_uuid").text()) == 0,
              "disk is attached to this VM");
    checks.ok(main, "it is the VM's main disk");
    checkCloudInit(checks, p, &settings);
    checkInitdata(checks, p, diskId, "new", hostData);
    checks.note("approving shreds the disk's key and the VM's vTPM state: the data on it is gone for good");
  } else if (strcmp(type, "delete_disk") == 0) {
    checks.ok(active, "disk exists");
    checks.ok(!att.found, "disk attached to no VM");
  } else {
    checks.ok(false, "unknown request type");
  }

done:
  disk.release();
  att.release();
  settings.release();

  return automatic;
}

/* ------------------------------------------------------------- applying */

/** A new entry, written only if there is none yet; `*taken` if there was. */
static bool baoCreate(const char *key, yyjson_mut_doc *doc, bool *taken) {

  char *json = yyjson_mut_write(doc, 0, NULL);
  bool conflict = false;
  bool written = json != NULL && baoWrite(key, json, 0, &conflict);

  free(json);
  *taken = conflict;

  return written;
}

/** A fresh disk key: 32 random bytes, kept as their base64 text - the guests
    use exactly those 44 characters as the LUKS passphrase. */
static bool newDiskKey(const char *diskId) {

  unsigned char raw[32];
  char text[48], path[128];

  if (!randomBytes(raw, sizeof raw))
    return false;

  toBase64(raw, sizeof raw, text);

  text_t at = TEXT`disk/${diskId}/key`;
  at.into(path, sizeof path);

  return baoPutKey(path, (const unsigned char *)text, strlen(text));
}

/** The state key of a persistent vTPM: 32 raw bytes. */
static bool newVtpmKey(const char *hostData) {

  unsigned char raw[32];
  char path[128];

  if (!randomBytes(raw, sizeof raw))
    return false;

  text_t at = TEXT`vtpm/${hostData}/state`;
  at.into(path, sizeof path);

  return baoPutKey(path, raw, sizeof raw);
}

/**
 * attachments/<disk> and, if the VM has none yet, vtpm/<host_data> with its
 * state key. The vTPM entry stays when the same VM attaches the disk again.
 */
static const char *attach(json_t p, const char *diskId, bool withVtpm) {

  char key[200];
  bool taken = false;
  blob_t raw = blobOf(p.get("initdata"));
  blob_t userData = blobOf(p.get("files").get("user-data"));
  char hostData[65];
  const char *wrong = NULL;

  if (raw.length < 0) {
    free(raw.at);
    free(userData.at);
    return "initdata cannot be read";
  }

  sha256Hex(raw.at, (size_t)raw.length, hostData);

  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *a = yyjson_mut_obj(doc);
  yyjson_mut_val *chips = yyjson_mut_arr(doc);
  yyjson_mut_doc_set_root(doc, a);
  yyjson_mut_obj_add_strcpy(doc, a, "vm_uuid", p.get("vm_uuid").text() ?: "");
  yyjson_mut_obj_add_strcpy(doc, a, "vm_name", p.get("vm_name").text() ?: "");
  yyjson_mut_obj_add_strcpy(doc, a, "host_data", hostData);
  yyjson_mut_obj_add_strncpy(doc, a, "initdata", raw.at, (size_t)raw.length);
  yyjson_mut_obj_add_strncpy(doc, a, "user_data", userData.at ?: "",
                             userData.length > 0 ? (size_t)userData.length : 0);
  yyjson_mut_arr_add_strcpy(doc, chips, p.get("chip_id").text() ?: "");
  yyjson_mut_obj_add_val(doc, a, "chip_ids", chips);
  yyjson_mut_obj_add_int(doc, a, "created", (int64_t)time(NULL));
  yyjson_mut_obj_add_bool(doc, a, "main", withVtpm);

  text_t at = TEXT`attachments/${diskId}`;
  at.into(key, sizeof key);

  if (!baoCreate(key, doc, &taken))
    wrong = taken ? "disk is already attached to a VM" : "cannot write the binding (OpenBao)";

  yyjson_mut_doc_free(doc);
  free(raw.at);
  free(userData.at);

  /* a volume joins a VM that has its vTPM already */
  if (wrong != NULL || !withVtpm)
    return wrong;

  doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *v = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, v);
  yyjson_mut_obj_add_strcpy(doc, v, "disk_id", diskId);
  yyjson_mut_obj_add_strcpy(doc, v, "vm_uuid", p.get("vm_uuid").text() ?: "");
  yyjson_mut_obj_add_strcpy(doc, v, "vm_name", p.get("vm_name").text() ?: "");
  yyjson_mut_obj_add_int(doc, v, "created", (int64_t)time(NULL));

  text_t vt = TEXT`vtpm/${hostData}`;
  vt.into(key, sizeof key);

  if (baoCreate(key, doc, &taken)) {
    if (!newVtpmKey(hostData))
      wrong = "cannot write the vTPM state key (OpenBao)";
  } else if (!taken) {
    wrong = "cannot write the vTPM entry (OpenBao)";
  }

  yyjson_mut_doc_free(doc);

  return wrong;
}

static bool addChip(yyjson_mut_doc *doc, yyjson_mut_val *root, void *with) {

  const char *chip = (const char *)with;
  yyjson_mut_val *chips = yyjson_mut_obj_get(root, "chip_ids");
  yyjson_mut_val *c;
  yyjson_mut_arr_iter it;

  if (!yyjson_mut_is_arr(chips))
    return false;

  yyjson_mut_arr_iter_init(chips, &it);

  while ((c = yyjson_mut_arr_iter_next(&it)) != NULL)
    if (yyjson_mut_equals_str(c, chip))
      return false;

  return yyjson_mut_arr_add_strcpy(doc, chips, chip);
}

/** A vTPM's state key overwritten, its entry and replay stand gone. */
static bool shredVtpm(const char *hostData) {
  return newVtpmKey(hostData) && storeDrop("vtpm", hostData) && storeDrop("replay", hostData);
}

/**
 * A fresh installation on the VM's main disk: the old key and the old vTPM
 * state shredded, then bound again as new with the initdata sent.
 */
static const char *reprovision(json_t p, const char *diskId) {

  bao_entry_t att = storeGet("attachments", diskId);
  char oldHd[80];
  text_t t = TEXT`${att.found ? att.payload().get("host_data").text() : ""}`;
  t.into(oldHd, sizeof oldHd);
  att.release();

  if (!newDiskKey(diskId))
    return "cannot overwrite the disk key (OpenBao)";

  if (isHex(oldHd, 64) && !shredVtpm(oldHd))
    return "cannot shred the old vTPM state (OpenBao)";

  if (!storeDrop("attachments", diskId))
    return "cannot remove the old binding (OpenBao)";

  storeResetLease(diskId);

  return attach(p, diskId, true);
}

/** Crypto-shredding: the keys are overwritten (KV v1 keeps no versions). */
static const char *deleteDisk(const char *diskId) {

  bool failed = false;
  const char *wrong = NULL;

  json_t deleting = meta_toJSON("{\"status\":\"deleting\"}");
  bool marked = storeSet("disks", diskId, deleting);
  deleting.release();

  if (!marked)
    return "cannot mark the disk (OpenBao)";

  /* an attach racing this one sees "deleting"; this one sees its binding */
  bao_entry_t att = storeGet("attachments", diskId);
  bool attached = att.found || att.failed;
  att.release();

  if (attached) {
    json_t active = meta_toJSON("{\"status\":\"active\"}");
    storeSet("disks", diskId, active);
    active.release();
    return "disk is attached to a VM";
  }

  if (!newDiskKey(diskId))
    return "cannot overwrite the disk key (OpenBao)";

  json_t keys = baoList("vtpm/", &failed);
  json_t list = keys.get("data").get("keys");

  for (int i = 0; !failed && i < list.count(); ++i) {

    char hd[80];
    text_t name = TEXT`${list.at(i).text() ?: ""}`;
    name.into(hd, sizeof hd);

    bao_entry_t v = storeGet("vtpm", hd);
    bool ours = v.found && strcmp(v.payload().get("disk_id").text() ?: "", diskId) == 0;
    v.release();

    if (!ours)
      continue;

    if (!shredVtpm(hd))
      wrong = "cannot shred a vTPM state key (OpenBao)";
  }

  keys.release();

  if (failed)
    return "cannot list the vTPMs (OpenBao)";

  if (wrong == NULL) {
    json_t deleted = meta_toJSON("{\"status\":\"deleted\"}");
    storeSet("disks", diskId, deleted);
    deleted.release();
  }

  return wrong;
}

/** Files a delete_disk request for the customer to decide. */
static void askToShred(const char *diskId, const char *vm, const char *vmName) {

  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *p = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, p);
  yyjson_mut_obj_add_strcpy(doc, p, "disk_id", diskId);
  yyjson_mut_obj_add_strcpy(doc, p, "vm_uuid", vm);
  yyjson_mut_obj_add_strcpy(doc, p, "vm_name", vmName);
  char *payload = yyjson_mut_write(doc, 0, NULL);
  yyjson_mut_doc_free(doc);

  static const char note[] =
      "[[null, \"the VM was deleted; approving shreds the key of its system disk for good\"]]";

  sql_t q = SQL`insert into requests (type, payload, status, checks)
    values ('delete_disk', ${payload ?: "{}"}::JSONB, 'pending', ${note}::JSONB)`;
  dbDo(&q);
  q.release();
  free(payload);
}

/** Carries out an approved request: keys, bindings, policy. NULL or why not. */
static const char *apply(const char *type, json_t p) {

  char diskBuf[48];
  const char *diskId = diskOf(type, p, diskBuf);
  const char *wrong = NULL;
  char key[200];

  if (strcmp(type, "unlock") == 0)
    return NULL;

  if (strcmp(type, "create") == 0 || strcmp(type, "create_volume") == 0) {

    bool system = strcmp(type, "create") == 0;
    bool taken = false;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *d = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, d);
    yyjson_mut_obj_add_str(doc, d, "status", "creating");
    yyjson_mut_obj_add_str(doc, d, "kind", system ? "system" : "volume");
    yyjson_mut_obj_add_int(doc, d, "created", (int64_t)time(NULL));

    text_t at = TEXT`disks/${diskId}`;
    at.into(key, sizeof key);

    bool made = baoCreate(key, doc, &taken);
    yyjson_mut_doc_free(doc);

    if (!made)
      return taken ? "disk ID is taken" : "cannot write the disk (OpenBao)";

    /* the key is made here, at the customer's, and goes only into their OpenBao */
    if (!newDiskKey(diskId))
      return "cannot write the disk key (OpenBao)";

    if (system && (wrong = attach(p, diskId, true)) != NULL)
      return wrong;

    json_t active = meta_toJSON("{\"status\":\"active\"}");
    bool done = storeSet("disks", diskId, active);
    active.release();

    if (!done)
      return "cannot mark the disk active (OpenBao)";

  } else if (strcmp(type, "attach") == 0) {

    bool boot = p.get("boot").truth();

    /* booted from, it gets the VM's vTPM; a data volume finds the VM's own */
    if ((wrong = attach(p, diskId, boot)) != NULL)
      return wrong;

    if (boot) {
      json_t booted = meta_toJSON("{\"booted\":true}");
      storeSet("disks", diskId, booted);
      booted.release();
    }

    /* a delete racing this one: whoever comes second sees the other */
    bao_entry_t disk = storeGet("disks", diskId);
    bool active = disk.found && strcmp(disk.payload().get("status").text() ?: "", "active") == 0;
    disk.release();

    if (!active) {
      storeDrop("attachments", diskId);
      return "disk is being deleted";
    }

  } else if (strcmp(type, "add_host") == 0) {

    text_t at = TEXT`attachments/${diskId}`;
    at.into(key, sizeof key);

    baoEdit(key, addChip, (void *)(p.get("chip_id").text() ?: ""));

  } else if (strcmp(type, "detach") == 0) {

    if (!storeDrop("attachments", diskId))
      return "cannot remove the binding (OpenBao)";

    storeResetLease(diskId);

    /* the VM is gone, and with it its system disk on the host. The key stays
       until the customer says so: a provider that deletes VMs must not be
       able to make the customer's backups of them unreadable */
    if (isSystemDisk(diskId))
      askToShred(diskId, p.get("vm_uuid").text(), p.get("vm_name").text());

  } else if (strcmp(type, "reprovision") == 0) {

    if ((wrong = reprovision(p, diskId)) != NULL)
      return wrong;

  } else if (strcmp(type, "delete_disk") == 0) {

    if ((wrong = deleteDisk(diskId)) != NULL)
      return wrong;

  } else {
    return "unknown request type";
  }

  return pushPolicy();
}

/* ---------------------------------------------------- submit and decide */

/**
 * Decides a request this worker holds (status 'deciding'): checked once more,
 * since the state may have changed since it came in, then carried out.
 */
static void finish(long id, const char *type, json_t p, bool approve, const char *by) {

  const char *status = "denied";
  char reason[600] = "denied by the customer";

  if (approve) {

    checks_t checks = checksNew();
    validate(&checks, type, p);

    if (checks.failures > 0) {
      status = "rejected";
      text_t why = TEXT`on approval: ${checks.failed.at}`;
      why.into(reason, sizeof reason);
    } else {
      const char *wrong = apply(type, p);
      status = wrong == NULL ? "applied" : "error";
      text_t why = TEXT`${wrong ?: ""}`;
      why.into(reason, sizeof reason);
    }

    checks.release();
  }

  sql_t q = SQL`update requests set status = ${status}, reason = ${(const char *)reason},
    decided = now(), decided_by = ${by} where id = ${id}`;
  dbDo(&q);
  q.release();
}

/** Takes a pending request for deciding; false if it is not pending (any more). */
static bool claim(long id, char **type, char **payload) {

  sql_t q = SQL`update requests set status = 'deciding'
    where id = ${id} and status = 'pending' returning type, payload::TEXT`;
  PGresult *r = dbAsk(&q);
  q.release();

  bool got = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (got) {
    *type = strdup(PQgetvalue(r, 0, 0));
    *payload = strdup(PQgetvalue(r, 0, 1));
  }

  if (r != NULL)
    PQclear(r);

  return got;
}

/** The customer's decision (UI or API). */
static void decide(long id, bool approve, const char *by) {

  char *type = NULL, *payload = NULL;

  if (!claim(id, &type, &payload))
    return;

  json_t p = meta_toJSON(payload);
  finish(id, type, p, approve, by);
  p.release();

  free(type);
  free(payload);
}

/**
 * A request from the control plane. Rejected when a check fails, applied at
 * once when it only takes rights away or an auto rule allows it, otherwise
 * left for the customer. Answers its ID, or -1.
 */
static long submit(const char *type, json_t p) {

  checks_t checks = checksNew();
  bool automatic = validate(&checks, type, p);
  const char *status = "pending", *by = "";
  char reason[600] = "";

  if (checks.failures > 0) {
    status = "rejected";
    by = "agent";
    text_t why = TEXT`checks failed: ${checks.failed.at}`;
    why.into(reason, sizeof reason);
  } else if (strcmp(type, "detach") == 0) {
    status = "deciding";
    by = "agent (only takes rights away)";
  } else if (automatic) {
    status = "deciding";
    by = "auto rule";
  }

  char *checksJson = checks.json();
  char *payload = yyjson_val_write(p.node, 0, NULL);
  long id = -1;

  sql_t q = SQL`insert into requests (type, payload, status, reason, checks, decided, decided_by)
    values (${type}, ${payload ?: "{}"}::JSONB, ${status}, ${(const char *)reason},
            ${checksJson ?: "[]"}::JSONB, case when ${by}::TEXT = '' then null else now() end, ${by})
    returning id`;
  PGresult *r = dbAsk(&q);
  q.release();

  if (r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1)
    id = atol(PQgetvalue(r, 0, 0));

  if (r != NULL)
    PQclear(r);

  free(checksJson);
  free(payload);
  checks.release();

  if (id > 0 && strcmp(status, "deciding") == 0)
    finish(id, type, p, true, by);

  return id;
}

/** {"id":..,"status":..,"reason":..} of a request into `out`; false if there is none. */
static bool requestState(long id, buf_t *out) {

  sql_t q = SQL`select json_build_object('id', id, 'status', status, 'reason', reason)::TEXT
    from requests where id = ${id}`;
  PGresult *r = dbAsk(&q);
  q.release();

  bool found = r != NULL && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;

  if (found)
    buf_t__put(out, PQgetvalue(r, 0, 0));

  if (r != NULL)
    PQclear(r);

  return found;
}

#endif /* WX_REQUESTS_H */

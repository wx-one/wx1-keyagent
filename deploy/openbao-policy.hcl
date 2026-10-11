# What wx1-keyagent may do in the customer's OpenBao, and nothing more.
#
#   bao secrets enable -path=transit transit          (once, by the operator)
#   bao policy write wx1-keyagent deploy/openbao-policy.hcl
#   bao token create -policy=wx1-keyagent -period=768h -field=token > /secrets/openbao-token
#
# With another mount than transit/ (WX_OPENBAO_TRANSIT), the paths here
# change with it. kv/ is the KBS's: the vTPM state keys, which the agent
# writes through the KBS admin API and never reads.

# Disk keys (wx1-disk-*), the guest keys of one release (wx1-guest-*), the
# start-up check's (wx1-check-*), the state key (wx1-state): made,
# configured, destroyed.
path "transit/keys/wx1-*" {
  capabilities = ["create", "read", "update", "delete"]
}

# A disk key leaves transit only wrapped for the guest's key.
path "transit/byok-export/wx1-guest-*" {
  capabilities = ["read"]
}

# Importing a key (the start-up check, the takeover of old keys) wraps it
# for transit's own key.
path "transit/wrapping_key" {
  capabilities = ["read"]
}

# The state in the database: signed, and checked when read.
path "transit/hmac/wx1-state/*" {
  capabilities = ["update"]
}

path "transit/verify/wx1-state/*" {
  capabilities = ["update"]
}

# Never in the clear, not even for the agent.
path "transit/export/*" {
  capabilities = ["deny"]
}

path "transit/backup/*" {
  capabilities = ["deny"]
}

# Only for taking over an installation of 0.0.5 or before (wx/ and the disk
# keys in kv/disk/); remove these once the agent logged "import done".
path "wx/data/*" {
  capabilities = ["read"]
}

path "wx/metadata/*" {
  capabilities = ["read", "list"]
}

path "kv/disk/*" {
  capabilities = ["read", "delete"]
}

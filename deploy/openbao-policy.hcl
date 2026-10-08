# What wx1-keyagent may do in the customer's OpenBao, and nothing more.
#
#   bao secrets enable -path=wx -version=2 kv        (once, by the operator)
#   bao policy write wx1-keyagent deploy/openbao-policy.hcl
#   bao token create -policy=wx1-keyagent -period=768h -field=token > /secrets/openbao-token
#
# kv/ is the KBS's (KV v1); the KBS reads it with a token of its own.

# Disk keys: made, overwritten when shredded, read to hand them out sealed to
# an attested guest.
path "kv/disk/*" {
  capabilities = ["create", "update", "read"]
}

# vTPM state keys: made and overwritten, never read. Only the KBS gives them
# out, and only to the SVSM of exactly that VM.
path "kv/vtpm/*" {
  capabilities = ["create", "update"]
}

# The agent's own state (KV v2, check-and-set).
path "wx/data/*" {
  capabilities = ["create", "update", "read"]
}

path "wx/metadata/*" {
  capabilities = ["read", "list", "delete"]
}

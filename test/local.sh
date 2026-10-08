#!/bin/bash
# Runs the agent against a CockroachDB, an OpenBao and a KBS stub in Docker,
# then test/api.sh against it. Leaves nothing behind.
#
#   test/local.sh            builds the image first (build.sh)
#   NO_BUILD=1 test/local.sh uses wx/wx1-keyagent as it is
set -euo pipefail
cd "$(dirname "$0")/.."

NET=wx1ka-test
W=$(mktemp -d)
trap 'docker rm -f wx1ka-test-agent wx1ka-test-db wx1ka-test-bao wx1ka-test-kbs >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$W"' EXIT

[ -n "${NO_BUILD:-}" ] || ./build.sh >/dev/null

mkdir -p "$W/secrets" "$W/refs" "$W/kbs" "$W/kds"
echo -n cp-secret > "$W/secrets/cp-token"
echo -n customer-secret > "$W/secrets/customer-token"
echo -n kbs-secret > "$W/secrets/kbs-admin-token"
echo -n ui-secret > "$W/secrets/ui-password"
printf 'igvm_measurement=%s\nigvm_persist_measurement=%s\n' \
  "$(head -c 48 /dev/urandom | xxd -p -c 48)" "$(head -c 48 /dev/urandom | xxd -p -c 48)" > "$W/refs/manifest.txt"
cp test/kbs-stub.py "$W/kbs/"

# TLS for the API: a CA, the agent's certificate, the control plane's client
# certificate, and a stranger's from another CA
mkdir -p "$W/tls"
(
  cd "$W/tls"
  key() { openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "$@" 2>/dev/null; }
  key -x509 -days 1 -subj /CN=wx-test-ca -keyout ca.key -out ca.pem
  key -subj /CN=localhost -keyout agent.key -out agent.csr
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san
  openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile san -out agent.pem 2>/dev/null
  key -subj /CN=control-plane -keyout cp.key -out cp.csr
  openssl x509 -req -in cp.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out cp.pem 2>/dev/null
  key -subj /CN=other-plane -keyout other.key -out other.csr
  openssl x509 -req -in other.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out other.pem 2>/dev/null
  key -x509 -days 1 -subj /CN=stranger -keyout stranger.key -out stranger.pem
  chmod a+r ./*
)
chmod -R a+rX "$W"; chmod 777 "$W/kbs" "$W/kds"

docker network create $NET >/dev/null
docker run -d --name wx1ka-test-db --network $NET cockroachdb/cockroach:latest-v24.3 \
  start-single-node --insecure >/dev/null
docker run -d --name wx1ka-test-bao --network $NET -e BAO_DEV_ROOT_TOKEN_ID=root \
  -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 openbao/openbao:latest server -dev >/dev/null
docker run -d --name wx1ka-test-kbs --network $NET -v "$W/kbs":/out python:3-alpine python /out/kbs-stub.py >/dev/null

for i in $(seq 60); do
  docker exec wx1ka-test-db cockroach sql --insecure -e "create database if not exists keyagent" >/dev/null 2>&1 && break
  sleep 1
done
# as an operator would set it up: the KBS's kv/, the agent's wx/, and a token
# with the agent's policy only - the tests run without root
B="docker exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root wx1ka-test-bao bao"
$B secrets enable -version=1 -path=kv kv >/dev/null
$B secrets enable -version=2 -path=wx kv >/dev/null
$B policy write wx1-keyagent - < deploy/openbao-policy.hcl >/dev/null
$B token create -policy=wx1-keyagent -field=token > "$W/secrets/openbao-token"

docker run -d --name wx1ka-test-agent --network $NET -p 127.0.0.1::8095 \
  -v "$W/secrets":/secrets:ro -v "$W/refs":/refs:ro -v "$W/kds":/kds -v "$W/tls":/tls:ro \
  -e WX_TLS_CERT=/tls/agent.pem -e WX_TLS_KEY=/tls/agent.key \
  -e WX_CP_CLIENT_CA=/tls/ca.pem -e WX_CP_CLIENT_SUBJECT=/CN=control-plane \
  -e WX_DB='postgresql://root@wx1ka-test-db:26257/keyagent?sslmode=disable' \
  -e WX_OPENBAO_URL=http://wx1ka-test-bao:8200 -e WX_KBS_ADMIN_URL=http://wx1ka-test-kbs:8090 \
  -e WX_API_LISTEN=0.0.0.0:8095 -e WX_RELEASE_LISTEN=0.0.0.0:8091 -e WX_WORKERS=2 \
  wx/wx1-keyagent >/dev/null

PORT=$(docker port wx1ka-test-agent 8095 | head -1 | cut -d: -f2)
for i in $(seq 30); do curl -sf --cacert "$W/tls/ca.pem" "https://localhost:$PORT/health" >/dev/null && break; sleep 1; done

WX_API="https://localhost:$PORT" WX_TLS="$W/tls" WX_BAO=wx1ka-test-bao WX_DB_CONTAINER=wx1ka-test-db \
  WX_POLICY="$W/kbs/policy.rego" test/api.sh

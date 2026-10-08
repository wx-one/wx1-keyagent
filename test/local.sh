#!/bin/bash
# Runs the agent against a CockroachDB, an OpenBao and a KBS stub in Docker,
# then test/api.sh against it. Leaves nothing behind.
#
#   test/local.sh            builds the image first (build.sh)
#   NO_BUILD=1 test/local.sh uses wx/keyagent-meta as it is
set -euo pipefail
cd "$(dirname "$0")/.."

NET=wxka-test
W=$(mktemp -d)
trap 'docker rm -f wxka-test-agent wxka-test-db wxka-test-bao wxka-test-kbs >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$W"' EXIT

[ -n "${NO_BUILD:-}" ] || ./build.sh >/dev/null

mkdir -p "$W/secrets" "$W/refs" "$W/kbs" "$W/kds"
echo -n root > "$W/secrets/openbao-token"
echo -n cp-secret > "$W/secrets/cp-token"
echo -n customer-secret > "$W/secrets/customer-token"
echo -n kbs-secret > "$W/secrets/kbs-admin-token"
echo -n ui-secret > "$W/secrets/ui-password"
printf 'igvm_measurement=%s\nigvm_persist_measurement=%s\n' \
  "$(head -c 48 /dev/urandom | xxd -p -c 48)" "$(head -c 48 /dev/urandom | xxd -p -c 48)" > "$W/refs/manifest.txt"
cp test/kbs-stub.py "$W/kbs/"
chmod -R a+rX "$W"; chmod 777 "$W/kbs" "$W/kds"

docker network create $NET >/dev/null
docker run -d --name wxka-test-db --network $NET cockroachdb/cockroach:latest-v24.3 \
  start-single-node --insecure >/dev/null
docker run -d --name wxka-test-bao --network $NET -e BAO_DEV_ROOT_TOKEN_ID=root \
  -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 openbao/openbao:latest server -dev >/dev/null
docker run -d --name wxka-test-kbs --network $NET -v "$W/kbs":/out python:3-alpine python /out/kbs-stub.py >/dev/null

for i in $(seq 60); do
  docker exec wxka-test-db cockroach sql --insecure -e "create database if not exists keyagent" >/dev/null 2>&1 && break
  sleep 1
done
docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root wxka-test-bao \
  bao secrets enable -version=1 -path=kv kv >/dev/null

docker run -d --name wxka-test-agent --network $NET -p 127.0.0.1::8095 \
  -v "$W/secrets":/secrets:ro -v "$W/refs":/refs:ro -v "$W/kds":/kds \
  -e WX_DB='postgresql://root@wxka-test-db:26257/keyagent?sslmode=disable' \
  -e WX_OPENBAO_URL=http://wxka-test-bao:8200 -e WX_KBS_ADMIN_URL=http://wxka-test-kbs:8090 \
  -e WX_API_LISTEN=0.0.0.0:8095 -e WX_RELEASE_LISTEN=0.0.0.0:8091 -e WX_WORKERS=2 \
  wx/keyagent-meta >/dev/null

PORT=$(docker port wxka-test-agent 8095 | head -1 | cut -d: -f2)
for i in $(seq 30); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 1; done

WX_API="http://127.0.0.1:$PORT" WX_BAO=wxka-test-bao WX_DB_CONTAINER=wxka-test-db \
  WX_POLICY="$W/kbs/policy.rego" test/api.sh

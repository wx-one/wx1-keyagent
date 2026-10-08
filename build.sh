#!/bin/sh
# Builds the image wx/wx1-keyagent the way CI does: ci/build.sh in
# ubuntu:24.04 against meta from the wxone/meta image, then the release on
# the hardened Debian 13 seed (ci/Dockerfile.release).
#
#   ./build.sh                     META_IMAGE=wxone/meta:<tag> to pin meta
set -eu
cd "$(dirname "$0")"
META_IMAGE=${META_IMAGE:-wxone/meta:latest}
VERSION=0.0.0-local

docker pull -q "$META_IMAGE" >/dev/null
docker run --rm -v "$PWD":/src -w /src \
  -e META_REF="$(docker image inspect --format '{{index .RepoDigests 0}}' "$META_IMAGE")" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  --entrypoint bash "$META_IMAGE" -c '
    set -e
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      build-essential curl ca-certificates perl bzip2 xz-utils bison flex jq git >/dev/null 2>&1
    git config --global --add safe.directory /src
    ci/build.sh '"$VERSION"' >/dev/null
    chown -R "$HOST_UID:$HOST_GID" out'
docker build -q -f ci/Dockerfile.release --build-arg RELEASE="wx1-keyagent-$VERSION-linux-x86_64" \
  -t wx/wx1-keyagent out >/dev/null
echo wx/wx1-keyagent

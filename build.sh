#!/bin/sh
# Baut das Image. meta kommt aus dem Git-Stand von $META (nicht aus dem Arbeitsbaum:
# dort liegen host-spezifische Build-Artefakte).
#   ./build.sh            META=../../metalanguage
set -eu
cd "$(dirname "$0")"
META=${META:-../../metalanguage}
rm -rf build/meta-src && mkdir -p build/meta-src
git -C "$META" archive HEAD | tar -x -C build/meta-src
git -C "$META" rev-parse HEAD > build/meta-src/META_COMMIT
docker build --build-context meta=build/meta-src -t wx/keyagent-meta .

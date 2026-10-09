#!/bin/bash
# Writes src/assets.c and src/assets.h from assets/: the fonts of the UI as
# byte arrays, so the agent serves them itself and the UI asks no other
# server for anything. Plain C, compiled into the module as it is (no meta
# in it). Run after changing a file in assets/; the result is committed.
#
#   ci/assets.sh
set -euo pipefail
cd "$(dirname "$0")/.."

names=()
{
  echo "/* Written by ci/assets.sh from assets/ - do not edit. */"
  echo "#include <stddef.h>"
  for f in assets/*.woff2; do
    name=$(basename "$f" .woff2 | sed 's/-latin//; s/-normal//; s/[^a-z0-9]/_/g')
    names+=("$name")
    echo
    echo "/* $(basename "$f"), sha256 $(sha256sum "$f" | cut -d' ' -f1) */"
    echo "const unsigned char asset_${name}[] = {"
    od -An -v -tx1 "$f" | sed 's/ \([0-9a-f][0-9a-f]\)/0x\1,/g; s/^/ /'
    echo "};"
    echo "const size_t asset_${name}_size = sizeof asset_${name};"
  done
} > src/assets.c

{
  echo "/* Written by ci/assets.sh from assets/ - do not edit. The bytes are in assets.c. */"
  echo "#ifndef WX_ASSETS_H"
  echo "#define WX_ASSETS_H"
  echo
  echo "#include <stddef.h>"
  echo
  for name in "${names[@]}"; do
    echo "extern const unsigned char asset_${name}[];"
    echo "extern const size_t asset_${name}_size;"
  done
  echo
  echo "#endif /* WX_ASSETS_H */"
} > src/assets.h

echo "src/assets.c: $(wc -c < src/assets.c) bytes, src/assets.h: ${#names[@]} assets"

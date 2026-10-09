#!/bin/bash
# CycloneDX 1.6 SBOMs for wx1-keyagent, written from what the build knows
# rather than scanned for: the libraries are linked statically, and no
# scanner finds a version string inside a binary reliably.
#
#   ci/sbom.sh release <stage-dir> <version> > release.cdx.json
#       everything inside the release: the agent, the meta runtime, yyjson,
#       nginx and the libraries ci/deps.sh built - and glibc, which the host
#       provides (scope "excluded": linked dynamically, not shipped)
#
#   ci/sbom.sh image <release.cdx.json> <BASE-LIBS> <seed-ref> <image-ref> > image.cdx.json
#       what the image adds on top of its base: the release, and the Debian
#       packages its libraries were copied from. The base is named with its
#       digest; it carries a signed SBOM of its own.
#
# Needs jq. Reads DEPS (ci/deps.sh prefix), META_ROOT, META_REF, YYJSON_H, NGINX_VERSION,
# NGINX_SHA256, NGINX_URL and DBM_VERSION, DBM_URL, DBM_SHA256 from the environment.
set -euo pipefail

licence_of() {
  case "$1" in
    zlib) echo Zlib ;;
    openssl) echo Apache-2.0 ;;
    curl) echo curl ;;
    postgresql) echo PostgreSQL ;;
    yaml) echo MIT ;;
    pcre2) echo "BSD-3-Clause WITH PCRE2-exception" ;;
    nginx) echo BSD-2-Clause ;;
    yyjson) echo MIT ;;
    *) echo NOASSERTION ;;
  esac
}

# component <name> <version> <url> <sha256> <licence> [description]
component() {
  jq -n --arg n "$1" --arg v "$2" --arg u "$3" --arg h "$4" --arg l "$5" --arg d "${6:-}" '
    {type: "library", "bom-ref": ("pkg:generic/" + $n + "@" + $v), name: $n, version: $v,
     purl: ("pkg:generic/" + $n + "@" + $v + (if $u != "" then "?download_url=" + ($u | @uri) else "" end)),
     licenses: [ (if ($l | test(" WITH | AND | OR ")) then {expression: $l} else {license: {id: $l}} end) ],
     scope: "required"}
    + (if $h != "" then {hashes: [{alg: "SHA-256", content: $h}]} else {} end)
    + (if $u != "" then {externalReferences: [{type: "distribution", url: $u}]} else {} end)
    + (if $d != "" then {description: $d} else {} end)'
}

document() { # <metadata-component-json> <components-json-array>
  jq -n --argjson app "$1" --argjson comps "$2" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg serial "urn:uuid:$(cat /proc/sys/kernel/random/uuid)" '
    {bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: $serial, version: 1,
     metadata: {timestamp: $ts,
                tools: {components: [{type: "application", name: "wx1-keyagent ci/sbom.sh"}]},
                component: $app},
     components: $comps,
     dependencies: [{ref: $app["bom-ref"], dependsOn: [$comps[]["bom-ref"]]}]}'
}

case "${1:-}" in
release)
  stage=${2:?stage dir} version=${3:?version}
  comps=()

  while read -r name version_ url sum; do
    comps+=("$(component "$name" "$version_" "$url" "$sum" "$(licence_of "$name")" "built from source by ci/deps.sh, linked statically")")
  done < "$DEPS/SOURCES"

  comps+=("$(component nginx "$NGINX_VERSION" "$NGINX_URL" "$NGINX_SHA256" BSD-2-Clause "built from source, with the agent built in")")

  comps+=("$(component meta-db-migrate "$DBM_VERSION" "$DBM_URL" "$DBM_SHA256" MIT "libdbmigrate-core and its cockroachdb/pg driver, linked statically with the migrations from migrations/")")

  yyjson=$(sed -n 's/^#define YYJSON_VERSION_STRING "\(.*\)"/\1/p' "$YYJSON_H")
  comps+=("$(component yyjson "$yyjson" "" "" MIT "vendored in the meta runtime, linked statically")")

  # the typeface of the UI, embedded (src/assets.h, written by ci/assets.sh)
  for f in assets/*.woff2; do
    comps+=("$(jq -n --arg n "$(basename "$f")" --arg h "$(sha256sum "$f" | cut -d' ' -f1)" '
      {type: "file", "bom-ref": ("font:" + $n), name: $n, group: "Barlow", version: "5.2.5 (fontsource)",
       licenses: [{license: {id: "OFL-1.1"}}], hashes: [{alg: "SHA-256", content: $h}],
       description: "typeface of the UI, embedded in the module",
       externalReferences: [{type: "distribution", url: "https://www.npmjs.com/package/@fontsource/barlow"}]}')")
  done

  # the meta runtime: the program is written in meta and links its runtime
  comps+=("$(jq -n --arg commit "$("$META_ROOT/meta" --version | cut -d' ' -f2)" --arg ref "${META_REF:-unknown}" '
    {type: "library", "bom-ref": "pkg:generic/meta-runtime", name: "meta-runtime",
     version: $commit, properties: [{name: "meta:image", value: $ref}], licenses: [{license: {name: "proprietary (wx-one)"}}], scope: "required",
     description: "runtime of the meta compiler (libmeta_runtime.a and its headers), linked statically",
     externalReferences: [{type: "distribution", url: ("https://hub.docker.com/r/wxone/meta")}]}')")

  comps+=("$(jq -n '
    {type: "library", "bom-ref": "pkg:generic/glibc", name: "glibc", version: ">= 2.38",
     licenses: [{license: {id: "LGPL-2.1-or-later"}}], scope: "excluded",
     description: "provided by the host, linked dynamically (libc, libm, ld-linux); not part of the release"}')")

  # the files shipped, by their hashes
  for f in sbin/nginx bin/wx1-keyagent; do
    comps+=("$(jq -n --arg f "$f" --arg h "$(sha256sum "$stage/$f" | cut -d' ' -f1)" '
      {type: "file", "bom-ref": ("file:" + $f), name: $f, hashes: [{alg: "SHA-256", content: $h}]}')")
  done

  app=$(jq -n --arg v "$version" --arg c "$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
             --arg l "${WX_LICENSE:-EUPL-1.2}" '
    {type: "application", "bom-ref": ("pkg:github/wx-one/wx1-keyagent@" + $v), name: "wx1-keyagent",
     version: $v, purl: ("pkg:github/wx-one/wx1-keyagent@" + $v),
     licenses: [ (if $l == "NOASSERTION" then {license: {name: "NOASSERTION"}} else {license: {id: $l}} end) ],
     externalReferences: [{type: "vcs", url: "https://github.com/wx-one/wx1-keyagent"}],
     properties: [{name: "git:commit", value: $c}]}')

  document "$app" "$(printf '%s\n' "${comps[@]}" | jq -s .)"
  ;;

image)
  release=${2:?release sbom} baselibs=${3:?BASE-LIBS} seed=${4:?seed ref} image=${5:?image ref}
  comps=()

  # the release as one component, with what is inside it nested
  comps+=("$(jq '.metadata.component + {components: [.components[] | select(.scope != "excluded")]}' "$release")")

  # the libraries copied from Debian, by their packages
  while read -r pkg version_ src srcversion; do
    case "$src" in glibc) l=LGPL-2.1-or-later ;; gcc-*) l="GPL-3.0-or-later WITH GCC-exception-3.1" ;; *) l=NOASSERTION ;; esac
    comps+=("$(jq -n --arg p "$pkg" --arg v "$version_" --arg s "$src" --arg sv "$srcversion" --arg l "$l" '
      {type: "library", "bom-ref": ("pkg:deb/debian/" + $p + "@" + $v), name: $p, version: $v,
       purl: ("pkg:deb/debian/" + $p + "@" + $v + "?arch=amd64&distro=debian-13"),
       licenses: [ (if ($l | test(" WITH ")) then {expression: $l} else {license: {id: $l}} end) ],
       description: ("copied from Debian 13 for the release (source package " + $s + " " + $sv + ")")}')")
  done < "$baselibs"

  comps+=("$(jq -n --arg s "$seed" '
    {type: "container", "bom-ref": "base-image", name: ($s | split("@")[0]), version: ($s | split("@")[1]),
     description: "hardened runtime seed of container.gov.de (Secure Government Container Initiative); its own signed CycloneDX SBOM is attached to it in its registry",
     externalReferences: [{type: "distribution", url: ("https://" + ($s | split("@")[0]))}]}')")

  app=$(jq -n --arg i "$image" --arg v "$(jq -r .metadata.component.version "$release")" '
    {type: "container", "bom-ref": ("image:" + $i), name: $i, version: $v}')

  document "$app" "$(printf '%s\n' "${comps[@]}" | jq -s .)"
  ;;

*)
  sed -n '2,19p' "$0"; exit 2 ;;
esac

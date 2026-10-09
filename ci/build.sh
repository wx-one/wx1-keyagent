#!/bin/bash
# Builds wx1-keyagent against meta at /opt/meta (the wxone/meta image) and
# packs a release: nginx, the module, a start script, the policy and the docs.
#
#   ci/build.sh [version]        writes out/wx1-keyagent-<version>-linux-x86_64.tar.gz
#
# Needs: /opt/meta (meta, its headers, lib/libmeta_runtime.a), gcc, make,
# curl, perl, bzip2, xz. Every library but glibc is built from pinned sources
# by ci/deps.sh and linked statically; what the release asks of a host is
# glibc, nothing else. The same on a CI runner (ubuntu-24.04) and in
# `docker run ubuntu:24.04`.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:-dev}
META_ROOT=${META_ROOT:-/opt/meta}
export NGINX_VERSION=1.26.3
export NGINX_SHA256=69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa
export NGINX_URL=https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
NAME=wx1-keyagent-$VERSION-linux-x86_64
OUT=$PWD/out
WORK=$OUT/work
STAGE=$WORK/$NAME

[ -x "$META_ROOT/meta" ] || { echo "no meta at $META_ROOT" >&2; exit 2; }
# an installed meta (the runtime as an archive), not a checkout
"$META_ROOT/meta" -print-config | grep -q '^runtime-archive=/' \
  || { echo "meta at $META_ROOT has no runtime archive (a checkout, not an installation?)" >&2; exit 2; }
export YYJSON_H=$("$META_ROOT/meta" -print-config | sed -n 's/^vendored-yyjson=//p')

# meta-db-migrate: the migrations are compiled in, the library linked in
export DBM_VERSION=0.3.0
export DBM_SHA256=639cc82b45b9fab45621c561ed87bb365d2f15714dc68b47640d89102017b925
export DBM_URL=https://github.com/db-migrate/meta-db-migrate/releases/download/v$DBM_VERSION/meta-db-migrate-v$DBM_VERSION-linux-x86_64-glibc2.39.tar.gz
export DBM=$OUT/meta-db-migrate-$DBM_VERSION
if [ ! -f "$DBM/lib/libdbmigrate-core.a" ]; then
  mkdir -p "$OUT/sources" "$DBM"
  dbmTar=$OUT/sources/$(basename "$DBM_URL")
  [ -f "$dbmTar" ] || curl -fsSL "$DBM_URL" -o "$dbmTar"
  echo "$DBM_SHA256  $dbmTar" | sha256sum -c --quiet -
  tar -xzf "$dbmTar" -C "$DBM" --strip-components=2 opt/meta-db-migrate
fi

export DEPS=${DEPS:-$OUT/deps}
export META_ROOT
[ -f "$DEPS/SOURCES" ] || ci/deps.sh "$DEPS"

rm -rf "$WORK" && mkdir -p "$WORK/addon-h" "$STAGE"

INCS="-I$DEPS/include -I$DBM/include"
L=$DEPS/lib
# the module's libraries, as archives: nothing for the dynamic linker to find
STATIC_LIBS="$L/libpq.a $L/libpgcommon_shlib.a $L/libpgport_shlib.a $L/libcurl.a $L/libyaml.a $L/libssl.a $L/libcrypto.a $L/libz.a"

# ---------------------------------------------------------------- lower
# the headers one by one (they carry meta syntax), then the program as a
# module, with the migrations compiled into it. These go under a path that
# ends in migrations/<name>.c: meta-db-migrate names each one after its
# __FILE__, as node db-migrate does.
(cd src && "$META_ROOT/meta" -s -I . $INCS -emit-each "$WORK/addon-h" ./*.h)

mkdir -p "$WORK/migrations"
MODULE_SRCS=()
for m in migrations/*.c; do
  "$META_ROOT/meta" -s -I src $INCS -emit "$WORK/migrations/$(basename "$m")" "$m"
  MODULE_SRCS+=(-module-src "$WORK/migrations/$(basename "$m")")
done

# the link line after meta's own (-lpq -lcurl and the runtime archive):
# db-migrate whole, since its driver registers itself from a constructor
# that nothing names; the runtime once more behind it, which db-migrate's
# core uses; then every library as an archive
RUNTIME=$("$META_ROOT/meta" -print-config | sed -n 's/^runtime-archive=//p')
(cd src && "$META_ROOT/meta" -s -I . $INCS "${MODULE_SRCS[@]}" \
  -module-lib "-Wl,--whole-archive $DBM/lib/libdbmigrate-cockroachdb.a $DBM/lib/libdbmigrate-core.a -Wl,--no-whole-archive" \
  -module-lib "$RUNTIME $STATIC_LIBS -lpthread -ldl -lm" \
  -module "$WORK/addon" main.c)
cp "$WORK"/addon-h/*.h "$WORK/addon/"

# ---------------------------------------------------------------- nginx
tarball=$OUT/nginx-$NGINX_VERSION.tar.gz
[ -f "$tarball" ] || curl -fsSL "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" -o "$tarball"
echo "$NGINX_SHA256  $tarball" | sha256sum -c --quiet -
tar -xzf "$tarball" -C "$WORK"

(
  cd "$WORK/nginx-$NGINX_VERSION"
  # the prefix the release unpacks to; every path is also given at start
  ./configure --prefix=/opt/wx1-keyagent --with-compat --with-http_ssl_module \
    --with-cc-opt="-O2 -fstack-protector-strong -Wno-error -I$WORK/addon $INCS" \
    --with-ld-opt="-L$L" \
    --without-http_rewrite_module --without-http_gzip_module --without-http_auth_basic_module \
    --add-dynamic-module="$WORK/addon" >"$WORK/configure.log" 2>&1 \
    || { tail -20 "$WORK/configure.log" >&2; exit 1; }
  make -j"$(nproc)" >"$WORK/make.log" 2>&1 || { grep -E "error:|undefined reference|relocation" "$WORK/make.log" | grep -v Werror | head -20 >&2; exit 1; }
)

# ---------------------------------------------------------------- pack
mkdir -p "$STAGE/sbin" "$STAGE/modules" "$STAGE/bin"
cp "$WORK/nginx-$NGINX_VERSION/objs/nginx" "$STAGE/sbin/nginx"
cp "$WORK/nginx-$NGINX_VERSION/objs/ngx_http_meta_module.so" "$STAGE/modules/"
cp ci/wx1-keyagent ci/wx1-keyagent.service "$STAGE/bin/" 2>/dev/null || true
mv "$STAGE/bin/wx1-keyagent.service" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/bin/wx1-keyagent"
cp -r deploy doc README.md "$STAGE/"
# the licence of everything inside, as the licences ask: nginx, the libraries
# from their sources, yyjson from the header the meta runtime vendors
{
  echo "wx1-keyagent $VERSION contains the following third-party software."
  echo "Each is listed with its licence, as found in the source it was built from."
  section() { printf '\n\n================================================================\n%s\n================================================================\n\n' "$1"; }
  section "nginx $NGINX_VERSION (BSD-2-Clause)"
  cat "$WORK/nginx-$NGINX_VERSION/LICENSE"
  while read -r name version url sum; do
    section "$name $version"
    cat "$DEPS/licenses/$name"
  done < "$DEPS/SOURCES"
  section "yyjson $(sed -n 's/^#define YYJSON_VERSION_STRING "\(.*\)"/\1/p' "$YYJSON_H") (MIT), vendored in the meta runtime"
  sed -n '2,20p' "$YYJSON_H"
  section "meta-db-migrate $DBM_VERSION (MIT), linked statically with the migrations"
  cat "$DBM/share/doc/meta-db-migrate/LICENSE"
  section "glibc (LGPL-2.1-or-later)"
  echo "Not included: linked dynamically and provided by the host system."
} > "$STAGE/THIRD_PARTY_NOTICES"

{
  echo "wx1-keyagent $VERSION"
  echo "commit $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "nginx $NGINX_VERSION"
  echo "meta $("$META_ROOT/meta" --version | cut -d" " -f2) (${META_REF:-image unknown})"
  while read -r name version url sum; do echo "$name $version"; done < "$DEPS/SOURCES"
  echo "meta-db-migrate $DBM_VERSION"
  echo "migrations $(ls migrations | tr '\n' ' ')"
  echo "built on $(. /etc/os-release && echo "$PRETTY_NAME")"
} > "$STAGE/BUILD"

ci/sbom.sh release "$STAGE" "$VERSION" > "$OUT/$NAME.cdx.json"
cp "$OUT/$NAME.cdx.json" "$STAGE/SBOM.cdx.json"

tar -czf "$OUT/$NAME.tar.gz" -C "$WORK" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" "$NAME.cdx.json" > "$NAME.sha256")
echo "$OUT/$NAME.tar.gz"

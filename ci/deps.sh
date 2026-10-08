#!/bin/bash
# Builds the libraries wx1-keyagent links statically, from pinned sources:
# OpenSSL, curl, libpq, libyaml, PCRE2, zlib - everything but glibc, which
# stays dynamic (DNS and NSS work the way they do for every other program on
# the host). All with -fPIC, because they end up in nginx's module.
#
#   ci/deps.sh <prefix>       installs into <prefix>/{include,lib}, prints nothing on success
#
# Every source is checked by SHA-256 (OpenSSL's and PostgreSQL's against their
# published sums, curl's and zlib's against their GitHub releases as well).
# The same versions go into both releases, and into the SBOM.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX=${1:?prefix}
CACHE=${DEPS_CACHE:-$PWD/out/sources}
WORK=$PREFIX/.build
JOBS=$(nproc)

# name version url sha256
SOURCES=(
  "zlib 1.3.2 https://zlib.net/zlib-1.3.2.tar.gz bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
  "openssl 3.5.9 https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
  "curl 8.22.0 https://curl.se/download/curl-8.22.0.tar.xz f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7"
  "postgresql 18.6 https://ftp.postgresql.org/pub/source/v18.6/postgresql-18.6.tar.bz2 555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f"
  "yaml 0.2.5 https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4"
  "pcre2 10.49 https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.49/pcre2-10.49.tar.bz2 53c156e1ba416a20da8e65395daa132da0d80e76910424caca3fcdae7831d384"
)

mkdir -p "$CACHE" "$WORK" "$PREFIX/include" "$PREFIX/lib" "$PREFIX/licenses"

# keep <name> <file>: the licence text, from the source as built, for THIRD_PARTY_NOTICES
keep() { cp "$2" "$PREFIX/licenses/$1"; }

export CFLAGS="-O2 -fPIC -fstack-protector-strong"
export CPPFLAGS="-I$PREFIX/include"
export LDFLAGS="-L$PREFIX/lib"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig"

# unpack <name>: fetched once into the cache, checked, unpacked fresh
unpack() {
  local entry name version url sum file
  for entry in "${SOURCES[@]}"; do
    read -r name version url sum <<<"$entry"
    [ "$name" = "$1" ] || continue
    file=$CACHE/$(basename "$url")
    [ -f "$file" ] || curl -fsSL "$url" -o "$file"
    echo "$sum  $file" | sha256sum -c --quiet -
    rm -rf "$WORK/$name-$version"
    tar -xf "$file" -C "$WORK"
    cd "$WORK/$name-$version"
    return 0
  done
  echo "unknown source $1" >&2
  exit 1
}

log() { "$@" >"$WORK/last.log" 2>&1 || { tail -30 "$WORK/last.log" >&2; exit 1; }; }

( unpack zlib
  keep zlib LICENSE
  log ./configure --prefix="$PREFIX" --static
  log make -j"$JOBS" install )

# OPENSSLDIR is a path of its own that does not exist on the host: a static
# OpenSSL reading the distribution's openssl.cnf - written for another
# version - is how a quiet incompatibility starts. The CA file is found by
# bin/wx1-keyagent and handed over as SSL_CERT_FILE.
( unpack openssl
  keep openssl LICENSE.txt
  log ./Configure linux-x86_64 --prefix="$PREFIX" --libdir=lib \
    --openssldir=/opt/wx1-keyagent/ssl no-shared no-module no-tests no-docs \
    no-legacy no-engine no-comp zlib -fPIC
  log make -j"$JOBS"
  log make install_sw )

# only what the agent speaks: HTTP and HTTPS through OpenSSL, nothing that
# would pull in GnuTLS, LDAP, libssh, IDN or other libraries
( unpack curl
  keep curl COPYING
  log ./configure --prefix="$PREFIX" --disable-shared --enable-static --with-pic \
    --with-openssl="$PREFIX" --with-zlib="$PREFIX" --with-ca-fallback \
    --without-ca-bundle --without-ca-path \
    --without-libpsl --without-libidn2 --without-brotli --without-zstd --without-nghttp2 \
    --without-nghttp3 --without-ngtcp2 --without-libssh2 --without-libssh --without-librtmp \
    --without-gssapi --disable-ldap --disable-ldaps --disable-dict --disable-gopher \
    --disable-imap --disable-pop3 --disable-smtp --disable-telnet --disable-tftp \
    --disable-rtsp --disable-mqtt --disable-file --disable-ftp --disable-smb --disable-ipfs \
    --disable-manual --disable-docs
  log make -j"$JOBS" install )

# libpq alone, with the two static helpers it needs, and without Kerberos,
# LDAP, readline or ICU
( unpack postgresql
  keep postgresql COPYRIGHT
  log ./configure --prefix="$PREFIX" --with-openssl --without-readline --without-icu \
    --without-gssapi --without-ldap --without-zlib --without-zstd --without-lz4
  log make -C src/include install
  log make -C src/common -j"$JOBS" install
  log make -C src/port -j"$JOBS" install
  # only the static archive: the shared library's own check ("must not call
  # exit") trips over pthread_exit in the static OpenSSL, and nothing here
  # links the shared one
  log make -C src/interfaces/libpq -j"$JOBS" libpq.a
  cp src/interfaces/libpq/libpq.a "$PREFIX/lib/"
  cp src/interfaces/libpq/libpq-fe.h src/interfaces/libpq/libpq-events.h "$PREFIX/include/" )

( unpack yaml
  keep yaml License
  log ./configure --prefix="$PREFIX" --disable-shared --enable-static --with-pic
  log make -j"$JOBS" install )

( unpack pcre2
  keep pcre2 LICENCE.md
  log ./configure --prefix="$PREFIX" --disable-shared --enable-static --with-pic --disable-pcre2grep-libz
  log make -j"$JOBS" install )

# nothing dynamic may be left for the linker to prefer
find "$PREFIX/lib" -name '*.so*' -delete

# what was built, for the SBOM
for entry in "${SOURCES[@]}"; do
  read -r name version url sum <<<"$entry"
  printf '%s %s %s %s\n' "$name" "$version" "$url" "$sum"
done > "$PREFIX/SOURCES"

rm -rf "$WORK"

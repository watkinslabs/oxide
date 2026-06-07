#!/usr/bin/sh
# GNU wget 1.21.4 build recipe — static-musl binaries checked in as
# `vendor/wget/wget-{x86_64,aarch64}`.
#
# Links the ALREADY-VENDORED openssl + zlib (same convention as
# vendor/openssh/build.sh, which links vendor/openssl/install-<arch> +
# vendor/zlib/install-<arch>). Built from source — NO prebuilt.
#
# Minimal feature set to avoid unvendored deps:
#   --with-ssl=openssl --with-openssl=yes  — TLS via vendored openssl
#   --without-libpsl                       — no public-suffix-list lib
#   --disable-nls                          — no gettext
#   --disable-iri                          — no libidn2/libunistring
#   --disable-shared --enable-static       — static musl link
# zlib provides gzip/deflate transfer decoding. PKG_CONFIG=/bin/false
# forces wget to use the explicit OPENSSL_CFLAGS/OPENSSL_LIBS we hand it
# rather than probing the host pkgconfig (which would find system openssl).
#
# Re-run to rebuild against fresh upstream (run tools/fetch-wget.sh first
# to populate the source tree).
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="wget-1.21.4"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-wget.sh first" >&2
  exit 1
fi

REPO="$(cd ../.. && pwd)"

# Confirm vendored dep paths up front (openssh build.sh convention).
echo "=== vendored openssl x86_64 ==="
ls "$REPO/vendor/openssl/install-x86_64/lib"
echo "=== vendored zlib x86_64 ==="
ls "$REPO/vendor/zlib/install-x86_64/lib"

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

# wget autoconf cross-build: a couple of guard tests it can't run on the
# host target. All values reflect Linux/musl reality.
config_cache() {
  cat > config.cache <<'EOF'
ac_cv_func_malloc_0_nonnull=yes
ac_cv_func_realloc_0_nonnull=yes
gl_cv_func_malloc_0_nonnull=1
ac_cv_func_working_mktime=yes
EOF
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"
  ssl_root="$REPO/vendor/openssl/install-${arch}"
  zlib_root="$REPO/vendor/zlib/install-${arch}"
  echo "=== building wget for $arch (vendored openssl + zlib) ==="
  cleanup_objs
  config_cache
  cp config.cache "$SRC/config.cache"
  ( cd "$SRC" && \
    CC="$cc" \
    ./configure \
      --cache-file=config.cache \
      --host="${arch}-linux-musl" \
      --disable-shared \
      --enable-static \
      --with-ssl=openssl \
      --with-openssl=yes \
      --without-libpsl \
      --disable-nls \
      --disable-iri \
      OPENSSL_CFLAGS="-I${ssl_root}/include" \
      OPENSSL_LIBS="-L${ssl_root}/lib -lssl -lcrypto" \
      CPPFLAGS="-I${zlib_root}/include -I${ssl_root}/include $extra" \
      LDFLAGS="-static -L${zlib_root}/lib -L${ssl_root}/lib" \
      CFLAGS="-static $extra" \
      PKG_CONFIG=/bin/false \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/src/wget" "wget-$suffix"
  strip "wget-$suffix" 2>/dev/null \
    || "${cc%gcc}strip" "wget-$suffix" 2>/dev/null \
    || true
  echo "  → wget-$suffix  ($(stat -c %s "wget-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64"

echo "OK — built wget for {x86_64, aarch64}"

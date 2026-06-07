#!/usr/bin/sh
# curl 8.11.0 build recipe — pre-built static-musl binaries checked in
# as `vendor/curl/curl-{x86_64,aarch64}`.
#
# Links the ALREADY-VENDORED openssl (vendor/openssl/install-<arch>)
# and zlib (vendor/zlib/install-<arch>) — same convention as
# vendor/openssh/build.sh. Static-musl so the binary runs pre-dynamic-
# linker. Per CLAUDE.md no-deferrals: only openssl + zlib are linked;
# every other optional backend is disabled rather than half-wired:
#   --with-openssl=<repo>/vendor/openssl/install-<arch>  — TLS
#   --with-zlib=<repo>/vendor/zlib/install-<arch>        — compression
#   --without-libpsl --without-brotli --without-zstd     — not vendored
#   --without-nghttp2 --without-nghttp3 --without-ngtcp2 — not vendored
#   --without-libssh2 --disable-ldap --disable-ldaps     — not vendored
#   --without-libidn2 --without-librtmp                  — not vendored
#   --disable-docs                                       — no manpages
#
# Re-run to rebuild against fresh upstream (run tools/fetch-curl.sh
# first to populate the source tree).
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="curl-8.11.0"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-curl.sh first" >&2
  exit 1
fi

REPO="$(cd ../.. && pwd)"
CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"
  ssl_root="${REPO}/vendor/openssl/install-${arch}"
  zlib_root="${REPO}/vendor/zlib/install-${arch}"
  echo "=== building curl for $arch (openssl=${ssl_root} zlib=${zlib_root}) ==="
  cleanup_objs
  # Pre-seed cross-compile probes curl's configure can't run on the host.
  # All values reflect Linux/musl reality on our targets.
  cat > "$SRC/config.cache" <<EOF
ac_cv_func_recv=yes
ac_cv_func_send=yes
curl_cv_recv=yes
curl_cv_send=yes
curl_cv_func_recv_args="int,void *,size_t,int,ssize_t"
curl_cv_func_send_args="int,const void *,size_t,int,ssize_t"
ac_cv_func_clock_gettime=yes
ac_cv_func_fcntl=yes
ac_cv_func_fcntl_o_nonblock=yes
ac_cv_func_setsockopt=yes
EOF
  # Static openssl pulls in -lpthread + -ldl for libcrypto; static link
  # of curl needs them at the final link step (LIBS) or the SSL_*
  # symbols fail to resolve. zlib is plain.
  #
  # CRITICAL: curl links the `curl` executable through libtool, which
  # SILENTLY DROPS a plain `-static` from the final link command (it
  # only honours `-static` for libtool libraries, not executables).
  # The result is a *dynamic* ELF that resolves openssl symbols against
  # the host's wrong-ABI libssl at runtime. `-all-static` is the
  # libtool-recognized flag that forces a fully static executable link.
  #
  # `-all-static` is NOT a gcc flag, so it cannot appear in LDFLAGS at
  # configure time (it fails the "C compiler can create executables"
  # probe). So: configure with plain `-static`, then inject
  # `-all-static` only into `make`'s LDFLAGS for the real link.
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static $extra" \
    CPPFLAGS="-I${ssl_root}/include -I${zlib_root}/include" \
    LDFLAGS="-static -L${ssl_root}/lib -L${zlib_root}/lib" \
    LIBS="-lssl -lcrypto -lz -lpthread -ldl" \
    PKG_CONFIG=/bin/false \
    ./configure \
      --cache-file=config.cache \
      --host="${arch}-linux-musl" \
      --disable-shared \
      --enable-static \
      --with-openssl="${ssl_root}" \
      --with-zlib="${zlib_root}" \
      --without-libpsl \
      --without-brotli \
      --without-zstd \
      --without-nghttp2 \
      --without-nghttp3 \
      --without-ngtcp2 \
      --without-libssh2 \
      --without-libidn2 \
      --without-librtmp \
      --disable-ldap \
      --disable-ldaps \
      --disable-docs \
      --prefix=/usr \
    && make -j4 LDFLAGS="-all-static -static -L${ssl_root}/lib -L${zlib_root}/lib" \
  )
  cp "$SRC/src/curl" "curl-$suffix"
  "$5" "curl-$suffix" 2>/dev/null || true
  echo "  → curl-$suffix  ($(stat -c %s "curl-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)"  "x86_64"  "strip"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64" "${CROSS_ROOT}/bin/aarch64-linux-musl-strip"

echo "OK — built curl for {x86_64, aarch64}"

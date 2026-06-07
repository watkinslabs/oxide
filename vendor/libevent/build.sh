#!/usr/bin/sh
# libevent 2.1.12 build recipe — per-arch static library installed under
# vendor/libevent/install-<arch>/{lib/libevent.a,include/event2/}.
# Dependency tmux links against. --disable-openssl: tmux needs only core
# libevent (no openssl bufferevents), which drops the openssl dep.
set -e

cd "$(dirname "$0")"
SRC="libevent-2.1.12-stable"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-libevent.sh first" >&2
  exit 1
fi

. ../lib/uapi-stage.sh

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libevent for $arch ==="
  rm -rf "$install"
  mkdir -p "$install"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-fPIC $(uapi_cflags "$arch")" \
    ./configure \
      --host="$host" \
      --prefix="$(pwd)/../$install" \
      --disable-shared --enable-static \
      --disable-openssl --disable-samples --disable-libevent-regress \
    && make -j4 \
    && make install \
  )
  echo "  → $install/lib/libevent.a ($(stat -c %s "$install/lib/libevent.a") bytes)"
}

build_one "x86_64"  "musl-gcc"   "x86_64-linux-musl"
build_one "aarch64" "$CROSS_CC"  "aarch64-linux-musl"

echo "OK — built libevent for {x86_64, aarch64}"

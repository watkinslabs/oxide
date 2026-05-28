#!/usr/bin/sh
# zlib 1.3.1 build recipe — per-arch static libz.a installed under
# vendor/zlib/install-<arch>/{libz.a,zlib.h,zconf.h}.
# F229: needed by openssh's --with-zlib for SSH compression.
set -e

cd "$(dirname "$0")"
SRC="zlib-1.3.1"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-zlib.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"
CROSS_RANLIB="$CROSS_ROOT/bin/aarch64-linux-musl-ranlib"

build_one() {
  arch="$1"; cc="$2"; ar="$3"; ranlib="$4"
  install="install-${arch}"
  echo "=== building zlib for $arch ==="
  rm -rf "$install"
  mkdir -p "$install"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    CC="$cc" \
    AR="$ar" \
    RANLIB="$ranlib" \
    CFLAGS="-Os -fPIC" \
    ./configure --static --prefix="$(pwd)/../$install" \
    && make -j4 libz.a \
    && make install \
  )
  echo "  → $install/lib/libz.a ($(stat -c %s $install/lib/libz.a) bytes)"
}

build_one "x86_64"  "musl-gcc" "ar" "ranlib"
build_one "aarch64" "$CROSS_CC" "$CROSS_AR" "$CROSS_RANLIB"

echo "OK — built zlib for {x86_64, aarch64}"

#!/usr/bin/sh
# lz4 1.9.4 SHARED build — per-arch liblz4.so under
# vendor/lz4/install-<arch>/{lib/liblz4.so*, include/lz4.h}.
# Track L2 systemd dep. Pure make; cross build just swaps CC.
set -e
cd "$(dirname "$0")"
SRC="lz4-1.9.4"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-lz4.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; cc="$2"
  install="install-${arch}"
  echo "=== building liblz4.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  make -C "$SRC/lib" clean >/dev/null 2>&1 || true
  make -C "$SRC/lib" CC="$cc" CFLAGS="-O2 -fPIC"
  cp -L "$SRC/lib/liblz4.so.1.9.4" "$install/lib/liblz4.so.1.9.4"
  ( cd "$install/lib" && ln -sf liblz4.so.1.9.4 liblz4.so.1 && ln -sf liblz4.so.1 liblz4.so )
  cp "$SRC/lib/lz4.h" "$install/include/"
  echo "  → $install/lib/liblz4.so.1.9.4 ($(stat -c %s "$install/lib/liblz4.so.1.9.4") bytes)"
}

build_one "x86_64"  "musl-gcc"
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc"

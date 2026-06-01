#!/usr/bin/sh
# zstd 1.5.6 SHARED build — per-arch libzstd.so installed under
# vendor/zstd/install-<arch>/{lib/libzstd.so*, include/zstd.h}.
# Track L2 systemd dep (journal compression). Pure make (no host codegen
# tool), so the cross build just swaps CC.
set -e
cd "$(dirname "$0")"
SRC="zstd-1.5.6"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-zstd.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; cc="$2"
  install="install-${arch}"
  echo "=== building libzstd.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  make -C "$SRC/lib" clean >/dev/null 2>&1 || true
  make -C "$SRC/lib" CC="$cc" CFLAGS="-O2 -fPIC" libzstd
  # The .so lands in lib/ (a symlink into obj/.../dynamic/); deref-copy it.
  cp -L "$SRC/lib/libzstd.so.1.5.6" "$install/lib/libzstd.so.1.5.6"
  ( cd "$install/lib" && ln -sf libzstd.so.1.5.6 libzstd.so.1 && ln -sf libzstd.so.1 libzstd.so )
  cp "$SRC/lib/zstd.h" "$install/include/"
  echo "  → $install/lib/libzstd.so.1.5.6 ($(stat -c %s "$install/lib/libzstd.so.1.5.6") bytes)"
}

build_one "x86_64"  "musl-gcc"
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc"

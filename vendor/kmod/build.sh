#!/usr/bin/sh
# kmod 31 SHARED build — per-arch libkmod.so under
# vendor/kmod/install-<arch>/{lib,include}.
# Track L2: systemd-modules-load / udev modalias link dep (libkmod).
# Minimal: no compressor libs — oxide2's kernel is monolithic (no .ko
# modules until the phase-10 loader), so module decompression is moot;
# libkmod exists here to satisfy systemd's link dependency. Compressed-
# module support (zstd/xz) rides whenever a real module loader lands.
set -e
cd "$(dirname "$0")"
SRC="kmod-31"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-kmod.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-tools --disable-manpages \
--disable-test-modules --without-zstd --without-xz --without-zlib \
--without-openssl --without-bashcompletiondir"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libkmod.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  # Force-include the GNU-basename shim (musl lacks it; kmod needs it) at
  # MAKE time only — including it during configure breaks autoconf's
  # compiler sanity probes.
  compat="-include $(pwd)/musl-compat.h"
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC $extra" ./configure $host $COMMON >/dev/null \
      && make -j4 CFLAGS="-O2 -fPIC $compat $extra" >/dev/null )
  real="$(cd "$SRC/libkmod/.libs" && ls libkmod.so.2.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libkmod.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/libkmod/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libkmod.so.2 && ln -sf libkmod.so.2 libkmod.so )
  cp "$SRC/libkmod/libkmod.h" "$install/include/"
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"

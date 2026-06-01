#!/usr/bin/sh
# libcap 2.69 SHARED build — per-arch libcap.so installed under
# vendor/libcap/install-<arch>/{lib/libcap.so*, include/sys/capability.h}.
# First L2 systemd shared dep (Track L2). Cross-build note: the host-side
# `_makenames` codegen tool must use BUILD_CC=gcc (host), while CC builds
# the target lib — otherwise the aarch64 tool can't run on the x86 host.
set -e
cd "$(dirname "$0")"
SRC="libcap-2.69"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libcap.sh first" >&2; exit 1; }

CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; cc="$2"; ar="$3"; ranlib="$4"; objcopy="$5"
  install="install-${arch}"
  echo "=== building libcap.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include/sys"
  make -C "$SRC/libcap" clean >/dev/null 2>&1 || true
  make -C "$SRC/libcap" CC="$cc" BUILD_CC=gcc AR="$ar" RANLIB="$ranlib" \
       OBJCOPY="$objcopy" CFLAGS="-O2 -fPIC" libcap.so
  cp -a "$SRC/libcap/libcap.so.2.69" "$install/lib/"
  ( cd "$install/lib" && ln -sf libcap.so.2.69 libcap.so.2 && ln -sf libcap.so.2 libcap.so )
  cp "$SRC/libcap/include/sys/capability.h" "$install/include/sys/"
  cp "$SRC/libcap/include/sys/psx_syscall.h" "$install/include/sys/" 2>/dev/null || true
  # capability.h pulls <linux/capability.h> — musl lacks linux/ uapi, so
  # ship libcap's bundled uapi headers in the install include path.
  mkdir -p "$install/include/linux"
  cp "$SRC/libcap/include/uapi/linux/"*.h "$install/include/linux/"
  echo "  → $install/lib/libcap.so.2.69 ($(stat -c %s "$install/lib/libcap.so.2.69") bytes)"
}

build_one "x86_64"  "musl-gcc" "ar" "ranlib" "objcopy"
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "$CROSS/aarch64-linux-musl-ar" \
          "$CROSS/aarch64-linux-musl-ranlib" "$CROSS/aarch64-linux-musl-objcopy"

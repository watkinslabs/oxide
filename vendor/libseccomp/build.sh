#!/usr/bin/sh
# libseccomp 2.5.5 SHARED build — per-arch libseccomp.so under
# vendor/libseccomp/install-<arch>/{lib/libseccomp.so*, include/seccomp.h}.
# Track L2 systemd dep (syscall sandboxing). Autotools + gperf/python host
# tools (present on the build box). Needs kernel UAPI headers (linux/,
# asm/): the aarch64 cross sysroot bundles them; for x86 musl-gcc lacks
# them, so `-idirafter /usr/include` appends the host kernel-headers at
# lowest priority (musl libc headers still win). Same trick systemd needs.
set -e
cd "$(dirname "$0")"
SRC="libseccomp-2.5.5"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libseccomp.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; cc="$2"; host="$3"; cflags="$4"
  install="install-${arch}"
  echo "=== building libseccomp.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC $cflags" ./configure $host \
      --enable-shared --disable-static >/dev/null && make -j4 >/dev/null )
  cp -L "$SRC/src/.libs/libseccomp.so.2.5.5" "$install/lib/libseccomp.so.2.5.5"
  ( cd "$install/lib" && ln -sf libseccomp.so.2.5.5 libseccomp.so.2 && ln -sf libseccomp.so.2 libseccomp.so )
  cp "$SRC/include/seccomp.h" "$SRC/include/seccomp-syscalls.h" "$install/include/"
  echo "  → $install/lib/libseccomp.so.2.5.5 ($(stat -c %s "$install/lib/libseccomp.so.2.5.5") bytes)"
}

build_one "x86_64"  "musl-gcc" "" "-idirafter /usr/include"
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl" ""

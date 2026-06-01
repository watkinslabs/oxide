#!/usr/bin/sh
# libxcrypt 4.4.36 SHARED build — per-arch libcrypt.so under
# vendor/libxcrypt/install-<arch>/{lib/libcrypt.so*, include/crypt.h}.
# Track L2: real crypt() for /etc/shadow ($6$ sha512crypt etc.) — musl's
# built-in crypt is limited; pam_unix/shadow want the full set. First
# AUTOTOOLS L2 dep (configure --host for the aarch64 cross). yescrypt is
# dropped (--enable-hashes=glibc) — it needs <linux/mman.h> musl lacks,
# and the glibc hash set covers what shadow uses.
set -e
cd "$(dirname "$0")"
SRC="libxcrypt-4.4.36"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libxcrypt.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-werror --enable-hashes=glibc --enable-obsolete-api=glibc"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libcrypt.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && ./configure CC="$cc" $host $COMMON >/dev/null && make -j4 >/dev/null )
  cp -L "$SRC/.libs/libcrypt.so.2.0.0" "$install/lib/libcrypt.so.2.0.0"
  ( cd "$install/lib" && ln -sf libcrypt.so.2.0.0 libcrypt.so.2 && ln -sf libcrypt.so.2 libcrypt.so )
  cp "$SRC/crypt.h" "$install/include/"
  echo "  → $install/lib/libcrypt.so.2.0.0 ($(stat -c %s "$install/lib/libcrypt.so.2.0.0") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"

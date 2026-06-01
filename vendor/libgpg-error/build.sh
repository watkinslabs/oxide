#!/usr/bin/sh
# libgpg-error 1.50 SHARED build — per-arch libgpg-error.so under
# vendor/libgpg-error/install-<arch>/{lib,include}.
# Track L2: libgcrypt's dep (systemd unconditional DEPENDS → journald FSS).
set -e
cd "$(dirname "$0")"
SRC="libgpg-error-1.50"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libgpg-error.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-doc --disable-tests \
--disable-languages --disable-nls"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libgpg-error.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC $extra" ./configure $host $COMMON >/dev/null && make -j4 >/dev/null )
  real="$(cd "$SRC/src/.libs" && ls libgpg-error.so.0.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libgpg-error.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/src/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libgpg-error.so.0 && ln -sf libgpg-error.so.0 libgpg-error.so )
  cp "$SRC/src/gpg-error.h" "$install/include/"
  # gpg-error-config / gpgrt-config consumers also want gpgrt.h alias.
  cp "$SRC/src/gpg-error.h" "$install/include/gpgrt.h" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"

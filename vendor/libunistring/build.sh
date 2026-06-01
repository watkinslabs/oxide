#!/usr/bin/sh
# libunistring 1.2 SHARED build — per-arch libunistring.so under
# vendor/libunistring/install-<arch>/{lib,include}.
# Track L2: libidn2's dep (Unicode string ops).
set -e
cd "$(dirname "$0")"
SRC="libunistring-1.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libunistring.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-rpath"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libunistring.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC $extra" ./configure $host $COMMON >/dev/null && make -j4 >/dev/null )
  real="$(cd "$SRC/lib/.libs" && ls libunistring.so.5.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libunistring.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/lib/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libunistring.so.5 && ln -sf libunistring.so.5 libunistring.so )
  cp "$SRC"/lib/unistring/*.h "$install/include/" 2>/dev/null || true
  cp "$SRC"/lib/uni*.h "$install/include/" 2>/dev/null || true
  cp "$SRC"/lib/unitypes.h "$install/include/" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"

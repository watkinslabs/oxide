#!/usr/bin/sh
# expat 2.6.2 SHARED build — per-arch libexpat.so under
# vendor/expat/install-<arch>/{lib/libexpat.so*, include/expat.h}.
# Track L2: dbus's XML parser dep (dbus → systemd bus stack). Autotools.
set -e
cd "$(dirname "$0")"
SRC="expat-2.6.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-expat.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --without-docbook --without-examples --without-tests"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libexpat.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC" ./configure $host $COMMON >/dev/null && make -j4 >/dev/null )
  cp -L "$SRC/lib/.libs/libexpat.so.1.9.2" "$install/lib/libexpat.so.1.9.2"
  ( cd "$install/lib" && ln -sf libexpat.so.1.9.2 libexpat.so.1 && ln -sf libexpat.so.1 libexpat.so )
  cp "$SRC/lib/expat.h" "$SRC/lib/expat_external.h" "$install/include/"
  echo "  → $install/lib/libexpat.so.1.9.2 ($(stat -c %s "$install/lib/libexpat.so.1.9.2") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"

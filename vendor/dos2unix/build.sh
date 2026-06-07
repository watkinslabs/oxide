#!/usr/bin/sh
# dos2unix 7.5.2 build recipe — static-musl /usr/bin/{dos2unix,unix2dos}.
# Pure Makefile build (no autotools). ENABLE_NLS= drops gettext dependency.
# dos2unix and unix2dos are SEPARATE binaries (mac2unix/unix2mac are symlinks).
set -e

cd "$(dirname "$0")"
VERSION="7.5.2"
SRC="dos2unix-${VERSION}"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-dos2unix.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

build_one() {
  arch="$1"; cc="$2"; strip="$3"
  echo "=== building dos2unix for $arch ==="
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    make CC="$cc" ENABLE_NLS= prefix=/usr \
         LDFLAGS_USER="-static" CFLAGS_USER="-O2 -static" )
  cp "$SRC/dos2unix" "dos2unix-$arch"
  cp "$SRC/unix2dos" "unix2dos-$arch"
  "$strip" "dos2unix-$arch" 2>/dev/null || true
  "$strip" "unix2dos-$arch" 2>/dev/null || true
  echo "  → dos2unix-$arch  ($(stat -c %s "dos2unix-$arch") bytes)"
  echo "  → unix2dos-$arch  ($(stat -c %s "unix2dos-$arch") bytes)"
}

build_one "x86_64"  "musl-gcc"   "strip"
build_one "aarch64" "$CROSS_CC"  "$CROSS_STRIP"

echo "OK — built dos2unix + unix2dos for {x86_64, aarch64}"

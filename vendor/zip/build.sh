#!/usr/bin/sh
# Info-ZIP Zip 3.0 build recipe. Hand-rolled unix/Makefile; the `zips` target
# builds without autoconfigure (generic/generic_gcc run a configure that
# compiles+runs target binaries — broken under cross-compile), so it
# cross-compiles cleanly with a per-arch CC + static link.
set -e
cd "$(dirname "$0")"
SRC="zip30"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-zip.sh first" >&2; exit 1; }

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

# Modern-libc patch (idempotent), same as UnZip: drop the K&R gmtime()/
# localtime() redeclaration — musl/glibc prototype them in <time.h>.
sed -i 's@^   struct tm \*gmtime(), \*localtime();@   /* musl/glibc prototype these in <time.h> */@' \
    "$SRC/unix/unxcfg.h" 2>/dev/null || true

build_one() {
  arch="$1"; cc="$2"; suffix="$3"
  echo "=== building zip for $arch ==="
  ( cd "$SRC" && make -f unix/Makefile clean >/dev/null 2>&1 || true; rm -f zip )
  ( cd "$SRC" && make -f unix/Makefile zips \
      CC="$cc" LD="$cc" AS="$cc -c" \
      CFLAGS="-O2 -DUNIX -I. -DLARGE_FILE_SUPPORT -DUIDGID_NOT_16BIT -DNO_LCHMOD" \
      LFLAGS1="-static" LFLAGS2="-s" )
  cp "$SRC/zip" "zip-$suffix"
  strip "zip-$suffix" 2>/dev/null || true
  echo "  → zip-$suffix  ($(stat -c %s "zip-$suffix") bytes)"
}

case "${1:-all}" in
  x86|x86_64) build_one x86_64 "musl-gcc" "x86_64" ;;
  arm|aarch64) build_one aarch64 "$CROSS_CC" "aarch64" ;;
  all) build_one x86_64 "musl-gcc" "x86_64"; build_one aarch64 "$CROSS_CC" "aarch64" ;;
esac
echo "OK"

#!/usr/bin/sh
# Info-ZIP UnZip 6.0 build recipe. Hand-rolled unix/Makefile; the `unzips`
# target builds without autoconfigure (cf. the linux_noasm target), so it
# cross-compiles cleanly with a per-arch CC + static link.
set -e
cd "$(dirname "$0")"
SRC="unzip60"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-unzip.sh first" >&2; exit 1; }

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

# Modern-libc patch (idempotent): musl/glibc declare gmtime()/localtime() with
# prototypes in <time.h>; UnZip 6.0's K&R redeclaration in unxcfg.h conflicts
# (error: conflicting types). Distros (Debian/Buildroot) drop it the same way.
sed -i 's@^   struct tm \*gmtime(), \*localtime();@   /* musl/glibc prototype these in <time.h> */@' \
    "$SRC/unix/unxcfg.h"

build_one() {
  arch="$1"; cc="$2"; suffix="$3"
  echo "=== building unzip for $arch ==="
  ( cd "$SRC" && make -f unix/Makefile clean >/dev/null 2>&1 || true; rm -f unzip )
  ( cd "$SRC" && make -f unix/Makefile unzips \
      CC="$cc" LD="$cc" \
      CFLAGS="-O2 -Wall -DUNIX -DLARGE_FILE_SUPPORT -DNO_LCHMOD" \
      LFLAGS1="-static" LF2="-s" )
  cp "$SRC/unzip" "unzip-$suffix"
  "${cc%-gcc}-strip" "unzip-$suffix" 2>/dev/null || strip "unzip-$suffix" 2>/dev/null || true
  echo "  → unzip-$suffix  ($(stat -c %s "unzip-$suffix") bytes)"
}

case "${1:-all}" in
  x86|x86_64) build_one x86_64 "musl-gcc" "x86_64" ;;
  arm|aarch64) build_one aarch64 "$CROSS_CC" "aarch64" ;;
  all) build_one x86_64 "musl-gcc" "x86_64"; build_one aarch64 "$CROSS_CC" "aarch64" ;;
esac
echo "OK"

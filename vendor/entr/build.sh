#!/usr/bin/sh
# entr 5.6 build recipe — static-musl binaries for both arches.
#
# entr ships a custom (non-autotools) ./configure that probes the host
# libc for strlcpy and copies Makefile.linux (musl has strlcpy) or
# Makefile.linux-compat, then a plain Makefile build. Linux backend uses
# inotify (missing/kqueue_inotify.c), auto-selected by the Linux case in
# configure. Static link so the binary runs pre-dynamic-linker.
#
# configure picks the Makefile variant from a CC compile-test; we pass CC
# via env for that, then override CC/CFLAGS/LDFLAGS on the make line so the
# real compile uses the chosen toolchain + static flags regardless of any
# host default the Makefile carries.
set -e

cd "$(dirname "$0")"
SRC="entr-5.6"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-entr.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

build_one() {
  arch="$1"; cc="$2"; strip_cmd="$3"; suffix="$4"
  echo "=== building entr for $arch ==="
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
  ( cd "$SRC" && rm -f Makefile >/dev/null 2>&1 || true )
  # configure runs a CC compile-test to choose the Makefile variant.
  ( cd "$SRC" && \
    CC="$cc" CFLAGS="-static" LDFLAGS="-static" TARGET_OS="Linux" ./configure )
  # real compile: force toolchain + static flags on the make line.
  ( cd "$SRC" && \
    make CC="$cc" CFLAGS="-O2 -static" LDFLAGS="-static" )
  cp "$SRC/entr" "entr-$suffix"
  "$strip_cmd" "entr-$suffix" 2>/dev/null || strip "entr-$suffix" 2>/dev/null || true
  echo "  → entr-$suffix  ($(stat -c %s "entr-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"   "strip"          "x86_64"
build_one "aarch64" "$CROSS_CC"  "$CROSS_STRIP"   "aarch64"

echo "=== results ==="
file entr-x86_64 entr-aarch64

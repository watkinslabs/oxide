#!/usr/bin/sh
# unix-tree 2.2.1 build recipe — pre-built static-musl binaries
# checked in as `vendor/tree/tree-{x86_64,aarch64}`.
#
# tree is a plain-Makefile C program. The Makefile uses `?=` for CC,
# CFLAGS and LDFLAGS, so command-line overrides win cleanly. No
# autotools, no config.cache. We override CC/CFLAGS/LDFLAGS for a
# static link (works pre-dynamic-linker) and ignore the `install`
# target — binaries are copied out by hand.
#
# musl-gcc (x86_64) lacks Linux UAPI headers; stage host copies and
# -isystem them via vendor/lib/uapi-stage.sh (same approach as bash).
# aarch64 uses the cross sysroot's own UAPI.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="unix-tree-2.2.1"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-tree.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

build_one() {
  arch="$1"; cc="$2"; strip="$3"; extra="$4"; suffix="$5"
  echo "=== building tree for $arch ==="
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    make \
      CC="$cc" \
      CFLAGS="-O2 -static $extra" \
      LDFLAGS="-static" \
  )
  cp "$SRC/tree" "tree-$suffix"
  "$strip" "tree-$suffix" 2>/dev/null || true
  echo "  → tree-$suffix  ($(stat -c %s "tree-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "strip"        "$(uapi_cflags x86_64)" "x86_64"
build_one "aarch64" "$CROSS_CC" "$CROSS_STRIP" "$(uapi_cflags aarch64)" "aarch64"

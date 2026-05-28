#!/usr/bin/sh
# bzip2 1.0.8 build recipe — hand-rolled Makefile, no autoconf.
# F226: eleventh userspace program after the 10 GNU packages.
set -e

cd "$(dirname "$0")"
SRC="bzip2-1.0.8"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-bzip2.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

build_one() {
  arch="$1"; cc="$2"; suffix="$3"
  echo "=== building bzip2 for $arch ==="
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -D_FILE_OFFSET_BITS=64" \
    make -j4 bzip2 \
  )
  ( cd "$SRC" && "$cc" -static -o "../bzip2-$suffix" \
      bzlib.o crctable.o randtable.o compress.o decompress.o blocksort.o huffman.o bzip2.c )
  strip "bzip2-$suffix" 2>/dev/null || true
  echo "  → bzip2-$suffix  ($(stat -c %s "bzip2-$suffix") bytes)"
}

# Pre-build the .o files via the upstream Makefile (uses host CC),
# then link statically with the cross CC. Simpler: just rebuild
# objects with the cross CC each time.
build_static() {
  arch="$1"; cc="$2"; suffix="$3"
  echo "=== building bzip2 for $arch (static) ==="
  ( cd "$SRC" && rm -f *.o && \
    for src in blocksort huffman crctable randtable compress decompress bzlib; do \
      "$cc" -c -Os -D_FILE_OFFSET_BITS=64 "$src.c" ; \
    done && \
    "$cc" -static -o "../bzip2-$suffix" \
      -Os -D_FILE_OFFSET_BITS=64 \
      blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o \
      bzip2.c \
  )
  strip "bzip2-$suffix" 2>/dev/null || true
  echo "  → bzip2-$suffix  ($(stat -c %s "bzip2-$suffix") bytes)"
}

build_static "x86_64"  "musl-gcc"  "x86_64"
build_static "aarch64" "$CROSS_CC" "aarch64"

echo "OK — built bzip2 for {x86_64, aarch64}"

#!/usr/bin/sh
# GNU make 4.4.1 build recipe — static-musl /usr/bin/make.
# F221: sixth GNU userspace program after bash/sed/coreutils/grep/tar.
set -e

cd "$(dirname "$0")"
SRC="make-4.4.1"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-make.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-make
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-make-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"
  echo "=== building make for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -D_GNU_SOURCE -std=gnu89 \
            -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --disable-nls \
      --without-guile \
      --without-libsigsegv \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/make" "make-$suffix"
  strip "make-$suffix" 2>/dev/null || true
  echo "  → make-$suffix  ($(stat -c %s "make-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "-isystem $HDRS_X86" "x86_64"
build_one "aarch64" "$CROSS_CC" "-isystem $HDRS_ARM" "aarch64"

echo "OK — built make for {x86_64, aarch64}"

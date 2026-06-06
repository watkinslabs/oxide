#!/usr/bin/sh
# xz-utils 5.6.3 build recipe — static-musl /usr/bin/xz.
# F227: twelfth userspace program.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="xz-5.6.3"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-xz.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-xz
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-xz-arm
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
  echo "=== building xz for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-D_GNU_SOURCE -std=gnu11 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -D_GNU_SOURCE -std=gnu11 \
            -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --disable-nls \
      --disable-shared \
      --enable-static \
      --disable-doc \
      --disable-scripts \
      --disable-lzma-links \
      --prefix=/usr \
    && make -j4 LDFLAGS=-all-static \
  )
  cp "$SRC/src/xz/xz" "xz-$suffix"
  strip "xz-$suffix" 2>/dev/null || true
  echo "  → xz-$suffix  ($(stat -c %s "xz-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64"

echo "OK — built xz for {x86_64, aarch64}"

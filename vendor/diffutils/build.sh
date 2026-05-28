#!/usr/bin/sh
# GNU diffutils 3.10 build recipe — static-musl /usr/bin/diff + cmp.
# F224: ninth GNU userspace package.
set -e

cd "$(dirname "$0")"
SRC="diffutils-3.10"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-diffutils.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-diff
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-diff-arm
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
  echo "=== building diffutils for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-D_GNU_SOURCE -std=gnu11 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -D_GNU_SOURCE -std=gnu11 \
            -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="" \
    ./configure \
      --host="${arch}-linux-musl" \
      --disable-nls \
      --without-selinux \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/src/diff" "diff-$suffix"
  cp "$SRC/src/cmp"  "cmp-$suffix"
  strip "diff-$suffix" "cmp-$suffix" 2>/dev/null || true
  echo "  → diff-$suffix  ($(stat -c %s "diff-$suffix") bytes)"
  echo "  → cmp-$suffix   ($(stat -c %s "cmp-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "-isystem $HDRS_X86" "x86_64"
build_one "aarch64" "$CROSS_CC" "-isystem $HDRS_ARM" "aarch64"

echo "OK — built diffutils for {x86_64, aarch64}"

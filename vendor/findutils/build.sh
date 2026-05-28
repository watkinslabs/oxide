#!/usr/bin/sh
# GNU findutils 4.10.0 build recipe — static-musl /usr/bin/find + /usr/bin/xargs.
# F223: eighth GNU userspace package after bash/sed/coreutils/grep/tar/make/awk.
set -e

cd "$(dirname "$0")"
SRC="findutils-4.10.0"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-findutils.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-find
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-find-arm
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
  echo "=== building findutils for $arch ==="
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
      --without-selinux \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/find/find" "find-$suffix"
  cp "$SRC/xargs/xargs" "xargs-$suffix" 2>/dev/null || true
  strip "find-$suffix" "xargs-$suffix" 2>/dev/null || true
  echo "  → find-$suffix  ($(stat -c %s "find-$suffix") bytes)"
  test -f "xargs-$suffix" && echo "  → xargs-$suffix ($(stat -c %s "xargs-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "-isystem $HDRS_X86" "x86_64"
build_one "aarch64" "$CROSS_CC" "-isystem $HDRS_ARM" "aarch64"

echo "OK — built findutils for {x86_64, aarch64}"

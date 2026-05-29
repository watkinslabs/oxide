#!/usr/bin/sh
# less 643 build recipe -- static-musl, linked against the F250
# vendored ncurses. Drops in at /usr/bin/less.
set -e

cd "$(dirname "$0")"
SRC="less-643"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-less.sh first" >&2
  exit 1
fi

NC_X86="$(cd ../ncurses/install-x86_64 && pwd)"
NC_ARM="$(cd ../ncurses/install-aarch64 && pwd)"

HDRS_X86=/tmp/musl-hdrs-less
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-less-arm
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
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; nc_root="$5"; host="$6"
  echo "=== building less for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE -I${nc_root}/include -I${nc_root}/include/ncursesw" \
    LDFLAGS="-static -L${nc_root}/lib" \
    LIBS="-lncursesw" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --with-regex=posix \
    && make less -j4 \
  )
  cp "$SRC/less" "less-$suffix"
  strip "less-$suffix" 2>/dev/null || true
  echo "  -> less-$suffix ($(stat -c %s less-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "-isystem $HDRS_X86" \
  "x86_64" "$NC_X86" "x86_64-linux-musl"

build_one "aarch64" "$CROSS_CC" \
  "-isystem $HDRS_ARM" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl"

echo "OK -- built less for {x86_64, aarch64}"

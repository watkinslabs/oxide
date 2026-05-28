#!/usr/bin/sh
# GNU sed 4.9 build recipe — static-musl single binary at /usr/bin/sed.
#
# F217: second GNU userspace program after bash. sed exercises:
#   - gnulib's regex engine (full POSIX BRE + ERE + extensions)
#   - getopt_long argument parsing
#   - SIGSEGV handler via libsigsegv (if available, else skipped)
#   - mmap of /tmp scratch files for -i
#   - signal-driven progress
# Smaller than coreutils gnulib mess; works with -D_GNU_SOURCE.
set -e

cd "$(dirname "$0")"
SRC="sed-4.9"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-sed.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-sed
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-sed-arm
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
  echo "=== building sed for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --disable-nls \
      --disable-acl \
      --disable-i18n \
      --without-selinux \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/sed/sed" "sed-$suffix"
  strip "sed-$suffix" 2>/dev/null || true
  echo "  → sed-$suffix  ($(stat -c %s "sed-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "-isystem $HDRS_X86" "x86_64"
build_one "aarch64" "$CROSS_CC" "-isystem $HDRS_ARM" "aarch64"

echo "OK — built sed for {x86_64, aarch64}"

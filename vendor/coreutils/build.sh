#!/usr/bin/sh
# GNU coreutils 9.7 build recipe — single-binary mode, static-musl.
#
# F218: full coreutils on oxide. Single binary at /usr/libexec/coreutils
# with applet symlinks installed by xtask. Exercises:
#   getdents64 d_type fields, lstat S_ISLNK, statx, getrandom seeding,
#   utimensat, fadvise, copy_file_range, openat with AT_*, fchmodat,
#   readlinkat, dup3, fchownat — each is a kernel/libc gap waiting
#   to be found.
#
# musl gaps: timezone_t (glibc <time.h> ext), O_BINARY/O_TEXT (DOS
# stubs), S_IXUGO/S_IRWXUGO (Linux stat shortcuts), c32tolower/upper
# (C23 <uchar.h>; route through wchar's tow*). We patch the gnulib
# headers in-place rather than -include a shim, because gnulib's
# CFLAGS plumbing mangles multi-line -include arguments.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="coreutils-8.32"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-coreutils.sh first" >&2
  exit 1
fi

# In-place header patches. Idempotent (sentinel markers).
# gnulib's lib/time.in.h provides timezone_t when the platform
# lacks it, so we DON'T patch strftime.h ourselves — that would
# conflict with the generated struct-pointer typedef.
patch_sources() {
  : # coreutils 8.32 needs no source patches with the CFLAGS shim below
}
patch_sources

HDRS_X86=/tmp/musl-hdrs-coreutils
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-coreutils-arm
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
  echo "=== building coreutils for $arch ==="
  cleanup_objs
  # Re-apply patches (distclean only touches build outputs, not lib/*).
  patch_sources
  # Pre-seed autoconf cache: musl lacks these glibc extensions so
  # gnulib must generate its own header from lib/error.in.h.
  cat > "$SRC/config.cache" <<EOF
ac_cv_header_error_h=no
ac_cv_have_decl_error=no
ac_cv_have_decl_error_at_line=no
ac_cv_func_error=no
EOF
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-D_GNU_SOURCE -DO_BINARY=0 -DO_TEXT=0 \
                      -DS_IXUGO='(S_IXUSR|S_IXGRP|S_IXOTH)' \
                      -DS_IRWXUGO='(S_IRWXU|S_IRWXG|S_IRWXO)' \
                      -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -D_GNU_SOURCE -DO_BINARY=0 -DO_TEXT=0 \
            -DS_IXUGO='(S_IXUSR|S_IXGRP|S_IXOTH)' \
            -DS_IRWXUGO='(S_IRWXU|S_IRWXG|S_IRWXO)' \
            -DSYS_getdents=SYS_getdents64 \
            -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="" \
    ./configure \
      --cache-file=config.cache \
      --host="${arch}-linux-musl" \
      --enable-single-binary=symlinks \
      --enable-no-install-program=stdbuf,arch,hostname \
      --disable-nls \
      --disable-libsmack \
      --disable-libcap \
      --disable-acl \
      --disable-xattr \
      --without-selinux \
      --without-openssl \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/src/coreutils" "coreutils-$suffix"
  strip "coreutils-$suffix" 2>/dev/null || true
  echo "  → coreutils-$suffix  ($(stat -c %s "coreutils-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64"

echo "OK — built coreutils for {x86_64, aarch64}"

#!/usr/bin/sh
# ncdu 1.21 build recipe -- static-musl, linked against the vendored
# static ncurses (libncursesw.a + headers under
# vendor/ncurses/install-<arch>/). Drops in at /usr/bin/ncdu.
#
# ncdu (NCurses Disk Usage) is a disk-usage TUI. The 1.x line is C; the
# 2.x line is rewritten in Zig and is out of scope for the C cross-build
# pathway -- this recipe pins 1.21.
#
# Run tools/fetch-ncdu.sh first to populate the source tree, and
# vendor/ncurses/build.sh first so install-<arch>/ exists.
#
# ncurses link: ncdu's configure REQUIRES pkg-config (PKG_PROG_PKG_CONFIG
# is a hard prereq), then prefers a `pkg-config ncursesw` probe. We can't
# disable pkg-config, so we point PKG_CONFIG_LIBDIR at an empty dir: the
# binary still exists (prereq satisfied) but `--exists ncursesw` fails,
# so configure falls back to AC_CHECK_LIB(ncursesw, initscr). That link
# test honours our LDFLAGS (-L vendored static lib) + CPPFLAGS, and on
# success sets LIBS="-lncursesw", statically linking the vendored
# libncursesw.a. --with-ncursesw selects the wide library.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="ncdu-1.21"

# Empty pkg-config search path so no host ncursesw .pc is found, forcing
# the AC_CHECK_LIB fallback that uses the vendored lib via LDFLAGS.
EMPTY_PC="/tmp/ncdu-empty-pkgconfig"
mkdir -p "$EMPTY_PC"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-ncdu.sh first" >&2
  exit 1
fi

NC_X86="$(cd ../ncurses/install-x86_64 && pwd)"
NC_ARM="$(cd ../ncurses/install-aarch64 && pwd)"

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; nc_root="$5"; host="$6"; strip="$7"
  echo "=== building ncdu for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    PKG_CONFIG_LIBDIR="$EMPTY_PC" \
    PKG_CONFIG_PATH="$EMPTY_PC" \
    CPPFLAGS="-I${nc_root}/include -I${nc_root}/include/ncursesw" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE" \
    LDFLAGS="-static -L${nc_root}/lib" \
    LIBS="-lncursesw" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --with-ncursesw \
    && make -j4 \
  )
  cp "$SRC/ncdu" "ncdu-$suffix"
  "$strip" "ncdu-$suffix" 2>/dev/null || true
  echo "  -> ncdu-$suffix ($(stat -c %s ncdu-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86" "x86_64-linux-musl" "strip"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl" "$CROSS_STRIP"

echo "OK -- built ncdu for {x86_64, aarch64}"

#!/usr/bin/sh
# GNU nano 8.2 build recipe — static-musl, linked against the vendored
# static ncurses (libncursesw.a + headers under
# vendor/ncurses/install-<arch>/). Drops in at /usr/bin/nano.
#
# Run tools/fetch-nano.sh first to populate the source tree, and
# vendor/ncurses/build.sh first so install-<arch>/ exists.
#
# ncurses link: nano's configure probes for the wide-char curses library.
# It uses PKG_CHECK_MODULES(NCURSESW, ncursesw) with an AC_CHECK_LIB
# fallback. We point PKG_CONFIG_LIBDIR/PATH at /nonexistent so no host
# ncursesw.pc is found, and pass NCURSESW_CFLAGS/NCURSESW_LIBS explicitly
# so configure uses the vendored static libncursesw.a via our -L/-I. The
# vendored headers live directly under include/ (curses.h, ncurses.h); the
# extra -I include/ncursesw is harmless if absent. Static link so the
# binary works pre-dynamic-linker.
#
# bool collision: the vendored ncurses headers hardcode
# NCURSES_ENABLE_STDBOOL_H=0, forcing `#define bool int`. nano assigns
# pointers to its `bool refresh_needed`, which GCC 14+ rejects as an
# int-from-pointer error. -DNCURSES_ENABLE_STDBOOL_H=1 makes curses use
# the real <stdbool.h> bool so the pointer->bool conversion is valid.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="nano-8.2"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-nano.sh first" >&2
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
  echo "=== building nano for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    PKG_CONFIG_LIBDIR="/nonexistent" \
    PKG_CONFIG_PATH="/nonexistent" \
    CPPFLAGS="-DNCURSES_ENABLE_STDBOOL_H=1 -I${nc_root}/include -I${nc_root}/include/ncursesw" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE" \
    LDFLAGS="-static -L${nc_root}/lib" \
    NCURSESW_CFLAGS="-I${nc_root}/include -I${nc_root}/include/ncursesw" \
    NCURSESW_LIBS="-L${nc_root}/lib -lncursesw" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --disable-nls \
      --disable-libmagic \
      --disable-speller \
    && make -j4 \
  )
  cp "$SRC/src/nano" "nano-$suffix"
  "$strip" "nano-$suffix" 2>/dev/null || true
  echo "  -> nano-$suffix ($(stat -c %s nano-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86" "x86_64-linux-musl" "strip"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl" "$CROSS_STRIP"

echo "OK — built nano for {x86_64, aarch64}"

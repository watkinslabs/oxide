#!/usr/bin/sh
# htop 3.3.0 build recipe — static-musl, linked against the vendored
# static ncurses (libncursesw.a + headers under
# vendor/ncurses/install-<arch>/). Drops in at /usr/bin/htop.
#
# htop — interactive process viewer (NCurses TUI). The 3.x line is C
# (autotools); 4.x has no release at pin time. This recipe pins 3.3.0.
#
# Run tools/fetch-htop.sh first to populate the source tree, and
# vendor/ncurses/build.sh first so install-<arch>/ exists.
#
# ncurses link: the vendored ncurses is a NON-split wide build — every
# symbol (waddwstr/keypad/doupdate/addnwstr) lives in libncursesw.a, no
# separate libtinfo. htop's --disable-unicode path probes -lncurses /
# -lcurses, which our libncursesw.a does NOT satisfy, so we build the
# DEFAULT --enable-unicode path: configure runs AC_CHECK_LIB([ncursesw],
# waddwstr), which honours our LDFLAGS (-L vendored lib) + CPPFLAGS and
# statically links libncursesw.a as -lncursesw. AC_SEARCH_LIBS([keypad],
# [tinfow tinfo]) is satisfied by the same lib (no extra -ltinfo). The
# header probe falls through ncursesw/curses.h -> ncurses.h (present in
# install-<arch>/include) via ProvideCurses.h. We empty PKG_CONFIG_LIBDIR
# (ncdu style) so no host ncursesw .pc shifts the probe onto a host lib.
#
# Two source-level snags handled by CPPFLAGS/CFLAGS, both pre-existing:
#   * The vendored ncurses was built with NCURSES_ENABLE_STDBOOL_H=0, so
#     <ncurses.h> does `#define bool NCURSES_BOOL` (int), clobbering C99
#     <stdbool.h> `bool`. htop declares APIs with real `bool`, so the two
#     collide (conflicting types on FunctionBar_drawExtra/Hashtable_new).
#     -DNCURSES_ENABLE_STDBOOL_H=1 tells the header to use system stdbool.
#   * GCC 14+ promotes -Wint-conversion to a hard error; htop 3.3.0 passes
#     a char* where a bool is expected (CommandLine.c, non-null => true).
#     -Wno-error=int-conversion keeps it the warning it was on older GCC.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="htop-3.3.0"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-htop.sh first" >&2
  exit 1
fi

# Empty pkg-config search path so no host ncursesw .pc is found, forcing
# the AC_CHECK_LIB fallback that uses the vendored lib via LDFLAGS.
EMPTY_PC="/tmp/htop-empty-pkgconfig"
mkdir -p "$EMPTY_PC"

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
  echo "=== building htop for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    PKG_CONFIG_LIBDIR="$EMPTY_PC" \
    PKG_CONFIG_PATH="$EMPTY_PC" \
    CPPFLAGS="-I${nc_root}/include -I${nc_root}/include/ncursesw -DNCURSES_ENABLE_STDBOOL_H=1" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE -Wno-error=int-conversion -Wno-int-conversion" \
    LDFLAGS="-static -L${nc_root}/lib" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --enable-unicode \
      --enable-static \
      --disable-unwind \
      --disable-hwloc \
      --disable-sensors \
      --disable-capabilities \
      --disable-delayacct \
    && make -j4 \
  )
  cp "$SRC/htop" "htop-$suffix"
  "$strip" "htop-$suffix" 2>/dev/null || true
  echo "  -> htop-$suffix ($(stat -c %s "htop-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86" "x86_64-linux-musl" "strip"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl" "$CROSS_STRIP"

echo "OK -- built htop for {x86_64, aarch64}"

#!/usr/bin/sh
# dialog 1.3-20240619 build recipe — static-musl, linked against the
# vendored static ncurses (libncursesw.a + headers under
# vendor/ncurses/install-<arch>/). Drops in at /usr/bin/dialog.
#
# dialog (invisible-island.net/dialog) is the classic curses TUI widget
# tool (--msgbox, --menu, --inputbox, --gauge, ...). Shell scripts and
# installers drive it via the command line.
#
# Run tools/fetch-dialog.sh first to populate the source tree, and
# vendor/ncurses/build.sh first so install-<arch>/ exists.
#
# ncurses link: dialog's configure uses --with-ncursesw to select the
# wide library, then runs a CF_NCURSES_CONFIG / pkg-config probe before
# falling back to AC_CHECK_LIB(ncursesw, initscr). We point
# PKG_CONFIG_LIBDIR/PATH at /nonexistent so no host ncursesw.pc is found,
# forcing the link test that honours our LDFLAGS (-L vendored static lib)
# + CPPFLAGS (-I vendored headers). On success LIBS gets -lncursesw,
# statically linking the vendored libncursesw.a. --disable-rc-file and
# friends keep the binary lean; --disable-nls drops gettext.
#
# bool collision: the vendored ncurses headers hardcode
# NCURSES_ENABLE_STDBOOL_H=0, forcing `#define bool int`. -D...=1 makes
# curses use the real <stdbool.h> bool, avoiding the bool/int clashes
# ncdu + nano hit with these headers. Static link so the binary works
# pre-dynamic-linker.
#
# opaque WINDOW vs getparyx: the vendored ncurses was built with
# NCURSES_OPAQUE=1 (curses.h hides struct _win_st). dialog's dlg_internals.h
# only pokes window internals (win->_pary, ...) as a FALLBACK, gated behind
# `#ifndef HAVE_GETPARYX`. As long as configure can link a curses probe it
# detects HAVE_GETPARYX/GETBEGYX/GETMAXYX=1 and uses the real curses
# functions, never the struct-poking macros — so the opaque struct is fine.
# (Forcing -DNCURSES_INTERNALS to un-opaque the struct is WRONG here: it also
# `#undef`s SCREEN and redefines it as `struct screen`, which collides with
# dialog's own SCREEN color-table token in util.c. The fix is the tinfo
# shim below, which makes the configure curses probes link.)
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="dialog-1.3-20240619"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-dialog.sh first" >&2
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

# tinfo shim: dialog's CF_NCURSES_LIBS macro appends `-ltinfo` to the
# curses link line (modern ncurses splits terminfo into libtinfo). The
# vendored ncurses is a single self-contained libncursesw.a with no
# separate libtinfo, so `-ltinfo` fails to resolve and EVERY curses link
# probe (start_color, ...) fails -> HAVE_COLOR stays undefined -> rc.c
# fails to compile (color_names[]/COLOR_COUNT are gated behind HAVE_COLOR
# but used unconditionally). Stage a libtinfo.a that is just a copy of the
# self-contained libncursesw.a so `-ltinfo` resolves to the same symbols.
stage_tinfo() {
  _ncl="$1"; _shim="$2"
  rm -rf "$_shim"; mkdir -p "$_shim"
  cp "${_ncl}/lib/libncursesw.a" "$_shim/libtinfo.a"
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; nc_root="$5"; host="$6"; strip="$7"
  echo "=== building dialog for $arch ==="
  cleanup_objs
  shim="/tmp/dialog-tinfo-$arch"
  stage_tinfo "$nc_root" "$shim"
  ( cd "$SRC" && \
    CC="$cc" \
    PKG_CONFIG_LIBDIR="/nonexistent" \
    PKG_CONFIG_PATH="/nonexistent" \
    CPPFLAGS="-DNCURSES_ENABLE_STDBOOL_H=1 -I${nc_root}/include -I${nc_root}/include/ncursesw" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE" \
    LDFLAGS="-static -L${nc_root}/lib -L${shim}" \
    LIBS="-lncursesw" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --with-ncursesw \
      --disable-nls \
      --disable-rpath-hack \
    && make -j4 \
  )
  cp "$SRC/dialog" "dialog-$suffix"
  "$strip" "dialog-$suffix" 2>/dev/null || true
  echo "  -> dialog-$suffix ($(stat -c %s dialog-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86" "x86_64-linux-musl" "strip"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl" "$CROSS_STRIP"

echo "OK — built dialog for {x86_64, aarch64}"

#!/usr/bin/sh
# tmux 3.5a build recipe — static-musl, per arch, linked against the
# already-vendored static libevent (libevent.a + event2/ headers under
# vendor/libevent/install-<arch>/) and static ncurses (libncursesw.a +
# headers under vendor/ncurses/install-<arch>/). Drops in at /usr/bin/tmux.
#
# Run tools/fetch-tmux.sh first to populate the source tree, and
# vendor/libevent/build.sh + vendor/ncurses/build.sh first so the
# install-<arch>/ trees exist.
#
# Dependency linking: tmux's configure uses pkg-config to discover
# libevent + ncurses. We bypass pkg-config entirely by passing the
# {LIBEVENT,LIBNCURSES}_{CFLAGS,LIBS} override vars directly (configure
# honours these in place of the pkg-config probe) AND pointing
# PKG_CONFIG_LIBDIR/PKG_CONFIG_PATH at an empty dir so no host .pc files
# leak in (ncdu style). tmux wants the wide ncurses (tinfo/ncursesw);
# our non-split libncursesw.a carries the terminfo code, so -lncursesw
# alone satisfies it.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="tmux-3.5a"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-tmux.sh first" >&2
  exit 1
fi

REPO="$(cd ../.. && pwd)"
LE_X86="$REPO/vendor/libevent/install-x86_64"
LE_ARM="$REPO/vendor/libevent/install-aarch64"
NC_X86="$REPO/vendor/ncurses/install-x86_64"
NC_ARM="$REPO/vendor/ncurses/install-aarch64"

# Empty pkg-config search path so configure can't find a host .pc and is
# forced to use the *_CFLAGS/*_LIBS overrides we pass below.
EMPTY_PC="/tmp/tmux-empty-pkgconfig"
mkdir -p "$EMPTY_PC"

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"
  le="$5"; nc="$6"; host="$7"; strip="$8"
  echo "=== building tmux for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    PKG_CONFIG_LIBDIR="$EMPTY_PC" \
    PKG_CONFIG_PATH="$EMPTY_PC" \
    LIBEVENT_CFLAGS="-I${le}/include" \
    LIBEVENT_LIBS="-L${le}/lib -levent" \
    LIBNCURSES_CFLAGS="-I${nc}/include -I${nc}/include/ncursesw" \
    LIBNCURSES_LIBS="-L${nc}/lib -lncursesw" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE" \
    LDFLAGS="-static" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --enable-static \
    && make -j4 \
  )
  cp "$SRC/tmux" "tmux-$suffix"
  "$strip" "tmux-$suffix" 2>/dev/null || true
  echo "  -> tmux-$suffix ($(stat -c %s tmux-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" "$(uapi_cflags x86_64)" \
  "x86_64" "$LE_X86" "$NC_X86" "x86_64-linux-musl" "strip"

build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" \
  "aarch64" "$LE_ARM" "$NC_ARM" "aarch64-linux-musl" "$CROSS_STRIP"

echo "OK — built tmux for {x86_64, aarch64}"

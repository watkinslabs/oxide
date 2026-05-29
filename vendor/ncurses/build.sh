#!/usr/bin/sh
# ncurses 6.5 build recipe -- per-arch static libncurses.a + libtinfo.a
# installed under vendor/ncurses/install-<arch>/{include,lib}.
#
# F250: needed by vim cross-build (T17). We disable shared libs,
# wide chars are on (vim builds for UTF-8 terminals), no progs, no
# database build -- terminfo is provided by the host musl rootfs
# at /usr/share/terminfo (busybox-applet terminfos work for vim).
set -e

cd "$(dirname "$0")"
SRC="ncurses-6.5"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-ncurses.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"
CROSS_RANLIB="$CROSS_ROOT/bin/aarch64-linux-musl-ranlib"

build_one() {
  arch="$1"; cc="$2"; ar="$3"; ranlib="$4"; host="$5"
  install="install-${arch}"
  echo "=== building ncurses for $arch ==="
  rm -rf "$install"
  mkdir -p "$install"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  # Pre-seed autoconf cache for cross-compile.
  cat > "$SRC/config.cache" <<EOF
cf_cv_func_mkstemp=yes
cf_cv_working_poll=yes
cf_cv_func_nanosleep=yes
cf_cv_link_funcs=link
cf_cv_posix_c_source=-D_POSIX_C_SOURCE=200809L
EOF
  ( cd "$SRC" && \
    CC="$cc" \
    AR="$ar" \
    RANLIB="$ranlib" \
    CFLAGS="-Os -fPIC" \
    ./configure \
      --cache-file=config.cache \
      --host="$host" \
      --prefix="$(pwd)/../$install" \
      --without-shared \
      --with-normal \
      --without-debug \
      --without-ada \
      --without-cxx \
      --without-cxx-binding \
      --without-manpages \
      --without-progs \
      --without-tack \
      --without-tests \
      --enable-pc-files=no \
      --disable-db-install \
      --enable-widec \
      --enable-overwrite \
      --with-default-terminfo-dir=/usr/share/terminfo \
      --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo \
    && make -j4 \
    && make install \
  )
  echo "  -> $install/lib/libncursesw.a ($(stat -c %s $install/lib/libncursesw.a) bytes)"
}

build_one "x86_64"  "musl-gcc"   "ar"          "ranlib"        "x86_64-linux-musl"
build_one "aarch64" "$CROSS_CC" "$CROSS_AR"  "$CROSS_RANLIB" "aarch64-linux-musl"

echo "OK -- built ncurses for {x86_64, aarch64}"

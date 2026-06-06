#!/usr/bin/sh
# vim 9.1.0950 build recipe -- static-musl, features=tiny, linked
# against the vendored static ncurses (F250).
#
# F251: vendor vim into the rootfs for the distro buildout. tiny
# feature set keeps binary modest and avoids interpreter deps.
#
# Run tools/fetch-vim.sh first to populate the source tree, and
# vendor/ncurses/build.sh first so install-<arch>/ exists.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="vim-9.1.0950"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-vim.sh first" >&2
  exit 1
fi

NC_X86="$(cd ../ncurses/install-x86_64 && pwd)"
NC_ARM="$(cd ../ncurses/install-aarch64 && pwd)"

HDRS_X86=/tmp/musl-hdrs-vim
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-vim-arm
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
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; nc_root="$5"
  echo "=== building vim for $arch ==="
  cleanup_objs
  cat > "$SRC/src/auto/config.cache" <<EOF
vim_cv_toupper_broken=no
vim_cv_terminfo=yes
vim_cv_tty_group=world
vim_cv_tty_mode=0620
vim_cv_getcwd_broken=no
vim_cv_stat_ignores_slash=no
vim_cv_memmove_handles_overlap=yes
vim_cv_bcopy_handles_overlap=yes
vim_cv_memcpy_handles_overlap=yes
ac_cv_sizeof_int=4
ac_cv_small_wchar_t=no
EOF
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE -I${nc_root}/include -I${nc_root}/include/ncursesw -Wno-error=incompatible-pointer-types -Wno-error=builtin-declaration-mismatch -fcommon" \
    LDFLAGS="-static -L${nc_root}/lib" \
    LIBS="-lncursesw" \
    vim_cv_toupper_broken=no \
    vim_cv_terminfo=yes \
    vim_cv_tty_group=world \
    vim_cv_tty_mode=0620 \
    vim_cv_getcwd_broken=no \
    vim_cv_stat_ignores_slash=no \
    vim_cv_memmove_handles_overlap=yes \
    vim_cv_bcopy_handles_overlap=yes \
    vim_cv_memcpy_handles_overlap=yes \
    ./configure \
      --host="${arch}-linux-musl" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --with-tlib=ncursesw \
      --with-features=tiny \
      --disable-gui \
      --disable-gtktest \
      --disable-xim \
      --disable-netbeans \
      --disable-channel \
      --disable-nls \
      --disable-acl \
      --disable-selinux \
      --disable-xsmp \
      --disable-rightleft \
      --disable-arabic \
      --disable-farsi \
      --disable-perlinterp \
      --disable-pythoninterp \
      --disable-python3interp \
      --disable-rubyinterp \
      --disable-tclinterp \
      --disable-luainterp \
      --disable-mzschemeinterp \
      --without-x \
    && make -C src auto/osdef.h \
    && sed -i -E '/(tgetent|tgetnum|tgetflag|tgetstr|tgoto|tputs)\(/d' src/auto/osdef.h \
    && make -C src -j4 vim \
  )
  cp "$SRC/src/vim" "vim-$suffix"
  strip "vim-$suffix" 2>/dev/null || true
  echo "  -> vim-$suffix ($(stat -c %s vim-$suffix) bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM"

echo "OK -- built vim for {x86_64, aarch64}"

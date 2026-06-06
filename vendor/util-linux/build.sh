#!/usr/bin/sh
# util-linux 2.40.2 build recipe — static-musl, real distro programs.
# D1 of the distro roadmap. We build the subset that replaces
# busybox versions: login, agetty, mount, su, umount, losetup,
# dmesg, kill, more, cal, script, tty, chsh, hexdump.
#
# Most of util-linux's PAM-aware tools (login, su, chsh, runuser)
# need libpam — we link against vendor/pam/install-<arch>/. The
# rest (mount/umount/agetty) are libc-only.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="util-linux-2.40.2"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-util-linux.sh first" >&2
  exit 1
fi

# statx (arm): the aarch64 cross musl lacks statx; systemd's backport appended
# struct statx + a non-static `int statx(...)` decl to the toolchain's
# <sys/stat.h> (guard __OXIDE_STATX_BACKPORT). util-linux's fileutils.h adds a
# `static inline statx` → "static declaration follows non-static" on arm. Skip
# util-linux's static wrapper when the backport is present + provide a matching
# non-static wrapper (arm only; x86 musl 1.2.5 has statx natively).
FU_H="$SRC/include/fileutils.h"; FU_C="$SRC/lib/fileutils.c"
if [ -f "$FU_H" ] && ! grep -q __OXIDE_STATX_BACKPORT "$FU_H"; then
  sed -i 's/!defined(HAVE_STATX) \&\& defined(HAVE_STRUCT_STATX)/!defined(HAVE_STATX) \&\& !defined(__OXIDE_STATX_BACKPORT) \&\& defined(HAVE_STRUCT_STATX)/' "$FU_H"
fi
if [ -f "$FU_C" ] && ! grep -q __OXIDE_STATX_BACKPORT "$FU_C"; then
  cat >> "$FU_C" <<'STATX_WRAP'

#ifdef __OXIDE_STATX_BACKPORT
#include <unistd.h>
#include <sys/syscall.h>
int statx(int fd, const char *path, int flags, unsigned int mask, struct statx *stx)
{ return syscall(SYS_statx, fd, path, flags, mask, stx); }
#endif
STATX_WRAP
fi

HDRS_X86=/tmp/musl-hdrs-util-linux
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-util-linux-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

# Programs we care about. Full list reduced to what actually
# replaces busybox functionality + provides PID-1-adjacent
# helpers systemd will want later (mount, umount, agetty, login).
PROGRAMS="login agetty mount umount su dmesg kill more cal script tty hexdump chsh losetup swapon swapoff"

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; host="$5"
  pam_root="$(pwd)/../pam/install-${arch}"
  echo "=== building util-linux for $arch ==="
  cleanup_objs
  # Aggressive feature pruning — no NLS, no systemd journal hook (we'll
  # bring that in with systemd-musl), no ncurses-using top-likes, no
  # libuuid bloat we don't use yet.
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os $extra -D_GNU_SOURCE -I${pam_root}" \
    LDFLAGS="-L${pam_root} -L${pam_root}/lib -Wl,-rpath,/usr/lib" \
    LIBS="-lpam -lpam_misc" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --bindir=/bin --sbindir=/sbin \
      --without-systemd \
      --without-systemdsystemunitdir \
      --without-tmpfilesdir \
      --without-ncurses \
      --without-ncursesw \
      --without-tinfo \
      --without-readline \
      --without-libmagic \
      --without-cap-ng \
      --without-selinux \
      --without-audit \
      --without-econf \
      --without-cryptsetup \
      --without-btrfs \
      --without-libutempter \
      --disable-nls \
      --disable-rpath \
      --disable-makeinstall-chown \
      --disable-bash-completion \
      --disable-asciidoc \
      --disable-pylibmount \
      --disable-all-programs \
      --enable-libblkid \
      --enable-libmount \
      --enable-libsmartcols \
      --enable-libuuid \
      --enable-libfdisk \
      --enable-login \
      --enable-agetty \
      --enable-mount \
      --enable-umount \
      --enable-su \
      --enable-dmesg \
      --enable-kill \
      --enable-cal \
      --enable-tty \
      --enable-hexdump \
      --enable-chsh \
      --enable-losetup \
      --enable-swaponoff \
    && make -j4 \
  )
  for p in $PROGRAMS; do
    src_path="$SRC/$p"
    [ -f "$src_path" ] || continue
    cp "$src_path" "$p-$suffix"
    strip "$p-$suffix" 2>/dev/null || true
    echo "  -> $p-$suffix ($(stat -c %s $p-$suffix) bytes)"
  done
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "x86_64-linux-musl"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "aarch64-linux-musl"

echo "OK — built util-linux for {x86_64, aarch64}"

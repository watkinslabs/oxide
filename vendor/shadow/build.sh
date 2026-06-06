#!/usr/bin/sh
# shadow-utils 4.16.0 build recipe -- D2 of distro roadmap.
# Static-musl. Provides real useradd, userdel, usermod, groupadd,
# passwd, chage, gpasswd, chgpasswd, newgrp.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="shadow-4.16.0"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-shadow.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-shadow
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-shadow-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

PROGRAMS="useradd userdel usermod groupadd groupdel groupmod passwd chage gpasswd newgrp chgpasswd"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; host="$5"
  pam_root="$(pwd)/../pam/install-${arch}"
  echo "=== building shadow for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os $extra -D_GNU_SOURCE -I${pam_root} -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS="-static -L${pam_root}" \
    LIBS="-lpam -lpam_misc" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --bindir=/bin --sbindir=/sbin \
      --disable-nls \
      --disable-rpath \
      --disable-shared \
      --enable-static \
      --without-selinux \
      --without-audit \
      --without-libcrack \
      --without-libbsd \
      --without-libpasswdqc \
      --without-tcb \
      --without-acl \
      --without-attr \
      --without-su \
      --with-libpam \
      --disable-account-tools-setuid \
      --enable-shadowgrp \
    && make -j4 \
  )
  for p in $PROGRAMS; do
    found=$(find $SRC -maxdepth 3 -type f -name "$p" -executable 2>/dev/null | head -1)
    [ -n "$found" ] || continue
    cp "$found" "$p-$suffix"
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

echo "OK -- built shadow for {x86_64, aarch64}"

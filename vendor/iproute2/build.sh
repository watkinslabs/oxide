#!/usr/bin/sh
# iproute2 6.10.0 build recipe -- D4 of distro roadmap.
# Static-musl. ip, ss, tc, bridge, rtmon, lnstat, nstat, routef,
# routel, rtacct, rtmon, ifstat.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="iproute2-6.10.0"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-iproute2.sh first" >&2
  exit 1
fi

HDRS_X86=/tmp/musl-hdrs-iproute2
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-iproute2-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; ar="$5"
  echo "=== building iproute2 for $arch ==="
  cleanup_objs
  # iproute2's configure is a hand-rolled shell script that probes
  # libelf, libbpf, libcap, libmnl, libbsd, libselinux. We disable
  # all the optional bells and ship a tight base build.
  # Empty pkg-config search so configure cannot find host libelf/libbsd/etc.
  mkdir -p /tmp/empty-pkgconfig
  ( cd "$SRC" && \
    CC="$cc" AR="$ar" \
    PKG_CONFIG_PATH=/tmp/empty-pkgconfig \
    PKG_CONFIG_LIBDIR=/tmp/empty-pkgconfig \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS="-static" \
    ./configure \
    && make CC="$cc" AR="$ar" \
      SUBDIRS="lib ip tc bridge misc genl" \
      LDFLAGS="-static" \
      CCOPTS="-Os -static $extra -D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
      HAVE_ELF=n HAVE_LIBBPF=n HAVE_BERKELEY_DB=n HAVE_SELINUX=n HAVE_LIBCAP=n \
      HAVE_LIBBSD=n HAVE_LIBMNL=n \
      -j4 \
  )
  for p in ip/ip misc/ss tc/tc bridge/bridge ip/rtmon misc/lnstat misc/nstat misc/ifstat; do
    found="$SRC/$p"
    [ -f "$found" ] || continue
    name=$(basename "$found")
    cp "$found" "$name-$suffix"
    strip "$name-$suffix" 2>/dev/null || true
    echo "  -> $name-$suffix ($(stat -c %s $name-$suffix) bytes)"
  done
}

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "ar"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$CROSS_AR"

echo "OK -- built iproute2 for {x86_64, aarch64}"

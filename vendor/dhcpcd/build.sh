#!/usr/bin/sh
# dhcpcd 10.3.2 build recipe — static-musl binaries committed as
# vendor/dhcpcd/dhcpcd-x86_64 and vendor/dhcpcd/dhcpcd-aarch64.
# Run tools/fetch-dhcpcd.sh first to populate the source tree.
#
# Per-arch — build one or both:
#   ./build.sh            # both (x86 then arm)
#   ./build.sh x86        # host musl-gcc only
#   ./build.sh arm        # aarch64 cross only
#
# Feature set (minimal embedded DHCPv4 client): --disable-inet6/-dhcp6/-auth,
# --disable-privsep, --without-udev, --small, --enable-static.
set -e

cd "$(dirname "$0")"
SRC="dhcpcd-10.3.2"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-dhcpcd.sh first" >&2
  exit 1
fi

. "$(dirname "$0")/../lib/uapi-stage.sh"

CONF="--prefix=/ --sbindir=/sbin --sysconfdir=/etc \
  --dbdir=/var/db/dhcpcd --libexecdir=/lib/dhcpcd \
  --disable-inet6 --disable-dhcp6 --disable-auth \
  --disable-privsep --without-udev --small --enable-static"

# --- x86_64 (host musl-gcc) -------------------------------------------
# musl-gcc's sysroot lacks the Linux UAPI headers (linux/, asm/, ...), so we
# stage host copies and -isystem them. Stage FRESH every time: the old
# `test -d || cp` skip-if-exists left a stale/empty /tmp dir from an
# interrupted run in place, so asm/types.h was never copied and the build
# died on it. `cp -rL` dereferences any symlinked uapi dirs.
build_x86() {
  ( cd "$SRC"
    make distclean >/dev/null 2>&1 || true
    CC=musl-gcc CFLAGS="-Os -static -no-pie -fno-pie $(uapi_cflags x86_64)" \
      LDFLAGS="-static -no-pie" ./configure $CONF >/dev/null
    make -j8 -C src dhcpcd
    cp -f src/dhcpcd ../dhcpcd-x86_64
    strip ../dhcpcd-x86_64
  )
  echo "vendor/dhcpcd/dhcpcd-x86_64: built ($(stat -c%s dhcpcd-x86_64) bytes)"
}

# --- aarch64 (cross) --------------------------------------------------
# The aarch64-linux-musl-cross sysroot already carries the full Linux UAPI
# headers — use them. Do NOT -isystem the host's x86 /usr/include copies:
# wrong arch, and the asm->asm-generic symlink hack was missing asm/types.h.
build_arm() {
  ARM_TC="$(cd ../cross/aarch64-linux-musl-cross/bin 2>/dev/null && pwd)"
  if [ -z "$ARM_TC" ]; then
    echo "vendor/dhcpcd/dhcpcd-aarch64: skip (run tools/fetch-cross.sh)" >&2
    return 0
  fi
  ( cd "$SRC"
    make distclean >/dev/null 2>&1 || true
    export PATH="$ARM_TC:$PATH"
    CC=aarch64-linux-musl-gcc CFLAGS="-Os -static -no-pie -fno-pie" \
      LDFLAGS="-static -no-pie" HOST=aarch64-linux-musl \
      ./configure --build=x86_64-linux-musl --host=aarch64-linux-musl $CONF >/dev/null
    make -j8 -C src dhcpcd
    cp -f src/dhcpcd ../dhcpcd-aarch64
    aarch64-linux-musl-strip ../dhcpcd-aarch64 2>/dev/null || true
  )
  echo "vendor/dhcpcd/dhcpcd-aarch64: built ($(stat -c%s dhcpcd-aarch64) bytes)"
}

case "${1:-all}" in
  x86) build_x86 ;;
  arm) build_arm ;;
  all) build_x86; build_arm ;;
  *)   echo "usage: $0 [x86|arm|all]" >&2; exit 2 ;;
esac

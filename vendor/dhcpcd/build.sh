#!/usr/bin/sh
# dhcpcd 10.3.2 build recipe — pre-built static-musl binaries
# checked in as `vendor/dhcpcd/dhcpcd-x86_64` and
# `vendor/dhcpcd/dhcpcd-aarch64`. Re-run this to rebuild against a
# fresh upstream (run `tools/fetch-dhcpcd.sh` first to populate the
# source tree).
#
# Feature set (matches a minimal embedded DHCPv4 client):
#   --disable-inet6         — no IPv6
#   --disable-dhcp6         — no DHCPv6
#   --disable-auth          — no RFC3118 message auth
#   --disable-privsep       — no privsep (we're single-uid root for now)
#   --without-udev          — no libudev dep (we don't ship udev)
#   --small                 — drop non-essential option decoders
#   --enable-static         — fully-static binary
#
# Output: two static-musl binaries committed to vendor/.
set -e

cd "$(dirname "$0")"
SRC="dhcpcd-10.3.2"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-dhcpcd.sh first" >&2
  exit 1
fi

# musl-gcc lacks Linux UAPI headers (linux/, asm/, asm-generic/, mtd/,
# scsi/, sound/, rdma/, xen/). Stage host copies into a private tree and
# -isystem them (same approach as vendor/busybox/build.sh).
HDRS_X86=/tmp/musl-hdrs-dhcpcd
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-dhcpcd-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done
test -L "$HDRS_ARM/asm" || ln -sf asm-generic "$HDRS_ARM/asm"

# --- x86_64 (host) -----------------------------------------------------
cd "$SRC"
make distclean >/dev/null 2>&1 || true
CC=musl-gcc CFLAGS="-Os -static -no-pie -fno-pie -isystem $HDRS_X86" LDFLAGS="-static -no-pie" \
  ./configure \
    --prefix=/ --sbindir=/sbin --sysconfdir=/etc \
    --dbdir=/var/db/dhcpcd --libexecdir=/lib/dhcpcd \
    --disable-inet6 --disable-dhcp6 --disable-auth \
    --disable-privsep --without-udev --small --enable-static \
    >/dev/null
make -j8 -C src dhcpcd
cp -f src/dhcpcd ../dhcpcd-x86_64
strip ../dhcpcd-x86_64
echo "vendor/dhcpcd/dhcpcd-x86_64: built ($(stat -c%s ../dhcpcd-x86_64) bytes)"
cd ..

# --- aarch64 (cross) ---------------------------------------------------
ARM_TC="$(cd ../cross/aarch64-linux-musl-cross/bin 2>/dev/null && pwd)"
if [ -z "$ARM_TC" ]; then
  echo "vendor/dhcpcd/dhcpcd-aarch64: skip (run tools/fetch-cross.sh)" >&2
  exit 0
fi

cd "$SRC"
make distclean >/dev/null 2>&1 || true
export PATH="$ARM_TC:$PATH"
CC=aarch64-linux-musl-gcc CFLAGS="-Os -static -no-pie -fno-pie -isystem $HDRS_ARM" LDFLAGS="-static -no-pie" \
  HOST=aarch64-linux-musl \
  ./configure \
    --build=x86_64-linux-musl --host=aarch64-linux-musl \
    --prefix=/ --sbindir=/sbin --sysconfdir=/etc \
    --dbdir=/var/db/dhcpcd --libexecdir=/lib/dhcpcd \
    --disable-inet6 --disable-dhcp6 --disable-auth \
    --disable-privsep --without-udev --small --enable-static \
    >/dev/null
make -j8 -C src dhcpcd
cp -f src/dhcpcd ../dhcpcd-aarch64
aarch64-linux-musl-strip ../dhcpcd-aarch64 2>/dev/null || true
echo "vendor/dhcpcd/dhcpcd-aarch64: built ($(stat -c%s ../dhcpcd-aarch64) bytes)"

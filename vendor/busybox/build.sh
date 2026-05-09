#!/usr/bin/sh
# busybox 1.37.0 build recipe — pre-built static-musl binary checked
# in as `vendor/busybox/busybox`. Re-run this to rebuild against a
# fresh upstream (network access required).
#
# Output: vendor/busybox/busybox (~1.2 MiB static-musl x86_64).
#
# Notes:
#   - musl-gcc lacks Linux UAPI headers (linux/, asm/, asm-generic/,
#     mtd/, scsi/, sound/, rdma/, xen/) that busybox needs. The build
#     copies host-side kernel headers into a temporary tree and points
#     EXTRA_CFLAGS at it via -isystem. This avoids polluting musl's
#     own include dir while keeping the build self-contained.
#   - LDFLAGS=--static forces a fully-static binary. busybox internally
#     pulls -lcrypt -lm -lresolv -lrt; musl-gcc resolves those via libc.a.
#   - HOSTCC=gcc is required so the host-side helper tools (mkconfig,
#     etc.) build with the system compiler.
set -e

cd "$(dirname "$0")"
test -d busybox-1.37.0 || {
  curl -sL https://busybox.net/downloads/busybox-1.37.0.tar.bz2 -o bb.tar.bz2
  tar xjf bb.tar.bz2
  rm bb.tar.bz2
}
cd busybox-1.37.0

mkdir -p /tmp/musl-hdrs
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "/tmp/musl-hdrs/$d" || cp -r "/usr/include/$d" "/tmp/musl-hdrs/$d" 2>/dev/null || true
done

CC=musl-gcc HOSTCC=gcc make defconfig
sed -i 's/^CONFIG_TC=y/# CONFIG_TC is not set/' .config
# FEATURE_INSTALLER off: the --list/--install code path inside
# busybox 1.37 mis-fires under our exec+argv handoff and dumps
# the applet table when invoked as a hardlinked applet name
# (e.g., /bin/echo). With INSTALLER disabled, run_applet_and_exit
# takes the find_applet_by_name route and dispatches /bin/echo
# etc. correctly. The `busybox --install` step is a one-time
# rootfs-setup operation, not a runtime requirement, so leaving
# INSTALLER off permanently is safe.
sed -i 's/^CONFIG_FEATURE_INSTALLER=y/# CONFIG_FEATURE_INSTALLER is not set/' .config
make CC=musl-gcc HOSTCC=gcc EXTRA_CFLAGS="-isystem /tmp/musl-hdrs" -j8 LDFLAGS=--static
cp -f busybox ../busybox
echo "vendor/busybox/busybox: $(./busybox --help 2>&1 | head -1)"

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
strip ../busybox
echo "vendor/busybox/busybox (x86_64): built"

# aarch64 cross-build. The static cross-toolchain at
# vendor/cross/aarch64-linux-musl-cross is the path we provision
# (see vendor/cross/README — fetched once from musl.cc).
ARM_TC=../../cross/aarch64-linux-musl-cross/bin
if test -d "$ARM_TC"; then
  export PATH="$(realpath $ARM_TC):$PATH"
  mkdir -p /tmp/musl-hdrs-arm
  for d in linux asm-generic mtd scsi sound rdma xen misc; do
    test -d "/tmp/musl-hdrs-arm/$d" || cp -r "/usr/include/$d" "/tmp/musl-hdrs-arm/$d" 2>/dev/null || true
  done
  test -d /tmp/musl-hdrs-arm/asm || ln -sf asm-generic /tmp/musl-hdrs-arm/asm
  make distclean
  ARCH=arm64 CROSS_COMPILE=aarch64-linux-musl- HOSTCC=gcc make defconfig
  sed -i 's/^CONFIG_TC=y/# CONFIG_TC is not set/' .config
  sed -i 's/^CONFIG_FEATURE_INSTALLER=y/# CONFIG_FEATURE_INSTALLER is not set/' .config
  # x86-only SHA-NI HWACCEL: undefined symbols on arm64.
  sed -i 's/^CONFIG_SHA1_HWACCEL=y/# CONFIG_SHA1_HWACCEL is not set/' .config
  sed -i 's/^CONFIG_SHA256_HWACCEL=y/# CONFIG_SHA256_HWACCEL is not set/' .config
  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-musl- HOSTCC=gcc \
       EXTRA_CFLAGS="-isystem /tmp/musl-hdrs-arm" -j8 LDFLAGS=--static
  cp -f busybox ../busybox-aarch64
  aarch64-linux-musl-strip ../busybox-aarch64 2>/dev/null || true
  echo "vendor/busybox/busybox-aarch64: built"
else
  echo "vendor/busybox/busybox-aarch64: skip (no cross-toolchain at $ARM_TC)"
fi

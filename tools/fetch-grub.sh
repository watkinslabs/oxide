#!/usr/bin/sh
# Vendor the GRUB aarch64 EFI platform modules into vendor/grub/arm64-efi
# so `grub2-mkrescue -d vendor/grub/arm64-efi` can build the ARM GRUB
# boot ISO WITHOUT a system `grub2-efi-aa64-modules` install (the host's
# own GRUB is x86-only here). Idempotent — skips if already vendored.
#
# Output:
#   vendor/grub/arm64-efi/{modinfo.sh,linux.mod,normal.mod,...}  (~6 MiB)
#
# Used by `xtask grub --arch aarch64` to produce the GRUB EFI ISO that
# OVMF loads and that `linux`-boots the kernel's arm64 EFI-stub Image.
#
# Source: Fedora `grub2-efi-aa64-modules` noarch RPM (GRUB 2.12). Pulled
# via `dnf download` (no install/root) then unpacked with rpm2cpio|cpio.
set -e

PKG="grub2-efi-aa64-modules"
cd "$(dirname "$0")/../vendor"
mkdir -p grub
cd grub

if [ -f arm64-efi/modinfo.sh ] && [ -f arm64-efi/linux.mod ]; then
  echo "fetch-grub: arm64-efi modules already vendored"
  exit 0
fi

for t in dnf rpm2cpio cpio; do
  command -v "$t" >/dev/null 2>&1 || { echo "fetch-grub: need $t on PATH"; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
( cd "$tmp" && dnf download "$PKG" )
rpm="$(ls "$tmp"/*.rpm | head -1)"
[ -n "$rpm" ] || { echo "fetch-grub: dnf download produced no rpm"; exit 1; }
( cd "$tmp" && rpm2cpio "$rpm" | cpio -idm 2>/dev/null )
src="$tmp/usr/lib/grub/arm64-efi"
[ -f "$src/modinfo.sh" ] || { echo "fetch-grub: arm64-efi modules not in rpm"; exit 1; }
rm -rf arm64-efi
cp -r "$src" arm64-efi
echo "fetch-grub: vendored $(ls arm64-efi | wc -l) modules to $(pwd)/arm64-efi"

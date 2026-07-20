#!/usr/bin/sh
# Vendor the GRUB aarch64 EFI platform modules into vendor/grub/arm64-efi
# so `grub2-mkrescue -d vendor/grub/arm64-efi` can build the ARM GRUB
# boot ISO without a system `grub2-efi-aa64-modules` installation.
#
# Source: Fedora's noarch `grub2-efi-aa64-modules` RPM. The package is
# downloaded and unpacked without installation or elevated privileges.
set -e

PKG="grub2-efi-aa64-modules"
cd "$(dirname "$0")/../vendor"
mkdir -p grub
cd grub

if [ -f arm64-efi/modinfo.sh ] && [ -f arm64-efi/linux.mod ]; then
  echo "fetch-grub: arm64-efi modules already vendored"
  exit 0
fi

for tool in dnf rpm2cpio cpio; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "fetch-grub: need $tool on PATH"
    exit 1
  }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
( cd "$tmp" && dnf download "$PKG" )
rpm="$(ls "$tmp"/*.rpm | head -1)"
[ -n "$rpm" ] || { echo "fetch-grub: dnf download produced no RPM"; exit 1; }
( cd "$tmp" && rpm2cpio "$rpm" | cpio -idm 2>/dev/null )
src="$tmp/usr/lib/grub/arm64-efi"
[ -f "$src/modinfo.sh" ] || { echo "fetch-grub: arm64-efi modules not in RPM"; exit 1; }
rm -rf arm64-efi
cp -r "$src" arm64-efi
echo "fetch-grub: vendored $(ls arm64-efi | wc -l) modules to $(pwd)/arm64-efi"

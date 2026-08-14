#!/usr/bin/env bash
# Validate that QEMU accepts the native hardware smoke topology before guest
# execution.  `-S` stops at reset; timeout's expected status proves that every
# device was realized rather than this being a boot test.
set -eu -o pipefail

out=$(mktemp)
trap 'rm -f "$out"' EXIT
set +e
timeout --signal=TERM 2 qemu-system-x86_64 \
    -machine q35,kernel_irqchip=split -accel tcg -nodefaults \
    -display none -monitor none -serial none -S \
    -device intel-iommu,intremap=on,caching-mode=on \
    -netdev user,id=net0 -device e1000e,netdev=net0,bus=pcie.0 \
    -device qemu-xhci,id=xhci,bus=pcie.0 \
    -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0 \
    -blockdev driver=null-co,node-name=nvm0,size=16777216 \
    -device nvme,serial=oxnvme,drive=nvm0,bus=pcie.0 \
    -device ich9-ahci,id=boot-ahci,bus=pcie.0 \
    -blockdev driver=null-co,node-name=root,size=16777216 \
    -device ide-hd,drive=root,bus=boot-ahci.0,serial=oxide-root \
    -blockdev driver=null-co,node-name=home,size=16777216 \
    -device ide-hd,drive=home,bus=boot-ahci.1,serial=oxide-home \
    -vga std >"$out" 2>&1
rc=$?
set -e
if [ "$rc" -ne 124 ]; then
    cat "$out" >&2
    exit "$rc"
fi
if grep -Eiq 'error|failed|invalid|not found|does not support' "$out"; then
    cat "$out" >&2
    exit 1
fi
printf 'native-q35: QEMU accepted AHCI/NVMe/e1000e/xHCI/VT-d topology\n'

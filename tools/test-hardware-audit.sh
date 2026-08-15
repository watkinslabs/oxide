#!/usr/bin/env bash
# Regression test for the physical-hardware audit's PCI binding verdicts.
# It uses a synthetic sysfs tree so the result is independent of the host.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
audit="$repo/tools/xtask/src/assets/oxide-hardware-audit.sh"
root=$(mktemp -d /tmp/oxide-hardware-audit-XXXXXX)
trap 'rm -rf "$root"' EXIT

device_root="$root/sys/bus/pci/devices"
driver_root="$root/sys/bus/pci/drivers"
mkdir -p "$device_root" "$driver_root/nvme" "$driver_root/xhci_hcd" "$driver_root/e1000" "$driver_root/e1000e" "$driver_root/igc" "$driver_root/atlantic" "$driver_root/r8169" "$driver_root/other"
mkdir -p "$root/sys/class/drm/card0" "$root/sys/class/drm/card1/device"
mkdir -p "$driver_root/nvidia"
ln -s "$driver_root/nvidia" "$root/sys/class/drm/card1/device/driver"
printf '%s\n' 0x10de > "$root/sys/class/drm/card1/device/vendor"
printf '%s\n' 0x2684 > "$root/sys/class/drm/card1/device/device"
mkdir -p "$root/sys/class/drm/card1-DP-1"

device() {
    local bdf=$1 vendor=$2 product=$3 class=$4 driver=${5:-}
    local dir="$device_root/$bdf"
    mkdir -p "$dir"
    printf '%s\n' "$vendor" > "$dir/vendor"
    printf '%s\n' "$product" > "$dir/device"
    printf '%s\n' "$class" > "$dir/class"
    [ -z "$driver" ] || ln -s "$driver_root/$driver" "$dir/driver"
}

device 0000:00:01.0 0x8086 0xf1a5 0x01080200 nvme
device 0000:00:02.0 0x8086 0xf1a6 0x01080200
device 0000:00:03.0 0x8086 0x100e 0x02000000 other
device 0000:00:04.0 0x8086 0x100e 0x02000000 e1000
device 0000:00:05.0 0x10ec 0x8125 0x02000000 r8169
device 0000:00:06.0 0x10ec 0x8125 0x02000000 other
device 0000:00:07.0 0x8086 0x1502 0x02000000
device 0000:00:08.0 0x8086 0x150e 0x02000000
device 0000:00:09.0 0x1d6a 0x04c0 0x02000000 atlantic
device 0000:00:0a.0 0x8086 0x15f3 0x02000000 igc
device 0000:00:0b.0 0x8086 0x125c 0x02000000
device 0000:00:0c.0 0x8086 0x153a 0x02000000
device 0000:00:0d.0 0x8086 0x10d3 0x02000000 e1000e
device 0000:00:0e.0 0x1022 0x14c9 0x0c033000 xhci_hcd
device 0000:00:0f.0 0x8086 0x10ea 0x02000000 e1000e
device 0000:00:10.0 0x10ec 0x8125 0x02000000

out_missing=$(OXIDE_HARDWARE_AUDIT_ROOT="$root" sh "$audit")
printf '%s\n' "$out_missing" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|NEEDS-FIRMWARE|bdf=0000:00:10.0|driver=r8169|reason=rtl8125-payload-unavailable'
mkdir -p "$root/usr/lib/firmware/rtl_nic"
touch "$root/usr/lib/firmware/rtl_nic/rtl8125b-2.fw"

out=$(OXIDE_HARDWARE_AUDIT_ROOT="$root" sh "$audit")
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:01.0|driver=nvme'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|UNBOUND|bdf=0000:00:02.0|expected=nvme'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|WRONG-DRIVER|bdf=0000:00:03.0|expected=e1000|driver=other'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:04.0|driver=e1000'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:05.0|driver=r8169'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|WRONG-DRIVER|bdf=0000:00:06.0|expected=r8169|driver=other'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|UNBOUND|bdf=0000:00:07.0|expected=e1000e'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|NEEDS-DRIVER|bdf=0000:00:08.0|driver=igb|reason=linux-igb-family'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:09.0|driver=atlantic'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:0a.0|driver=igc'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|UNBOUND|bdf=0000:00:0b.0|expected=igc'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|UNBOUND|bdf=0000:00:0c.0|expected=e1000e'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:0d.0|driver=e1000e'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:0e.0|driver=xhci_hcd'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|BOUND|bdf=0000:00:0f.0|driver=e1000e'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|driver-assessment|UNBOUND|bdf=0000:00:10.0|expected=r8169'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|display-card|FIRMWARE-FALLBACK|card=card0|driver=simpledrm'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|display-card|NEEDS-DRIVER|card=card1|vendor=0x10de|device=0x2684|driver=nvidia-drm'
printf '%s\n' "$out" | grep -Fx 'OXIDE_HARDWARE_AUDIT|v1|display|PRESENT|cards=2'

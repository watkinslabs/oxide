#!/usr/bin/env bash
# Fast smoke runner. Boots the prebuilt GRUB ISO directly (bypassing
# xtask's rebuild step), watches serial stdio for PASS/FAIL markers,
# kills QEMU as soon as the last expected smoke reports.
#
# Usage:
#   tools/run-smokes.sh x86_64
#   tools/run-smokes.sh aarch64
#   tools/run-smokes.sh both
#
# Exits 0 only if every expected smoke is PASS on every requested arch.

set -o pipefail
arch_arg="${1:-x86_64}"

run_one() {
  local arch="$1"
  case "$arch" in x86_64|aarch64) ;; *) echo "arch must be x86_64 or aarch64"; return 2;; esac

  local repo; repo="$(cd "$(dirname "$0")/.." && pwd)"
  local img="$repo/target/oxide-$arch-grub.iso"
  if [ ! -f "$img" ]; then
    echo "no boot ISO at $img — run 'cargo run -p xtask -- image --arch $arch --features debug-all' first" >&2
    return 2
  fi

  local log; log="$(mktemp -t oxide-smoke-$arch.XXXXXX)"
  local cleanup_files=("$log")
  cleanup() {
    if kill -0 "$qemu_pid" 2>/dev/null; then
      kill "$qemu_pid" 2>/dev/null || true
      sleep 0.2
      kill -9 "$qemu_pid" 2>/dev/null || true
    fi
    for f in "${cleanup_files[@]}"; do rm -f "$f"; done
  }
  trap cleanup RETURN

  # Limine is gone: $img is the GRUB boot ISO. x86 = SeaBIOS El Torito
  # (qemu default, no -bios) + multiboot2 kernel + ext4 rootfs on
  # virtio-blk; arm = OVMF→GRUB→EFI-stub `linux` with the rootfs embedded
  # in the kernel Image (no block device) + semihosting for early UART.
  local qemu_args
  if [ "$arch" = "x86_64" ]; then
    qemu_args=(qemu-system-x86_64
      -machine q35 -cpu Haswell-v4 -m 1G
      -cdrom "$img" -boot d
      -drive "if=none,id=hd0,format=raw,file=$repo/kernel/blobs/rootfs-x86_64.img"
      -device "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0"
      -display none -no-reboot -no-shutdown
      -serial stdio)
  else
    qemu_args=(qemu-system-aarch64
      -machine virt,gic-version=3,its=on -cpu cortex-a72 -m 2G
      -bios "$repo/vendor/firmware/ovmf-aarch64.fd"
      -cdrom "$img" -boot d
      -display none -no-reboot
      # Semihosting required: boot-aarch64 uses `hlt #0xf000`
      # for early-boot UART output before pl011 is set up;
      # without this QEMU treats it as a real hlt and stalls.
      -semihosting-config "enable=on,target=native"
      -serial stdio)
  fi

  "${qemu_args[@]}" </dev/null >"$log" 2>&1 &
  local qemu_pid=$!

  local expected=(sem_smoke msg_smoke mq_smoke ptrace_smoke ptrace_singlestep_smoke mprotect_smoke)
  local total=${#expected[@]}
  declare -A status
  # ARM UEFI firmware boot is ~25s slower than x86; budget separately.
  # x86 needs >30s once init runs all 5 IPC smokes back-to-back.
  local boot_budget; [ "$arch" = "aarch64" ] && boot_budget=120 || boot_budget=60
  local deadline=$(( $(date +%s) + boot_budget ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for name in "${expected[@]}"; do
      [ -n "${status[$name]:-}" ] && continue
      if grep -aq "${name}: PASS" "$log" 2>/dev/null; then
        status[$name]=PASS
      elif grep -aq "${name}: FAIL" "$log" 2>/dev/null; then
        status[$name]=FAIL
      fi
    done
    [ "${#status[@]}" -ge "$total" ] && break
    sleep 0.3
  done

  echo "=== smoke results (arch=$arch) ==="
  local overall=0
  for name in "${expected[@]}"; do
    local s="${status[$name]:-MISSING}"
    echo "  $name: $s"
    [ "$s" = "PASS" ] || overall=1
  done
  echo "=================================="
  return "$overall"
}

if [ "$arch_arg" = "both" ]; then
  rc=0
  run_one x86_64  || rc=1
  run_one aarch64 || rc=1
  exit "$rc"
else
  run_one "$arch_arg"
fi

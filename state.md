# Session hand-off

## Headline
Branch `F376-arm-selfbootstrap` (PR #1525), autonomous loop. **Limine fully
removed; GRUB-only on both arches; both reach `oxide login:` (x86 40s, arm
44s).** **arm PSCI SMP=2 PROVEN on the `-kernel` path.** python exec_prefix
warning fixed. docs/55 open questions resolved. Remaining: full SMP=2
lockstep (x86 INIT-SIPI + arm-EFI ACPI-MADT) and the graphical display
(virtio-gpu not enumerated — `pci: devices=0`).

## Landed + pushed this session (PR #1525)
- python: `/usr/lib/python3.13/lib-dynload` landmark → kills exec_prefix warn.
- **Limine removed entirely** (limine-proto, boot-*/limine.rs, LIMINE_* statics,
  .limine_requests, vendor/limine, *.limine.conf, Makefile/scripts/xtask
  image_qemu Limine plumbing). x86=MB2, arm=DTB/self-boot.
- `dtb::enum_cpus` (hosted-tested) + `855b41ce` arm PSCI AP-startup
  (ApBootBlock + oxide_ap_entry_arm_psci trampoline + bring_up_aps_psci +
  publish_psci_ap_params).
- `81b5357b` **fixed a project-life-long latent bug**: `dtb_totalsize`/
  `read_dtb_memory` read only 8 bytes before `parse_header` (needs ≥40) →
  the arm DTB NEVER parsed → memmap silently used a 1GB fallback + cmdline
  the arch-default all along. Now real DTB memmap/cmdline + enum_cpus works.
  Also: AP boot-block phys via hardware `AT S1E1R` (heap is kernel-image
  high half, not HHDM).
- `d4f0a72a` docs/55 §17 open questions resolved (Linux-equivalence).

## arm PSCI SMP=2 — PROVEN (`-kernel` path)
`OXIDE_QEMU_HEADLESS=1 cargo run -p xtask -- selfboot --arch aarch64 --smp 2
--features "debug-irq,debug-boot"` → `[smp-psci] cpus=2`, `cpu_on st=0`,
`[ap] entered ap_main` + `[ap] online aff=1`. CPU#1 completes trampoline →
ap_main → GIC/runqueue hook → online; both CPUs run (interleaved UART).

## Open work (priority order; gates stay SMP=1 until BOTH SMP arches land)
1. **Full SMP=2 lockstep** (TASKS.md S4a-smp-regress): (a) arm EFI/GRUB path
   has NO DTB (OVMF didn't install gFdtTableGuid → `dtb_pa=0`; that's why
   `make qemu-arm` was always on the memmap fallback) → enumerate CPUs from
   **ACPI MADT GICC** (OVMF gives ACPI; efi_stub must also grab ACPI RSDP).
   (b) **x86**: ACPI MADT LAPIC enum + INIT-SIPI + real-mode AP trampoline
   (NO INIT-SIPI in kernel — Limine did it). Then flip both gates to -smp 2.
   The PSCI trampoline + driver are proven; only the enum source differs.
2. **Graphical display** (user's "docs 55 = the display"): root cause is
   `pci: devices=0` — the virtio-gpu-pci device isn't enumerated on arm
   (known-hard arm PCI ECAM; see memory `virtio_pci_progress`, "UEFI leaves
   PCI Memory bit OFF on QEMU virt"). fbcon/fbdev/drv-virtio-gpu exist; the
   framebuffer never goes live → only serial shows output. docs/55 is the
   FONT layer atop a live framebuffer, not the framebuffer itself.
3. python interactive segfault: non-reproducing under instrumentation (the
   "hang" is a CPython brute-force close storm, not a kernel crash). Revisit
   only if it reproduces.

## First command next session
```
cd /home/nd/oxide2 && git log --oneline -8 && sed -n '/S4a-smp-regress/,+1p' TASKS.md
```
Then: x86 INIT-SIPI SMP (qemu MCP single-step) OR the arm PCI/virtio-gpu
display bring-up. Use the qemu MCP for both (single-step / qemu_screen).

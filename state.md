# Session hand-off

## Headline
Branch `F376-arm-selfbootstrap` (PR #1525), autonomous loop. **Limine fully
removed; GRUB-only; both arches reach `oxide login:` (x86 40s, arm 44s).**
This session systematically restored everything Limine's removal silently
regressed on arm — DTB parse, ACPI, PCI, the **graphical display**, and SMP
— and un-gated device init so the display works in release, not just debug.

## DONE + pushed this session (PR #1525)
- **Limine removed entirely** (code/xtask/vendor/configs/Makefile).
- **busybox removed** (real util-linux mount/umount; bash=/bin/sh).
- python `lib-dynload` landmark → exec_prefix warning gone.
- **DTB-parse bug fixed** (`81b5357b`): 8-byte header read vs ≥40 needed —
  the arm DTB NEVER parsed; memmap ran on a 1GB fallback + cmdline on the
  arch-default the whole project life. Now real memmap/cmdline + /cpus enum.
- **arm PSCI SMP=2 PROVEN both paths** (`855b41ce`/`81b5357b`/`823df2c1`):
  `oxide_ap_entry_arm_psci` MMU-off trampoline + `bring_up_aps_psci`; CPU
  enum from DTB `/cpus` (-kernel) or ACPI-MADT GICC (EFI). `[ap] online
  aff=1` on both. Boot-block phys via `AT S1E1R` (heap is kernel-image
  high half, not HHDM).
- **ACPI RSDP restored** (`3eab5591`): efi_stub grabs gEfiAcpi20TableGuid →
  XSDT→MCFG→MADT → **`pci: devices=5` + virtio-gpu `scanout 1280x800
  painted` + CPU enum**. All dark since Limine left (it surfaced rsdp_pa).
- **device init un-gated** (`581f4671`): `enumerate_and_log` had wrapped PCI
  enum + GPU install in `debug_boot!` → release = serial-only. Now device
  init runs in every build; pure-release arm reaches login.
- all kernel warnings hand-cleaned (`9ca7d05e`); docs/55 OQs resolved
  (`d4f0a72a`); CHANGELOG entry (`29134415`).

## Open work (priority order)
1. **x86 SMP=2 — sole remaining piece for the gate flip** (TASKS.md
   S4a-smp-regress). x86 `bring_up_aps_x86` only parks `goto_address`
   (Limine pattern); NO INIT-SIPI, no real-mode trampoline. Needs: 16-bit
   AP trampoline in a low (<1MB) identity page (16→32→64-bit: GDT,
   CR3=kernel PML4, EFER.LME, CR0.PG → `oxide_ap_entry_x86` + per-AP stack)
   + INIT-IPI then 2×SIPI via LAPIC ICR per `cpu::get()` APIC id (x86 MADT
   LAPIC enum already fills cpu_topology). Highest risk, no scaffolding —
   DO WITH qemu MCP single-step. Then flip BOTH gates to -smp 2 (arm SMP=2
   already works; held at 1 only for lockstep).
2. **Un-gate virtio-net iface + netlink seed** (still in `debug_boot!`,
   pci_boot/mod.rs enumerate_and_log ~583-665) → release networking. Same
   pattern as the GPU un-gate; intricate (interleaved with F40/F45/F46
   MSI/GIC diagnostics which stay gated).
3. docs/55 font/cluster implementation (framebuffer is now live).

## python interactive segfault — non-reproducing
Instrumented trace shows no kernel crash; the "hang" is a CPython brute-force
close storm. Real kernel fixes already landed (close_range, NOFILE clamp,
aarch64 TLB flushes, prlimit pid=0). Revisit only if it reproduces.

## First command next session
```
cd /home/nd/oxide2 && git log --oneline -10 && sed -n '/S4a-smp-regress/,+1p' TASKS.md
```
Then: x86 INIT-SIPI via qemu MCP (mcp__qemu__qemu_start arch=x86_64 smp=2,
break at the SIPI vector, single-step the AP through each mode transition).

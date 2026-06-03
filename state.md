# Session hand-off

## Headline
GRUB/Multiboot2 **self-bootstrap boots to `oxide login:`**, replacing
Limine on x86_64. Merged: PR #1514 (the milestone), PR #1515 (login
harness + serial-RX gap doc). On `main` @ `360e9007`. Both arches +
Limine x86 green (no regression). Full analysis in `bootswap.md`.

## What landed this session
- Own 32→64-bit long-mode trampoline (`crates/arch/boot-x86_64/src/mb2.rs`):
  MB2 header + entry tag, page tables (identity + higher-half VMA→LMA +
  HHDM), EFER LME|NXE, boot stack, identity teardown, MB2-info→BootInfo
  (memmap carve, RSDP as HHDM VA, cmdline).
- Linker `AT()` for low LMA (`link/x86_64-kernel.ld`).
- `remap_and_mask_pic()` in `_start_rust` (bootloader-agnostic; the
  8259 PIC fix — IRQ0 was aliasing the #DF vector).
- spec-lint UTF-8 char-boundary panic fixed (`tools/spec-lint`).
- `make smoke-grub` (+ `SMOKE_KEEP_LOG`, `OXIDE_QEMU_DINT`); `cmd_grub`
  defaults to `debug-boot` (mirrors the Limine login path).
- Six implicit Limine→kernel handoff assumptions resolved — see
  `bootswap.md` "implicit contract" + the per-bug table.

## Open work (next, in order)
1. **Serial RX gap on the GRUB path** (`bootswap.md` #5). GRUB reaches
   `oxide login:` + systemd Console Getty, but typed serial input does
   NOT reach the getty. `boot-smoke-login grub` fails; identical
   `boot-smoke-login x86` (Limine) PASSes (alice→PAM→shell→uid=1000).
   Serial TX works, RX doesn't. Chardev + cmdline ruled out. Suspect:
   COM1 RX IRQ (IRQ4) IOAPIC redirection, or RX init state left by
   GRUB's `terminal_input serial`. **A printed prompt ≠ a working
   login — don't claim GRUB login until this PASSes.**
2. Latent (non-GRUB) bug: `debug-all` boot deadlocks in the
   `debug_sched!` smokes — `tick_yield` `sti;hlt` on the device-map-
   smoke-disarmed LAPIC timer. Re-arm a tick for the sched smokes, or
   make `tick_yield` not halt when other tasks are runnable.
3. Extend trampoline HHDM 1 GiB → 4 GiB (robustness; 1 GiB covers ACPI).
4. Multiple GRUB menu entries / boot options; then drop Limine.

## First command next session
```
# Reproduce the serial-RX gap, compare vs Limine:
OXIDE_QEMU_KVM=1 KEEP_LOG=/tmp/grub-login.log ./tools/boot-smoke-login.sh grub 360
# then trace COM1 RX IRQ4 / IOAPIC redirection in the GRUB boot vs
# OXIDE_QEMU_KVM=1 ./tools/boot-smoke-login.sh x86 300   (PASSes)
```

## Notes
- Drive GRUB boots via `make smoke-grub` (setsid harness); direct qemu
  from the Bash tool gets sandbox-killed (exit 144).
- Never `git add` `rootfs-*.img` (shows as M; leave it).
- KVM ~30s to login; TCG several min. cmd_grub rebuilds rootfs+ISO each
  run (~1-2 min) before qemu.

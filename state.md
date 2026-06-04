# Session hand-off

## Headline
Branch `F376-arm-selfbootstrap` (PR #1525). Autonomous loop. **Limine is
fully removed; GRUB-only on both arches; both boot to `oxide login:`
(x86 40s, arm 44s).** Python `exec_prefix` warning fixed. SMP=2 was
Limine-provided → now SMP=1 on both (regression documented + plan in
TASKS.md S4a-smp-regress). Remaining: restore SMP=2 (arm PSCI in
progress), then docs/55 display.

## Landed this session (pushed to F376)
- `bff0575a` python: create `/usr/lib/python3.13/lib-dynload` landmark →
  kills "Could not find platform dependent libraries <exec_prefix>".
- `15724c03` **remove Limine entirely** — limine-proto crate, boot-*/
  limine.rs, all LIMINE_* statics, `.limine_requests` linker sections,
  fallback branches in capture_cmdline/build_boot_info, vendor/limine,
  *.limine.conf, qemu-*-limine Makefile targets, fetch-vendor + boot-smoke
  limine paths. x86=MB2 tags, arm=DTB. Both boot SMP=1.
- `73f3704f` xtask: remove dead Limine image/UEFI-launch plumbing
  (cmd_image/cmd_qemu/build_disk_image/build_iso/*_disk launchers);
  qemu-{x86,arm}-debug repointed to GRUB. image_qemu.rs 876→353.
- `c9e7d096` `dtb::enum_cpus` — DTB /cpus → MPIDR list (hosted-tested),
  foundation for arm PSCI SMP.

## Open work (priority order)
1. **Restore SMP=2 (arm first, then x86) — see TASKS.md S4a-smp-regress.**
   arm UNBLOCKED by F376: SB_LOAD_BASE + `_sb_l1_ident`/`_sb_ttbr1_l0`
   live in BSS. Build phys AP trampoline (mirror `_arm_entry` EL2→EL1 +
   MAIR/TCR/TTBR + SCTLR, jump high, call `ap_main`); `bring_up_aps_arm`
   drives `psci::cpu_on(mpidr, SB_LOAD_BASE+(tramp_va-KB), ctx)`.
   `ap_main` (F326: VBAR+GICR+SGI+runqueue) already correct. x86 needs
   ACPI-MADT enum + INIT-SIPI (no INIT-SIPI in kernel today; Limine did
   it). **Keep both smoke gates SMP=1 until BOTH land** (no lockstep skew).
2. **docs/55 display** (item 5) — in-kernel color-font console (KDFONTOP/
   fbcon, KCF packages). DRAFT spec; advance per spec-before-code.

## Python segfault (interactive REPL) — investigated, non-reproducing
Instrumented arm trace (close_range fixed) shows NO crash; the "hang" is
a CPython brute-force close storm (65535 fds, EBADF each — slow, harmless).
Real kernel fixes already landed earlier (close_range unsigned, NOFILE
clamp, aarch64 TLB flushes on COW/munmap/madvise, prlimit pid=0). No
kernel MM bug found in the clean trace. Revisit only if it reproduces.

## First command next session
```
cd /home/nd/oxide2 && git log --oneline -6 && sed -n '/S4a-smp-regress/p' TASKS.md
```
Then implement the arm PSCI AP trampoline per S4a-smp-regress.

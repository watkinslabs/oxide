# Session hand-off

On **main**, HEALTHY: both arches boot → systemd → `oxide login:` → shell.
Limine fully removed (x86 GRUB-MB2, arm GRUB EFI-stub self-boot).

## This session (all merged)
- **arm SMP=2 FIXED** (#1564): vmm.rs `ATTR1=1<<3`→`1<<2` (AttrIdx bug — user
  pages were mapped Device under self-boot MAIR=0xFF04 → unaligned musl read
  alignment-aborted → PID1 SIGSEGV). arm -smp 1 AND 2 → login. Gate now -smp 2
  both arches (#1566).
- **x86 AP INIT/SIPI bring-up** (#1567): real-mode→long-mode trampoline
  (PAE+LME+**NXE**), MADT INIT/SIPI; AP reaches online (verified online_count→2).
  GATED OFF (`bring_up_aps_x86` returns 0) pending 2 fixes (see fn): (1) reserve
  the low trampoline page from the PMM; (2) AP scheduling integration (runqueue
  +timer+sti wedges boot). Flip `if true { return 0; }` to resume.
- **Distro /etc profiles + skel** (#1569): shells, hosts, environment, motd,
  bash.bashrc, inputrc, profile.d/*.sh (sourced by /etc/profile), skel dotfiles
  + seeded root/alice. Verified live (alice login): motd, prompt, aliases, PATH,
  bracketed-paste. (rootfs_etc.rs split keeps rootfs.rs ≤1000.)

## Open distro/SMP follow-ups
- **Login shell ≠ login shell:** getty/util-linux-login launches the user shell
  as interactive-NON-login → sources ~/.bashrc but NOT /etc/profile, so
  /etc/profile.d env (LANG etc) doesn't reach the shell. Fix login to exec a
  login shell (argv[0]="-bash"), or set LANG in /etc/bash.bashrc as a stopgap.
- x86 SMP integration (the 2 gated fixes above).
- More distro standard items as desired.

## CRITICAL environment rule
Any command containing **`pkill` / `rm -rf` is permission-DENIED** in the
autonomous shell → the WHOLE command aborts (0 output, exit 1). NEVER use them.
Every earlier "qemu/build env-blocked" note was THIS, not a real block.

## Boot + verify (no pkill)
- x86: `nohup python3 /tmp/run_login.py &` → /tmp/oxide-sc.log. Login = alice /
  **swordfish**. Rebuild ISO after kernel change: `xtask grub --arch x86_64
  --features debug-boot --build-only`.
- arm: `cargo run -q -p xtask -- qemu --arch aarch64 --features debug-boot`
  builds target/oxide-aarch64.img (its own qemu launch fails on a stale
  hostfwd:2222 — harmless), then `nohup python3 /tmp/arm_login3.py &` boots it
  directly (socket serial, NO hostfwd) → /tmp/oxide-arm3.log. ~10min TCG.
- qemu-MCP arch=aarch64 boots a STALE grub ISO (oxide-aarch64-grub.iso, never
  rebuilt — xtask grub is x86-only) → INVALID for current-main arm debug. x86
  MCP is fine.

## Merged this session (9 PRs)
#1541/#1542 vendor arm builds 45/46 (uapi-stage.sh; shadow dynamic-pam
+--disable-logind; util-linux arm statx; iputils/pam meson). systemd not rebuilt
(meson build.ninja resource-killed) but unchanged + prebuilt works.
#1543 Phase 14 (VMM advanced) done — mremap/mprotect/madvise/file-mmap + 108 vmm
tests + both arches boot real userspace.
#1544 BUG F — AF_UNIX SCM_CREDENTIALS over socketpairs (send-time cred stamp +
recvmsg_unix_msgpair). "without valid credentials" gone both arches.
#1545 net host-buildability restored → 171 net oracle tests run + pass.
#1546/#1547 + B54 (#1541): PID1 Linux-way boot + session hand-offs.

## Goals — all 3 primary DONE
1. vendor arm cross-builds work (45/46). 2. arm at full lockstep with x86. 3.
distro advanced; both arches boot CLEAN (only benign autofs4 warning).

## Bootloader status (answers "is Limine removed from arm?")
- **YES — removed both arches (#1549).** arm boots OVMF→GRUB→`linux`→our PE
  Image; EFI stub finds DTB+ACPI-RSDP, ExitBootServices, the selfboot.rs MMU
  trampoline builds identity+HHDM+kernel-high tables → kmain. `make qemu-arm`
  = `xtask grub --arch aarch64`. Old `xtask qemu` Limine launchers are dead
  code (not on any live path) — a tidy-up could delete them + vendor/limine.
- **xtask de-Limined (#1551)**: dropped cmd_qemu + build_disk_image + the
  Limine launchers; `xtask image` = `grub --build-only`; accept.py /
  run-smokes.sh / qemu-mcp boot the GRUB ISO; fetch-vendor stopped fetching
  Limine.
- **arm PSCI AP bring-up (#1552)**: kernel now PSCI `CPU_ON`s secondaries
  (MMU-off trampoline `oxide_ap_entry_arm_psci`); CPUs enumerated from DTB
  `/cpus` (-kernel) or ACPI-MADT GICC (GRUB/EFI). Verified `-smp 2`: AP boots
  → `[ap] online aff=1`. **But `-smp 2` full boot is NOT stable**: once the
  load balancer lands a user task on the fresh AP the boot wedges at the
  systemd handoff (AP can't EL0-return a migrated task; per-CPU active-AS +
  arm ctxsw-to-EL0-on-AP incomplete). Gate stays `-smp 1`.

## ARM is slow because TCG, not a bug
- No `/dev/kvm` for aarch64 on an x86 host → QEMU TCG (software JIT), ~30-40x
  vs x86-under-KVM. Steady state is clean (idle=`wfi`, 10 Hz tick). Levers:
  arm SMP=1 (done; SMP=2 wedged UP-kernel + halved single-thread TCG), boot
  without debug-boot (kills the per-byte PL011 MMIO klog flood), and the real
  fix for parallel arm = land PSCI AP bring-up then `-accel tcg,thread=multi`.
- Harness hygiene: kill stray qemus + free :2222 before smoke (overlapping
  qemus from manual boots cause false hostfwd failures). Pre-push hook runs
  `make smoke` both arches; set OXIDE_QEMU_KVM=1 so x86 smoke isn't TCG-slow.

## This-iteration findings (Phase 15 net acceptance, verification-only)
- Net bins present in rootfs: ping nc wget ip ifconfig hostname ss dhcpcd udhcpc
  route tc. /proc/net/dev shows `lo`. (Phase-15 partial evidence; 171 net oracle
  tests pass.)
- **python3 is BROKEN in the rootfs**: "Failed to import encodings module / No
  module named 'encodings'" — real stdlib-path bug (PYTHONHOME/zoneinfo). Worth
  fixing (distro completeness). Polluted the ping test output.
- Loopback ping/TCP acceptance still UNVERIFIED (python noise) — retry with a
  clean nc/ping loopback test.

## Abandoned (do NOT merge)
- **P16-01-uts-ns-fork-inherit** (unmerged): UTS-ns fork inheritance in clone.rs
  REGRESSED the boot (systemd didn't start, 2/2 vs main booting) for reasons
  inspection didn't explain. Abandoned per discipline. If retried: boot-verify
  before/after; investigate Task::new_user ns-field init.

## SMP status — arm SMP=2 FIXED (#1564); x86 SMP unported (next)
**arm -smp 2 now boots → systemd → login (fault=0), same as -smp 1.** ROOT was
an aarch64 page-attr bug (#1564): vmm.rs `ATTR1=1<<3` is descriptor bit 3 =
AttrIdx **2**, but AttrIndx is bits[4:2] so AttrIdx1=1<<2. Self-boot
MAIR=0xFF04 puts Normal-WB at AttrIdx1; with the wrong bit no mapping could
select Normal → every demand-faulted user page was Device → first EL0 unaligned
read (musl memcpy) took a DFSC=0x21 alignment abort → PID1 SIGSEGV. Latent since
the Limine removal (Limine MAIR=0xff had Normal@AttrIdx0, so the wrong const was
harmless). Fix: ATTR1=1<<2. The 5 earlier SMP fixes (#1552 PSCI AP, #1554
per-CPU preempt, #1556 per-CPU SVC, #1557 on_rq guard, #1560 SCTLR.A, #1563
demand-fault tlbi) are all correct + still wanted; none alone unblocked it.
Methodology gotcha that cost time: per-crate debug features differ (syscalls has
`debug-boot`, sched has `debug-sched`, mm-pmm has `debug-irq`) — a
`#[cfg(feature="debug-boot")]` trace in sched/mm-pmm is silently compiled out;
verify traces with `strings <elf> | grep`. Also: editing a low-level crate
(hal-aarch64) can leave a stale cached build — confirm "Compiling hal-aarch64".

**x86 AP INIT/SIPI bring-up: IMPLEMENTED + merged (#1567), GATED OFF.** Replaced
the dead Limine parked-AP path with a real-mode→long-mode trampoline
(global_asm 16→32→64; PAE+LME+**NXE** — kernel PTEs are NX, NXE-off makes bit63
reserved → AP #PF'd reading LAPIC MMIO, the key diagnosis) copied to a low phys
page + identity-mapped in the master PML4, INIT→SIPI→SIPI off the ACPI MADT
(cpu::get). AP reaches long mode + LAPIC enable + online (verified -smp 2:
online_count→2). `bring_up_aps_x86` returns 0 (x86 runs UP, no regression)
pending TWO integration fixes (documented in the fn): (1) TRAMP_PA=0x8000 is not
PMM-reserved → the copy corrupts live RAM; needs a boot-carved low page. (2) AP
scheduling participation (per-CPU runqueue + LAPIC-timer preempt + sti idle)
wedges the BSP boot — x86 AP scheduling integration (arm's equivalent works).
Flip the `if true { return 0; }` gate to resume. lapic::local_apic_id +
busy_wait_us added.

## Discipline
Author = Chris Watkins, no AI/Co-Authored-By trailers. spec-lint clean + both
arches build + boot-verify before every kernel-touching merge. Branch+PR+merge,
never commit to main directly. Never ship a regression (abandon like P16-01).

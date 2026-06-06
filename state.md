# Session hand-off

On **main**, HEALTHY: both arches boot → systemd → `oxide login:` → shell.
**Limine is now fully removed from BOTH arches** (#1549, F378): x86 = GRUB
multiboot2, arm = GRUB EFI-stub `linux` (arm64 Image + PE header, self-boot
MMU trampoline). arm verified to `oxide login:` in 48s (TCG, SMP=1).

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

## Open / next (lowest-risk first)
1. **arm SMP=2 boot-stability** — chain of gaps; AP comes online (#1552) and
   per-CPU preempt state is fixed (#1554, was a global wrong-task-switch race).
   REMAINING (gdb-confirmed at the wedge): a task woken on one CPU but queued
   on another CPU's runqueue is never picked — no cross-CPU **wakeup→resched
   -IPI** is sent, and the AP idle loop (`ap_main`) is pure `wfi` (IRQ-driven
   only). Both CPUs end up `wfi` with PID1 unrunnable → boot wedges at the
   systemd handoff (BSP stuck in elf_arm.rs:291 wfi-loop; AP in smp.rs:306).
   Fix = `try_to_wake_up`-style enqueue-to-target-CPU + resched IPI on the
   wake path (wait_list.rs). Then SMP=2 arm smoke + `-accel tcg,thread=multi`.
   Also note: `spawn_timer_driver`/load-balancer is UNREACHABLE on arm
   (elf_arm::run loops forever before it) — balancer never runs.
   (debug-irq-only `[FAULT] sigsegv` in elf/init-arm at SMP=2 — investigate
   alongside; not in the debug-boot path.)
2. python3 encodings/stdlib path fix (distro; verify-left-able).
3. Phase 15 acceptance: clean loopback nc/ping test → close Phase 15 if green.
4. Phase 16 real namespace isolation (currently id-substrate, F100-F107).
5. smoke_rr arm debug-all hang (debug-only; needs disk+gdb, MCP can't — stale ISO).
6. phases 17–35 — deep feature work, best with user prioritization.

## Discipline
Author = Chris Watkins, no AI/Co-Authored-By trailers. spec-lint clean + both
arches build + boot-verify before every kernel-touching merge. Branch+PR+merge,
never commit to main directly. Never ship a regression (abandon like P16-01).

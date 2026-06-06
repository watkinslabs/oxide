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

## Open / next — arm SMP=2 boot (DEEP; root = unmapped memcpy src)
FIVE SMP fixes landed, all correct + UP-safe, NONE unblock SMP=2:
#1552 PSCI AP bring-up; #1554 per-CPU preempt+ctxsw-staging; #1556 per-CPU
SVC-frame base; #1557 on_rq dedup guard; #1560 clear SCTLR_EL1.A (firmware
left A=1 w/ >1 vCPU → EL0 unaligned access trapped; real latent bug, Linux
always clears A — but NOT the smp2 root).
**ROOT (gdb-pinned):** at -smp 2 PID1(systemd) faults in EL0 right after
readlinkat at systemd `0x40016f88: ldr x6,[x1]` — a 10-byte memcpy
(dst=0x10034b70, src=x1=0x10004322, len=x2=10; caller x30=systemd 0x40063bc4
where x1=x22). **src=0x10004322 is UNMAPPED** (faults regardless of A: DFSC=0x21
align w/ A=1, translation w/ A=0) → systemd's memcpy is handed a WRONG src
pointer. PID1's syscall stream is BYTE-IDENTICAL SMP=1/2 through readlinkat
(19,218,brk→0x10035000 ×2,mmap→0x10035000,readlinkat→5); SMP=1 then does openat,
SMP=2 dies. So the divergence comes from NON-syscall input — leading hypothesis:
vDSO/CNTVCT **time** differs under 2-vCPU TCG (guest-time advances per total
icount), and systemd uses a time value to compute the bad src pointer (no
syscall → invisible in the stream). NEXT: (1) check oxide vvar/vDSO time page
+ whether systemd reads it pre-fault; (2) aarch64-objdump systemd around
0x63bc4/0x16f00 to see how x22 (src) is computed; (3) trace x1's origin.
**KEY: the wedge is the 2-vCPU ENVIRONMENT, not the AP.** Bisected:
**KEY FINDING — the wedge is the 2-vCPU ENVIRONMENT, not the AP.** Bisected:
(a) ap_init no-op, (b) bring_up_aps_psci no-op, (c) cpu-enum capped to 1 — ALL
still wedge at qemu `-smp 2`; `-accel tcg,thread=multi` also wedges; `-smp 1`
boots. So NOT the AP, NOT scheduler, NOT cpu::count(), NOT TCG round-robin.
EVIDENCE (debug-boot, fresh builds — beware STALE ISO: always check ELF mtime
≥ edit time, `xtask grub --build-only` can silently reuse a stale kernel):
- PID1(systemd) syscall stream is BYTE-IDENTICAL SMP=1 vs SMP=2 through
  readlinkat: 19, 218(set_tid_addr→1), 12(brk→0x10035000), 12(brk→0x10037000),
  9(mmap→0x10035000), 267(readlinkat→5). SMP=1 then does 257(openat); SMP=2
  DIES in the EL0 window between readlinkat-return and openat.
- Death = EL0 ALIGNMENT data abort (ESR=0x92000021 EC=0x24 DFSC=0x21,
  FAR=0x10004322). `[noenq tid=c0de0002 st=3]` ⇒ PID1→Zombie (SIGSEGV); the
  "wedge" is just init-dead aftermath. sp_el0 AT the fault is GOOD (0x7fff…) —
  earlier "SP_EL0 poison" reading was WRONG; a non-sp reg holds 0x10004322
  (x19=0x100042d9, a VALID systemd mmap ptr, identical SMP=1/2).
- readlinkat dispatch-exit SVC frame byte-identical SMP=1/2. Syscalls run
  IRQ-MASKED (SVC entry daifset #0xf, no unmask) → no mid-syscall preempt.
- Verified CORRECT: EL0-IRQ save/restore offsets (x0-x18,x29,x30,elr,spsr,
  sp_el0 @ matching slots); oxide_context_switch (x19-x30,sp,tpidr_el0).
So: identical inputs+state, PID1 erets after readlinkat and dies in EL0 only at
-smp 2. Only async difference = an EL0 timer tick in that window. But no-switch
re-pick is transparent and all reg paths check out → mechanism still UNKNOWN.
NEXT EXPERIMENTS (do in order): (1) dump ALL x0-x30 at the EL0 alignment fault
(hook deliver_sigsegv_arm, debug-boot) + `qemu_disasm` the faulting insn at elr
to see which reg = 0x10004322 and what op faults; (2) `its=off` to isolate
ITS/LPI routing with 2 redistributors; (3) diff GIC init (GICR count / IROUTER)
1 vs 2 redistributors. (4) CONFIRMED this session: UP-kernel-smp2 FAULTS
(PID1→Zombie st=3, same readlinkat window) — NOT a stall, so ONE corruption
bug, not lost-IRQ/GIC-routing. boot-and-trace exhausted (~40 boots); right next
tool is a focused gdb hw-watchpoint at the deterministic fault (far=0x10004322,
EL0, right after readlinkat n=6). Gate stays `-smp 1`; distro fully works there.
2. python3 encodings/stdlib path fix (distro; verify-left-able).
3. Phase 15 acceptance: clean loopback nc/ping test → close Phase 15 if green.
4. Phase 16 real namespace isolation (currently id-substrate, F100-F107).
5. smoke_rr arm debug-all hang (debug-only; needs disk+gdb, MCP can't — stale ISO).
6. phases 17–35 — deep feature work, best with user prioritization.

## Discipline
Author = Chris Watkins, no AI/Co-Authored-By trailers. spec-lint clean + both
arches build + boot-verify before every kernel-touching merge. Branch+PR+merge,
never commit to main directly. Never ship a regression (abandon like P16-01).

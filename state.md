# Session hand-off — virtio-blk busy-poll → adaptive spin-then-sleep (B75)

## Branch B75-login-hang-diag → PR #1658 (open). Author Chris Watkins
## <chris@watkinslabs.com>. Counters: F=423 B=75 C=11 D=95.

## HEADLINE: residual x86 SMP=2 freeze ROOT-CAUSED + FIXED. virtio-blk
## completion is no longer a 50M busy-poll that pegs a core; it now spins
## briefly then SLEEPS, woken from the timer tick. Verified BOTH arches.

## What landed this session (UNCOMMITTED — not yet committed/pushed)
- `crates/drivers/drv-virtio-blk/src/modern.rs` (+ Cargo.toml: +hal +sched):
  `submit` restructured → busy-gate (RingShadow.busy) + `do_request` +
  adaptive `wait_for_completion`. Spin `IO_SPIN_BUDGET`=200k (catches the
  fast common completion, zero added latency, boot stays fast) → then park
  on global `BLK_COMPL` WaitList. Magic `50_000_000` → `IO_TIMEOUT_NS`=5s
  wall-clock EIO backstop. inflight spinlock NEVER held across a sleep.
  `can_sleep()` gates parking: excludes `SchedClass::Idle` (boot-smoke reads
  run on the idle task — parking it panics `enqueue: idle`) and pre-sched.
- `crates/kernel/kmain/{Cargo.toml,src/kmain.rs}`: +drv-virtio-blk dep;
  `tick_poll_combined` calls `drv_virtio_blk::modern::tick_wake_completions()`
  (wakes BLK_COMPL every tick — the completion waker; mirrors net rx poll).
- Also touched (pre-existing, NOT mine): 060_exit.rs, server.py, sched-anal.md,
  tty-anal.md. blk-poll-anal.md (??) = this session's full analysis + plan.

## Diagnosis recap (how the wedge was found)
- Wedge = guest busy-loop in TCG (host-gdb `gdb -p <qemu> thread apply all bt`
  showed cpu_exec spinning; main loop healthy). All our guest-side diagnostics
  (serial sysrq, NMI, watchdog) are blind to it: single CPU (aps_started=0, no
  peer to NMI) + the spinning CPU never services the tick. host-gdb (ptrace,
  bypasses BQL/chained-TCG) is the tool — recipe in blk-poll-anal.md.
- Root: blk `submit` busy-polled 50M then EIO; on a slow/lost completion the
  caller retry-storm pegged the core → looks like a hard freeze.

## VERIFY RESULTS (full rebuilds, real boots — no shortcuts)
- x86 KVM/smp1: `oxide login:` @9s.
- x86 tcg+smp2 (the wedge repro): 5/5 boots → login @14-15s. (was ~10% wedge)
- aarch64 (tcg): login, startup 15.6s. Lockstep gate met.
- spec-lint clean; 16 hosted tests pass; modern.rs 598 lines (<1000 cap).

## DEFERRED (noted, NOT done — separate future branches)
- Real per-queue MSI-X completion IRQ: set queue_msix_vector (currently
  COMMENTED OUT at pci-boot/src/virtio_drv.rs:243 → boot log msi_fires=0) +
  register_msi_handler → wake BLK_COMPL. Pure latency optimization; tick-wake
  + adaptive spin are correct + fast without it.
- x86 AP bring-up (smp cpus=0 aps_started=0) so the cross-CPU hard-lockup
  detector has a peer. Separate sizable feature.
- In-guest full-RAM memtest (prior session request): crates/kernel/smoke/src/
  memtest.rs + debug-memtest feature. Not started.

## FIRST TASK next session
1. Decide with user: commit this fix? (nothing committed yet this session).
   `make smoke` already effectively passed (both arches boot to login).
2. If committing: small focused commits — (a) drv-virtio-blk adaptive sleep,
   (b) kmain tick waker. Author Chris Watkins. spec-lint clean already.
3. Then optionally the real MSI-X completion IRQ (latency) as a follow-up.

## ENV QUIRKS (this agent sandbox)
- Foreground qemu / long builds: Bash run_in_background:true + Monitor
  until-loop on the output file (foreground sleep blocked).
- Background bash with an INNER `timeout`/long redirect sometimes gets
  SIGTERM'd early (exit 144) with empty output — just re-run (cargo is
  incremental). Don't redirect to a /tmp file inside; let the task file capture.
- Boot verify: ALWAYS `pkill -9 -f qemu-system-x86; sleep 3` first — a
  lingering qemu (incl. the grub build's own smoke boot) sharing root-x86_64.img
  causes disk-contention false "wedge" (bit me once on the KVM check).
- `xtask grub --arch <a>` BUILDS then BOOTS (prints serial, exits at login) —
  grep its output for `oxide login:` instead of a separate boot step.

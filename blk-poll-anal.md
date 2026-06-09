# virtio-blk busy-poll → sleep/IRQ completion (B75 residual freeze)

## Diagnosis (this session)

x86 SMP=2 tcg ~10% hard freeze at the boot-smoke→PID1 handoff (last serial
line `keymap loaded: US QWERTY`, no `systemd[1]:` ever). Host-gdb on the
wedged QEMU process (`gdb -p <qemu>`, ptrace — bypasses guest BQL):

- vCPU thread 3: spinning in `cpu_exec` = tight **guest busy-loop in JIT'd
  TCG**, core pegged 99%.
- vCPU thread 2: parked in `qemu_wait_io_event` — AP never started
  (`aps_started=0`), only ONE live CPU.
- main loop + iothread: healthy in `ppoll`.

Every guest-side diagnostic is blind to this shape:
- serial sysrq (`<NUL>t/w/c/b`): serviced from the timer-tick UART poll; the
  spinning CPU never returns to the tick path. Confirmed: `<NUL>t` → 0 response.
- liveness watchdog: timer-driven, same dead tick.
- cross-CPU lockup detector + NMI backtrace: need a 2nd CPU; `aps_started=0`.
- gdb `-exec-interrupt`/`info registers`: loop is TCG-chained into a
  self-looping block that never re-checks `cpu->exit_request`.

## Root cause (design)

`crates/drivers/drv-virtio-blk/src/modern.rs:199-206` — every block I/O
**busy-polls `used.idx`** with `spin_loop()`, bounded by magic `50_000_000`,
never sleeping, never yielding. Completions are NOT interrupt-driven (MSI-X
enabled on the function but queue vector masked, `msi_fires=0` in boot log).
On a missed/late completion: ~1s of 100% CPU then `EIO`; callers (exec /
page-fault loading systemd) retry → retry-storm → looks like a permanent hang.

The `used.idx` poll reads guest RAM (HHDM), not MMIO, so it does NOT hold the
QEMU BQL (main loop/iothread stayed alive). Bounded → not literally infinite;
the permanent peg is the EIO-retry loop above it.

## UPDATE — "just sleep" (old Stage 1) is unsafe alone; verified by boot test

Implemented sleep-in-submit, booted: kernel passes ALL pre-scheduler boot smoke
(fallback poll path works) but HANGS RELIABLY at the systemd/PID1 handoff — even
on KVM/smp1 (pre-fix that path reached login in ~7s). vCPU sits in kvm_vcpu_block
(~29%, halted, timer firing): the parked block-read task never resumes. Two
independent blockers:

1. **No completion waker.** The only rouser is the 100ms deadline scanner
   (`tick_wake_expired`), and it didn't resume the task. Reference drivers
   (virtio-input) are ALWAYS woken explicitly by their producer (`wake_one` on
   push). A blk sleeper needs the completion IRQ to wake it — sleeping without
   it regresses.
2. **Lock held across I/O.** ext4 holds `Ext4FileInode::bytes` spinlock across
   `submit_sync` (inode.rs:90 → state.rs:145 → mount.rs:584). Sleeping there
   risks a hard deadlock: single-CPU cooperative sched, a 2nd task spinning on
   that lock never yields the CPU back to the parked holder.

Reverted to known-good busy-poll. The sleep infra I wrote is correct; it just
needs the two prerequisites below first.

## IMPLEMENTED (this session) — adaptive spin-then-sleep, tick-woken

- **A done+verified**: magic `50_000_000` spin count → real 5s monotonic
  deadline. KVM login @9s, no regression.
- **B done (verify-only)**: confirmed the kernel already keeps `submit_sync`
  outside every spinlock (`06§3.6`) — VFS read (ensure_bytes does I/O at
  inode.rs:89 before the :90 lock), pagecache read_page/fsync
  (pagecache.rs:199), ext4 read_byte_range, exec (reads blob first). The
  earlier audit subagent misread inode.rs and was WRONG. No refactor needed.
- **C+D done**: `BlkState::submit` restructured to busy-gate (RingShadow.busy)
  + `do_request` + adaptive `wait_for_completion`: spin `IO_SPIN_BUDGET`
  (200k, catches the fast common completion, zero added latency, keeps boot
  fast) → then park on a global `BLK_COMPL` WaitList. Woken every timer tick
  by `tick_wake_completions()` (added to kmain `tick_poll_combined`, next to
  net rx drain) + promptly by `release_turn`. inflight spinlock never held
  across a sleep. 5s wall-clock deadline = EIO backstop. Pre-scheduler boot
  probes spin (sched_live()==false). Why this beats "just sleep": a pure
  IRQ/tick-only sleep is too slow for the boot read storm; the brief spin
  handles the ~instant completions so only a stuck one pays the sleep.
- **Deferred (latency opt, noted)**: real per-queue MSI-X completion IRQ
  (set queue_msix_vector at virtio_drv.rs:243, register_msi_handler →
  wake BLK_COMPL). tick-wake is correct without it; MSI only lowers slow-path
  latency. boot log msi_fires=0 today because queue_msix_vector is unset.

## Corrected fix order (foundation before wiring)

- **A. Wall-clock bound the busy-poll** (safe, no regression): replace magic
  50M spin count with a monotonic-ns deadline. Ships now.
- **B. ext4/pagecache lock refactor**: no Spinlock held across submit_sync.
- **C. Completion IRQ waker**: unmask q0 MSI-X (spi=81), handler drains used
  ring + wake_one() the compl WaitList.
- **D. Driver sleep** (re-apply the reverted infra), woken by C, lock-safe via B.

## Fix plan (original — superseded by the corrected order above)

**Stage 1 — sleep instead of spin (kills the CPU peg).**
Use existing `WaitList` (`sched/src/live/wait_list.rs`: `park_with_deadline`/
`wake_*`, already used by timer_driver). In `submit()`: publish + kick, register
head id pending, **drop the device lock**, `park_with_deadline()` +
`schedule()`. On wake: reacquire, `pop_used()`, re-check our head; loop until
seen or a REAL time deadline (not a spin count). Pre-scheduler boot probes keep
a small bounded poll as the only remaining spin. Watch: never sleep holding the
device lock (deadlocks the IRQ handler) — follow the wait_list park protocol.

**Stage 2 — completion IRQ (eliminates polling).**
Unmask the q0 MSI-X vector already bound (`spi=81`); register a virtio-blk
completion handler that drains the used ring and `wake_one()`s the matching
sleeper. Legacy-ISR fallback when MSI-X unavailable.

**Stage 3 — cleanup + hosted test.**
Replace `50_000_000` literal with a typed deadline const. Hosted test driving
`submit_sync` against a fake virtqueue with delayed completion → proves
sleep→wake without a boot.

**Stage 4 — diagnostics gap.**
Bring up the x86 AP so the cross-CPU lockup detector has a peer; add the
host-gdb `thread apply all bt` recipe to the diag doc for the chained-TCG case.

## Verify
After Stage 1: re-run tcg+smp2 boot loop (features=debug-boot,debug-watchdog),
confirm the ~10% wedge is gone. Lockstep: `make qemu-arm` must still reach login.

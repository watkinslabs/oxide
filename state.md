# Session hand-off — F425 SMP scheduler: Phase A DONE, Phase B next

## BRANCH: F425-smp-scheduler — Phase A keystone landed + verified
Commit d2c4cec9 `feat(sched): collapse to one switch engine +
finish_task_switch handoff (F425 Phase A)`. PR open (see `gh pr list`).
Design docs at repo root: `smp-arch.md` (authoritative) + `sched-anal.md`.

### What Phase A did (one coordinated change, the keystone)
- ONE switch engine: deleted `schedule_from_irq`, `stage_switch`,
  `tick_pick_next`, `PERCPU_*_CTX_OFF`, the per-CPU ctx staging slots, the
  ~12 gs:/tpidr: staging asm blocks (x86 irq.rs + arm vbar.rs). IRQ-exit
  now calls `oxide_irq_resched_on_exit(saved CS/SPSR)` → the one
  `schedule()` iff returning to user with `should_resched_to_user`
  (VOLUNTARY preempt). Dispatchers (lapic/gic) only `set_need_resched`.
- preempt_count handoff: `schedule()` entry `preempt_disable` (+1); the
  INCOMING task pays −1 in `oxide_finish_task_switch`. First-run tasks
  reach it via scaffold trampoline `oxide_finish_switch_tramp` baked into
  `new_*_with_irq_frame` (both arches).
- **Per-task IRQ-state preservation** (`irq_save_disable`/`irq_restore` in
  schedule()): our syscalls run IF=0 (SFMASK) and take non-irqsave
  process locks (ZOMBIES, registry, wait lists) the timer ISR also takes
  — so a switch MUST preserve each task's own IF. (An early version
  `sti`'d unconditionally in finish → blocked syscall resumed IF=1 →
  timer fired while it held ZOMBIES → `tick_poll`/`reap_orphans` spun on
  ZOMBIES with IRQs masked → timer dead → permanent post-login wedge,
  ~15% of boots. Diagnosed via hypervisor `info registers`: RIP in the
  ZOMBIES cmpxchg spin, RFL IF=0.)

### Verified (both arches, this session)
- 30/30 hypervisor-monitored x86 boots login→shell→id, 0 wedge (was ~15%).
- x86 + arm `make smoke-login-{x86,arm}` (real bash+coreutils fork/exec).
- x86 + arm `make smoke` (SMP=2 boot→login).
- sched hosted: 89 green (+switch_handoff_balances/underflow tests).
- spec-lint clean.

## FIRST TASK next session — Phase B (SMP), per smp-arch.md §B, in order:
1. **B1 rq->lock handoff**: hold `rq.inner` across the switch; the INCOMING
   task releases it in `finish_task_switch` (Linux context_switch→
   finish_lock_switch). Needs a raw unlock on `Spinlock` (acquire + forget
   guard, `raw_unlock` on the incoming stack — UP: always `global().inner`).
   **BLOCKER found this session (attempted, reverted):** holding `rq.inner`
   across the switch makes `enqueue_zombie` (in schedule(), the prev→Zombie
   move) run UNDER `rq.inner` → establishes order `Runqueue(110) → TaskList
   (100)`, which INVERTS the lock-rank order (`sync::decl_lock_class!`:
   TaskList=100 < Runqueue=110) that `reap_orphans`→`enqueue_runnable`
   already follows (TaskList→Runqueue). On SMP that's a deadlock. **Fix
   first:** defer the zombie-enqueue (and any TaskList/ZOMBIES touch) to
   AFTER the rq-lock release — Linux's `finish_task_switch`→`put_task_struct`
   pattern. B1 is NOT a clean isolated step; it pulls in the lock-ordering
   audit. Do that audit (the `Runqueue` lock's full nesting set) before
   landing B1, or it builds on sand.
2. **B2 ttwu**: `try_to_wake_up`→`select_task_rq` (affinity + idlest/
   wake-affine)→enqueue on target rq under its lock→`resched_curr`→
   reschedule IPI (vec 0x41 stub already exists). Add `smp_mb__after_spinlock`.
3. **B3 AP bring-up into the scheduler**: per-CPU init (GS/TPIDR, TSS/idle,
   lapic timer), AP enters its idle→schedule() loop; un-gate `smp_x86.rs`
   (`bring_up_aps_x86` returns 0 today — two integration fixes noted there).
4. **B4 affinity**: per-task cpumask, sched_setaffinity/getaffinity, forced
   migration. 5. **B5 load balance**: sched_domains + periodic/newidle.
Phase C (concurrency hardening) is entangled with B1 already (see blocker):
the timer ISR (`tick_poll_combined`) takes non-irqsave process locks
(ZOMBIES, registry REG) — currently safe only because process holders run
IF=0 (syscalls) / the switch is IRQ-masked. Real SMP needs these irqsave or
deferred to softirq. Each step: hosted test → build both arches → `make
smoke` (SMP=2, BOTH cpus online) → boot→login→shell→fork repeated.

## GOTCHA learned this session (important)
- The hypervisor register dump is the ONLY way to see an IRQs-masked wedge:
  serial-sysrq needs the timer-tick UART poll, which is dead when IRQs are
  masked. Boot qemu directly with `-monitor unix:...`, query `info
  registers` (RIP + RFL IF bit), symbolize with
  `addr2line -e target/x86_64-unknown-oxide-kernel/release/oxide-x86_64`.
- Booting `-cdrom oxide-x86_64-grub.iso` directly does NOT rebuild the ISO;
  rebuild with `xtask grub --arch x86_64 --build-only` or a stale ISO
  silently tests old code.

## ENV QUIRKS
- `pkill ... || true` (set -e aborts the whole line on pkill no-match).
- Multi-line `git commit -m` mangles under the snapshot shell → `-F file`.
- ALWAYS `pkill -9 -f qemu-system; sleep 2-3` before a boot (disk-lock).

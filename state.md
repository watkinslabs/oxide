# Session hand-off — F425 SMP scheduler: Phase A + B1 DONE; B3 next

Merged this session (all green CI): **#1662 Phase A** (one switch engine +
finish_task_switch handoff + the per-task IRQ-state fix), **#1664 B1**
(rq-lock held across switch + deferred reap). Design docs at repo root:
`smp-arch.md` (authoritative) + `sched-anal.md`.

## Done + verified
- **Phase A** (#1662): collapsed the two switch engines into one
  `schedule()`; IRQ-exit → `oxide_irq_resched_on_exit` (saved CS/SPSR) →
  the one schedule() iff returning-to-user (VOLUNTARY). preempt_count
  handoff in `oxide_finish_task_switch` (first-run via scaffold trampoline
  `oxide_finish_switch_tramp`). **Per-task IRQ preservation**
  (`irq_save_disable`/`irq_restore`): syscalls run IF=0 and take
  non-irqsave process locks the timer ISR also takes, so a switch MUST keep
  each task's own IF — an early `sti`-in-finish draft deadlocked the timer
  ISR on ZOMBIES (~15% post-login wedge; found via hypervisor `info
  registers`, RIP in the ZOMBIES cmpxchg spin, IF=0).
- **B1** (#1664): `schedule()` holds `rq.inner` across the switch; the
  INCOMING task releases it in `finish_task_switch` via
  `Spinlock::raw_unlock` (lock + `mem::forget` guard). Zombie-reap deferred
  to the per-CPU `Runqueue::reap_pending` slot, drained AFTER the rq-lock
  release — so ZOMBIES (`TaskList`=100) is never taken under `inner`
  (`Runqueue`=110). Inert on UP; the SMP foundation.
- Both: 30/30 hypervisor-monitored x86 boots login→shell→id (0 wedge),
  x86+arm smoke-login + SMP=2 smoke, sched 89 + sync 16 hosted, spec-lint.

## NEXT: B3 — AP into the scheduler (the gating SMP step; SCOPED this session)
B2 (ttwu+IPI) is inert without B3, so do B3 first. It's a multi-PR infra
effort, NOT a quick integration. `bring_up_aps_x86` (smp_x86.rs) gates the
AP off (`if true { return 0 }`); the AP reaches long mode + LAPIC-online
then `cli;hlt` parks. Two documented blockers + two MORE found this session:
1. **(blocker 1) Reserve TRAMP_PA=0x8000 from the PMM** — the trampoline
   copy corrupts live RAM. Use `pmm ... reserve_early(Pfn(8), 1)` during
   boot (see mm-pmm/src/lib.rs:416). Contained, needed regardless.
2. **Per-CPU TSS (x86)** — `schedule()` does `set_rsp0`/`set_syscall_kstack`
   on switch; the AP scheduling into tasks would clobber the BSP's shared
   TSS RSP0. The likely "wedges the BSP" cause. Need per-CPU TSS+GDT desc
   before the AP can run user tasks. (arm uses sp_el0/TPIDR, check parity.)
3. **Periodic-timer concurrency** — `register_timers` is idempotent (one
   registration) BUT `timer::register_periodic(cgroup::tick, balance_tick)`
   fire on WHICHEVER CPU ticks; an AP arming its LAPIC timer runs them
   concurrently with the BSP → races on shared cgroup/balance state. Make
   them BSP-only (like the lapic dispatch's `is_bsp` tick_poll guard) or
   per-CPU. The lapic dispatch already gates tick_poll/softirq to is_bsp.
4. **AP scheduling participation**: ap_main_x86 must install its per-CPU
   runqueue (`install_default_runqueue` — per-CPU GLOBALS slot, idempotent
   register_timers), set up its per-CPU TSS, arm its LAPIC timer, then enter
   `halt_forever` (idle→schedule loop) INSTEAD of cli;hlt park.
Then **B2**: `try_to_wake_up`→`select_task_rq` (UP=local, SMP=idlest/
affinity)→enqueue on TARGET rq under its lock→`resched_curr`→resched IPI
(vec 0x41 stub exists, `send_resched_ipi`). Only then does the AP get work.
DEV LOOP: qemu MCP (one warm VM, break+inspect BOTH cpus) — NOT cold boots.
Verify: `make smoke` SMP=2 with BOTH cpus actually running tasks; the
hypervisor `info registers -a` dump (per Phase-A method) for any wedge.

## Phase C (entangled): timer ISR (`tick_poll_combined`) takes non-irqsave
process locks (ZOMBIES, registry REG); safe today only because process
holders run IF=0 / the switch is IRQ-masked. Real concurrent SMP needs
these irqsave or deferred to softirq.

## GOTCHAS (carry forward)
- Hypervisor `info registers` is the ONLY way to see an IRQs-masked wedge
  (serial-sysrq needs the timer-tick UART poll, dead when IRQs masked).
  Boot qemu with `-monitor unix:...`, query `info registers` (RIP + RFL IF
  bit 0x200), symbolize: `addr2line -e
  target/x86_64-unknown-oxide-kernel/release/oxide-x86_64 <rip>`.
- Booting `-cdrom oxide-x86_64-grub.iso` directly does NOT rebuild the ISO;
  rebuild with `xtask grub --arch x86_64 --build-only` first or a stale ISO
  silently tests old code.
- `pkill ... || true` (set -e aborts the whole shell line on pkill no-match).
- Multi-line `git commit -m` mangles under the snapshot shell → `-F file`.
- ALWAYS `pkill -9 -f qemu-system; sleep 2-3` before a boot (disk-lock).

# Session hand-off — SMP Phase B in progress (autonomous /loop)

Driving `smp-distro-plan.md` (the ordered SMP→distro plan) as a self-paced
/loop. Merge on local-green (= CI-green for this repo: build both arches +
hosted tests + spec-lint, all run locally; pre-push hook runs SMP=2 smoke).

## Merged this session (SMP scheduler rework, F425 Phase A/B)
- #1670 B2: ttwu wake-time placement (select_task_rq idlest/affinity +
  resched_curr +IPI); WaitList wakes routed through it. UP=local.
- #1671 B3.5: arm AP scheduling participation (AP runs halt_forever schedule
  loop via AP_IDLE_HOOK, not wfi park). arm SVC frame already per-CPU (TPIDR).
- #1662 Phase A: one switch engine + finish_task_switch + per-task IRQ fix
  (found+fixed a ~15% intermittent ZOMBIES-lock deadlock via hypervisor
  info-registers; the fix is per-task IRQ-state save/restore in schedule()).
- #1664 B1: rq-lock held across switch + deferred zombie-reap (lock-order:
  ZOMBIES TaskList=100 reaped AFTER rq-lock release, never under Runqueue=110).
- #1666 B3.1: x86 AP comes ONLINE (reserve TRAMP_PA + un-gate bring-up).
- #1667 B3.2: per-CPU TSS (per-CPU RSP0). Gotcha: install_tss must NOT read
  current_cpu() (runs pre-gs); ltr 0x50 for BSP, install_tss_for_cpu for AP.
- #1668 B3.3: per-CPU syscall slots (gs:[8] kstack + gs:[16] user-RSP);
  BSP seeded after set_percpu_base.
- #1669 B3.4: **AP runs the scheduler** (per-CPU rq+TSS+timer+idle loop,
  not cli;hlt). Root cause of the old "AP wedges BSP": AP was on the SIPI
  trampoline's 4-entry GDT → ltr of per-CPU TSS sel #GP'd → triple fault.
  Fix: `load_kernel_gdt_for_ap` (lgdt the shared kernel GDT) BEFORE GS_BASE
  setup. Verified 5/5 SMP=2 boots login + online=2, AP scheduling.

## NEXT (first unchecked box): B4 affinity
SMP scheduling now WORKS both arches (AP runs migrated tasks via ttwu +
balance.rs load balancer; both honor cpus_allowed). Remaining:
- B4 affinity: sched_setaffinity/getaffinity (slots 203/204) FULL Linux
  semantics (the cpus_allowed mask substrate + ttwu/balancer checks exist;
  wire the syscalls + forced migration if the running task is moved off its
  current cpu). Check current 203/204 impl first.
- B5 load balance: balance.rs exists (busiest→idlest periodic); refine
  (sched_domains, newidle balance, can_migrate cache-hot) for completeness.
- Phase C concurrency hardening; then task.md syscall/distro/vendor-app backlog.


## DEBUG RECIPES (carry forward)
- SMP=2 boot wedge/crash: `OXIDE_SMP=2 ./tools/boot-smoke.sh x86 300`.
  Crash (qemu exits) = triple fault; hypervisor `info registers -a` (boot
  qemu with `-monitor unix:...`, per the diag-hang-mon.py pattern) shows
  RIP/RFLAGS per cpu. `-d int` via OXIDE_QEMU_DINT=<file> logs the exception
  cascade but is finicky under the bash tool — prefer info-registers.
- Stress: /tmp/diag-hang-mon.py (rebuilds ISO, N hypervisor-monitored boots,
  dumps regs on hang). ~12 boots is enough for deterministic changes.
- `addr2line -e target/x86_64-unknown-oxide-kernel/release/oxide-x86_64 <rip>`.
- ENV: `pkill ... || true` STILL aborts compound lines under the snapshot
  shell — run boot/make as a BARE single command, no pkill prefix. Multi-line
  git commit → `-F file`. Stale qemu holds the disk lock → flaky boots; the
  smp2rep.sh / boot-smoke retry covers it.

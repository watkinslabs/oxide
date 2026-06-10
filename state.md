# Session hand-off — SMP Phase B in progress (autonomous /loop)

Driving `smp-distro-plan.md` (the ordered SMP→distro plan) as a self-paced
/loop. Merge on local-green (= CI-green for this repo: build both arches +
hosted tests + spec-lint, all run locally; pre-push hook runs SMP=2 smoke).

## Merged this session (SMP scheduler rework, F425 Phase A/B)
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

## NEXT (first unchecked box in smp-distro-plan.md): B2 ttwu + resched IPI
The AP now runs its idle loop but has NO runnable tasks (its rq has only
idle). B2 makes it a migration target:
- `try_to_wake_up(task)` → `select_task_rq(task)` (UP=local; SMP=idlest /
  wake-affine, honoring affinity) → enqueue on the TARGET cpu's rq under its
  lock → `resched_curr(rq)` → if remote, `send_resched_ipi(target_apic)`
  (vec 0x41 stub + lapic::send_resched_ipi already exist). Add the
  smp_mb__after_spinlock wake barrier. Route the wake sites (WaitList,
  zombies, futex, ipc, tty) through it.
- Verify: a task actually runs on the AP at SMP=2 (e.g. spawn N spinners,
  observe work on online=2; or instrument a per-cpu run counter). Use the
  hypervisor info-registers -a to confirm both cpus executing user/kernel.
- Then B3.5 (arm AP scheduling parity via PSCI), B4 affinity, B5 balance,
  Phase C concurrency hardening. Then the task.md syscall/distro/vendor-app
  backlog (see smp-distro-plan.md sections B/C/D).

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

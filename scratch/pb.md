# Handoff — hard-IRQ lock discipline campaign

`main` @ `7721355b1`. Plan of record: **`scratch/skizm.md`** (inventory,
tracking table with Branch + Status, validation gates). This doc is state and
the next action only.

---

## What changed this session

Five PRs merged, all boot-verified on `main` after merge:

| Step | Item | PR |
|---|---|---|
| 2a | `CONFIG_DEBUG_PREEMPT` subset — `[PREEMPT-LEAK]` detectors + `preempt_count`/`resched` in the sysrq per-CPU dump | #3928 |
| 3a | `spin_lock_bh` — `sync::BhGate` + `Spinlock::lock_bh` + `sched::bh::SchedBh` | #3929 |
| 3b | loadavg folds per-CPU `nr_running` instead of walking the task list in hard IRQ | #3930 |
| 3c | timekeeper `CLOCK` behind a seqlock — builds `sync::SeqLock` | #3931 |
| 3d | wake list as a lock-free `llist` — no lock, no alloc, safe from the ISR | #3932 |

Two Linux primitives the inventory listed as missing now exist: `spin_lock_bh`
and `seqlock`.

---

## The x86 gate was misdiagnosed — this is the important part

`pb.md` (previous) said "a lost wakeup, same class as the ARM `smp=2` hang" and
told the next session to fix it before starting Step 3. **Both halves were
wrong.** Evidence is in `skizm.md` 3.0b and 3.0c; summary:

- Baseline, clean `main`, 3 sequential boots, `OXIDE_SMOKE_ATTEMPTS=1`:
  **2/3 pass**, at 94 s and 372 s. A 4x spread between two *passes*.
- The failing boot: **44.7 s of system-wide silence**, and the ELF-interpreter
  read that began at 5.512 s completes at 50.281 s. systemd then logs
  `Failed to fork off sandboxing environment ...: Protocol error` →
  `Freezing execution.` The terminal "nothing runnable" state is **systemd
  having frozen itself**, not a kernel wedge.
- Largest stalls per boot: 12 s (fast pass), 44.7 s (fail), 129 s + 292 s (slow
  pass). The stalls dominate every boot.
- sysrq at the stall: both CPUs ticking, `nr_run 0`, all tasks `S`,
  `ktimers`/`ksoftirqd` holding live deadlines ~90 ms out — timer machinery
  healthy.
- With `C216` landed, the dump now prints the count: **`preempt_count = 0`** on
  the idle CPU with `resched=1`, and neither `[PREEMPT-LEAK]` detector fired.
  No leaked count. That eliminates the mechanism Step 2 was built to fix.

So there is no separate "2b" bug to fix first. `switch.rs:62-71` states the
real dependency in the tree's own words: the kernel is safe from the hard-IRQ
lock-sharing deadlock **only because syscalls run `IF=0`**, since the
process-context locks the timer ISR also takes are held without irqsave. Every
such lock must become irqsave / BH-safe / lockless before that global masking
can be lifted — which is Steps 3a–3f. Fixing the locks *is* the fix.

`sync::IrqGate::save_enable` already exists for running a bounded IRQs-on
section inside an `IF=0` context, and its documented precondition is "caller
must hold no plain lock that IRQ/softirq context also takes". That is precisely
what this campaign establishes.

---

## FIRST TASK NEXT SESSION

**Step 3f — make the allocator lock IRQ-safe.** It needs a design decision
before any code, written up in `skizm.md` §5. Linux allows
`kmalloc(GFP_ATOMIC)` from IRQ context because the allocator lock is IRQ-safe;
ours is a plain `Spinlock<AllocState, KMalloc>`. `lock_irqsave` needs an
`IrqGate`, and `crates/shared/kalloc` depends only on `sync`, so it cannot
reach `hal-*` without inverting the layer order. Options and costs are tabled in
`skizm.md`; the recommendation is a `cfg`-selected `sync::ArchIrq` mirroring
`timekeeper::platform::Irq` (one owner, no indirect call on the `kmalloc` hot
path). **Decide, then write.**

Then 3e (bridge STP — `spin_lock_bh` now exists for it), then 4a.

### Also open

- **`F704-preempt-count-per-task` is pushed and unmerged.** Still a correct fix
  for 3.2, but per 3.0c it is not the x86 stall and no longer gates anything.
  It conflicts with current `main` (`metadata/index.md`, `scratch/skizm.md`).
  Rebase/merge-in `main` and land it on its own merit.
- `Tty` never appeared in lockdep output, so `skizm.md` 3.1 #6/#7 remain **[P]**
  — re-check with console input concurrent with a tty syscall *before* building
  the workqueue (4a) they justify.

---

## Process notes that held up

- **A single boot proves nothing.** Report clean/total. The failure is ~1-in-3
  at one attempt; `boot-smoke.sh` defaults to 3 attempts, which is why the
  normal gate usually passes and hid this.
- **`boot-smoke.sh` deletes a failed attempt's log** — always pass
  `SMOKE_KEEP_LOG_DIR=<dir>`.
- The pre-push hook **skips boot-smoke for PR-branch pushes**, so pushes are
  fast; boot-verify after each merge to `main` instead.
- Measuring the largest gap between consecutive klog timestamps turns "the boot
  was slow" into a number, with no extra boots. Script pattern in
  `skizm.md` 3.0b.

# Deferred-work architecture — where we diverge from Linux, and the plan

Nothing applied. `main` untouched. Companion audit: `hardirq-context-plan.md`.

## Linux's model — four contexts, strictly ordered by what they may do

| Context | May sleep | May allocate | May take a plain lock shared with process ctx | What runs there |
|---|---|---|---|---|
| Hard IRQ (top half) | no | no | **no** | ack, EOI, record, raise softirq, wake |
| Softirq / tasklet | no | `GFP_ATOMIC` only | no | net RX/TX, block completion, timers, RCU |
| **Workqueue (`kworker`)** | **yes** | **yes** | yes | everything that can block |
| Dedicated kthread | yes | yes | yes | kswapd, jbd2, long-running loops |

Linux also splits timers deliberately: `timer_list` fires in softirq TIMER
context (must not sleep); `delayed_work` fires on a workqueue (may sleep). You
pick based on whether the callback can block.

## What we actually have

| Linux | Ours | State |
|---|---|---|
| hard-IRQ top half | `gic/dispatch.rs`, `lapic/dispatch.rs` | exists — but loaded with process-context work |
| softirq, 10 vectors | `crates/kernel/softirq`, 7 slots | exists — but handlers **allocate** |
| per-CPU `ksoftirqd` | `ksoftirqd` | exists |
| **workqueue / `kworker`** | **only a Linux-module ABI shim, `modules/src/linux_time/work.rs`** | **MISSING for the core kernel** |
| `timer_list` (softirq, no sleep) | — | conflated with the below |
| `delayed_work` (workqueue, may sleep) | `timer::register_periodic` -> `ktimers` | `ktimers` does BOTH jobs |
| kswapd / subsystem kthreads | `kswapd0`, `netns_reaper`, `fw_loader` | exists |
| `preempt_count` **per-task** | **per-CPU** | **broken — see Phase 0** |

## The problem, stated once

We have the threads. We do not have the **contract**. Nothing declares which
context a piece of work runs in, nothing enforces it, and the counter that is
supposed to track it (`preempt_count`) is per-CPU instead of per-task, so it
lies as soon as a task parks mid-drain. Work therefore drifts into whichever
layer was convenient at the time, and each drift is a latent deadlock.

Masked interrupts in kernel context hid all of it. The IRQs-on migration —
correct, and required — removed the mask, so the drifts became live hangs. That
is why this keeps happening and why it feels like whack-a-mole: we are finding
them one boot at a time instead of enforcing the rule.

## The plan, in dependency order

### Phase 0 — make context accounting truthful
`preempt_count` moves per-task (Linux `thread_info`), saved and restored across
`switch`. Until this lands, `in_interrupt()` / `in_atomic()` / `might_sleep()`
are all unreliable and every guard built on them is decorative.
Fixes on its own: the leaked HARDIRQ/SOFTIRQ field that pins a CPU dead — the
CPU stops draining softirqs and stops rescheduling, permanently.

### Phase 1 — build the missing primitive: a real workqueue
Per-CPU `kworker` pool with `queue_work` / `queue_delayed_work`, in `sched`.
Promote the module-ABI shim to call it rather than owning its own thread.
**This is the actual hole in the architecture.** Every piece of work that can
block currently has nowhere correct to go, so it ends up in softirq or the tick.

### Phase 2 — enforce the contract
- `might_sleep()` that fires at the offending call site (Linux's).
- Lockdep-lite: lock classes already exist (`TtyClass`, `TaskListClass`, ...).
  Tag each class IRQ-safe or not, and assert on take from the wrong context.
  Turns "find it by booting for six hours" into an immediate named failure.

### Phase 3 — route every existing piece of work to its correct layer, by rule

| Work | Today | Correct layer | Note |
|---|---|---|---|
| `loadavg::tick` | hard IRQ (takes `REG`) | hard IRQ, **lock-free** | Linux keeps `calc_load_tasks` as an atomic updated on enqueue/dequeue; interim: ktimers |
| `bridge_stp_tick` | hard IRQ (2 locks) | workqueue / timer | seconds-scale, no urgency |
| `fbcon tick_drain` | hard IRQ (tty locks) | workqueue | decide cadence explicitly |
| block completion | softirq, **allocates** | softirq, allocation-free | preallocated / intrusive list |
| reclaim, swap, zram | reachable from softirq | never from softirq | `GFP_ATOMIC` gate, already written up in `watermark.rs` |
| `vblank_tick`, `vvar::publish`, watchdog | hard IRQ | hard IRQ | atomics only — correct as-is |

### Phase 4 — lock audit
Every `Spinlock` whose data an IRQ handler touches becomes irqsave at **every**
site, or the IRQ-side work moves out. Phase 2's lockdep-lite finds these
automatically instead of by inspection.

### Phase 5 — frame de-bloat
135 functions >= 1 KB, worst 37 KB, vs Linux's ~1 KB. Ranked list already in
`scratch/arm-smp2-fault.md`.

## Sequencing note

Phase 3's loadavg + bridge-STP move is the tactical fix that unblocks the
current `-smp 2` hang, and it is parked in `git stash` ready to go. It is worth
landing first because it is zero/low risk and gets the boot moving.

But it is a symptom fix. Phases 0-2 are what stop the next one, and Phase 0 is
both the cheapest and the one that makes everything after it enforceable.

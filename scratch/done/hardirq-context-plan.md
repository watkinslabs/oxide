# Hard-IRQ context correctness — audit + plan

Nothing here is applied. `main` is untouched; the proposed diff is parked in
`git stash` ("PROPOSED-loadavg-bridgestp-to-ktimers").

## The rule being violated

`docs/06§3.1`: a hard-IRQ handler must never spin on a plain (non-irqsave) lock
that process context also holds. Doing so deadlocks the CPU the moment the tick
preempts a holder.

This was always true, but until the IRQs-on migration the kernel ran with
interrupts MASKED during syscalls and faults, so the tick could not land on a
kernel-context lock holder. Enabling IRQs in kernel context — correct, and the
whole point of that work — made every existing violation reachable. B1344
already moved PSI, `reap_orphans` and `tick_wake_expired` out for this reason;
the sweep was incomplete.

## Inventory — everything in `tick_poll_combined` (`kmain/src/kmain/hooks.rs`)

ONE hook, called from BOTH dispatchers (`gic/dispatch.rs` aarch64,
`lapic/dispatch.rs` x86_64), so every row applies to both arches.

| # | Call | What it takes | Verdict |
|---|---|---|---|
| 1 | `sched::loadavg::tick` | `registry.rs:140` **`REG.lock()`** — plain `Spinlock<Vec<(u32, Weak<Task>)>>` — then `retain` + `upgrade()` over EVERY task | **MUST MOVE — the live deadlock** |
| 2 | `fbcon::kernel::tick_drain` | `ANSWERBACK[i].lock()` plain `Spinlock<_, TtyClass>`, then a sink callback into the tty input path | **MUST MOVE** |
| 3 | `fbdev::vblank_tick` | one `fetch_add` | safe — keep |
| 4 | `sched::live::timer_driver::tick_poll_ktimers` | atomics + `WAKE_LISTS[cpu].lock()` (per-CPU) | keep — but verify `schedule()` masks IRQs around `wake_list_drain` |
| 5 | `net::global_stack().bridge_stp_tick` | `bridge_stp.rs:123` `state.lock()` + `ingress.rs:273` `inner.lock()` — both held plain by netlink/ioctl/socket callers | **MUST MOVE** |
| 6 | `sched::diag::watchdog_tick` | atomics only; the dump path takes `REG`, but only once the CPU is already wedged | keep |
| 7 | `syscalls::vvar::publish` | atomics | safe — keep |

`REG` is exactly the lock the comment at `hooks.rs:32` names as unsafe to take
from the tick. `loadavg::tick` calls it three lines ABOVE that comment.

## Why this is the observed hang

CPU 1 enters `execve`, takes `REG`. CPU 0's timer IRQ fires (~160 us cadence),
calls `loadavg::tick` -> `live_counts()` -> `REG.lock()`, and spins with IRQs
off. CPU 0 is now stuck inside the dispatcher between `irq_enter` and
`irq_exit` — permanently `hardirq=1`, so it can never drain softirqs nor
reschedule. Any completion routed to CPU 0 is lost; CPU 1 waits on it forever.

Matches every measurement: `preempt_count=0x00010000` on an otherwise idle
CPU 0, CPU 1 in `execve`, and none of the three leak detectors firing (CPU 0
never reaches idle or `schedule()`).

Single-CPU survives because the tick must land inside a short critical section
on the SAME cpu; two CPUs turn a narrow window into a near-certainty.

## Blast radius of moving 1, 2, 5 to `timer::register_periodic` (ktimers, process context)

* Timer registry is a `Vec` (`timer/src/lib.rs:60`) — no capacity limit, no
  overflow risk from added entries.
* ktimers is one kthread; the tick hook is BSP-only, so coverage is equivalent.
* Mechanism is already proven in-tree by PSI / `reap_orphans` /
  `tick_wake_expired`.
* Fixes both arches at once — one shared hook.

| Move | Latency change | Risk |
|---|---|---|
| `loadavg::tick` | self-gates to a **5 s** resample; tick rate vs 100 ms is invisible to it. `/proc/loadavg` unchanged | **none** |
| `bridge_stp_tick` | STP timers are seconds-scale (hello ~2 s, forward delay ~15 s); 1 s cadence is ample, and with no bridges configured it is a no-op | **low** |
| `fbcon tick_drain` | terminal answerback replies go from ~tick to ~100 ms | **low-moderate — the only one worth debating.** Affects an app that sends a terminal query and blocks on the reply. Give it its own 10 ms periodic, or raise a softirq from the tick and drain there |

## What this does NOT fix

Moving three calls stops the current deadlock. It does not make the kernel
Linux-shaped. These are the divergences measured this session, each of which has
already produced a real bug:

1. **`preempt_count` is per-CPU; Linux keeps it per-task in `thread_info`.**
   Anything parking inside `do_softirq` leaks the softirq field to the next task
   on that CPU, which then never drains softirqs and eventually underflows.
   Fix: save/restore it across the switch, or make it a `Task` field.
2. **Softirq handlers allocate** (`drv-virtio-blk` collects completions into a
   `Vec`; virtio-net snapshots a `Vec`). Linux's never do. Allocation can enter
   direct reclaim -> swap -> zram -> park. Fix: preallocated/intrusive lists.
   This also unblocks applying `GFP_ATOMIC` parity to `watermark.rs`, which is
   written up there but not applied because it regressed x86 without this.
3. **Stack frames up to 37 KB** (zstd/zram chain), vs ~1 KB in Linux; 135
   functions >= 1 KB. Ranked targets in `scratch/arm-smp2-fault.md`.
4. **Plain locks shared between IRQ and process context, generally.** Items 1/2/5
   above are the instances found by following the tick. The systematic answer is
   Linux's: any lock whose data an IRQ handler touches becomes `irqsave` at
   EVERY site, or the IRQ side moves out. Needs a repo-wide audit of `Spinlock`
   declarations vs their callers.

## Proposed sequencing

1. **Now, small:** move 1 and 5 to ktimers (zero / low risk). Leave `fbcon` on
   the tick for the moment and decide its cadence separately.
2. **Verify:** both arches build; arm `smp=1` and x86 gates stay green; arm
   `smp=2` gets past the `execve` wedge.
3. **Then, structurally:** `preempt_count` per-task (item 1) — it is the next
   thing that can wedge a CPU, and it is stack-independent.
4. **Then:** allocation-free softirq handlers (item 2), which unlocks the
   `GFP_ATOMIC` gate.
5. **Then:** the lock-class audit (item 4) and frame de-bloat (item 3).

For `loadavg` specifically the eventual Linux-correct form is a lock-free
counter: Linux keeps `calc_load_tasks` as an atomic updated on enqueue/dequeue,
so its tick reads it without any lock and legitimately stays in the tick.
Moving to ktimers is the safe interim, not the destination.

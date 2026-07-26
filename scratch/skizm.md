# skizm — deferred work & lock discipline: inventory, plan, validation

**Why this doc exists.** Six earlier versions of this diagnosis were wrong, each
because the culprit was found by reading a few call paths and generalising. This
version is built from a checked inventory, tags every claim, and states how the
plan gets validated *before* work starts.

Tags: **[V]** validated (I read the cited line in this tree) · **[P]** proposed
(design, unverified) · **[X]** tried and rejected, with reason.

Nothing is applied. `main` is untouched. One stashed diff is to be **discarded**
(§5, Step 1 note).

---

## 1. The one rule everything follows

Not "kthread or not". The question is:

> **Does this work need to SLEEP?**
>
> - **Yes** → it must run in a workqueue or kthread. *Only here does "move it" apply.*
> - **No** → **leave it where it is** and fix the *lock*: irqsave, BH-safe,
>   lockless, or remove the lock access entirely.

Linux uses the second far more often. Applied to the violations found so far,
**5 of 7 need no thread move at all**.

---

## 2. Inventory — Linux primitive vs what we have  **[V]**

| Linux | Ours | Status |
|---|---|---|
| hard-IRQ handler | `gic/dispatch.rs`, `lapic/dispatch.rs` | exists, **overloaded with process-context work** |
| softirq (10 vectors) | `crates/kernel/softirq`, 7 slots | exists |
| per-CPU `ksoftirqd` | `ksoftirqd` | exists |
| wait queues | `WaitList` (`live/wait_list.rs`) — **the only irqsave lock in the tree** | exists |
| RCU | `sync::rcu` | exists |
| per-CPU vars | `Pcpu<T>` | exists |
| `spin_lock_irqsave` | `lock_irqsave::<I>()` | exists — **36 sites, nearly all inside `slab`/`sync`** |
| `local_bh_disable/enable` | `sched/src/bh.rs` | exists |
| `preempt_disable/enable` | `sched/src/preempt.rs` | exists |
| **`spin_lock_bh`** | **none in core.** Module ABI exports it but `raw_spin_lock_bh` is literally `raw_spin_lock(l)` (`modules/src/linux_sync.rs:152`) — **it does not disable BH at all** | **MISSING + the shim is a lie** |
| **sleeping mutex** | **none anywhere** | **MISSING** |
| semaphore / rwsem | module ABI shim only (`linux_sync.rs:30`) | missing in core |
| **workqueue + `kworker`** | module ABI shim only (`modules/src/linux_time/work.rs:56`) | **MISSING in core** |
| `delayed_work` | module shim only | missing in core |
| `tasklet` | module shim only | missing in core |
| `timer_list` (softirq TIMER) | module shim only; core's `timer::register_periodic` runs on **ktimers, process context** | **wrong context** |
| `hrtimer` | module shim only | missing in core |
| kthread API | `spawn_kernel_thread(tid, name, entry, arg)` only — no `kthread_stop`/`should_stop`/`park` | minimal |
| NAPI | module shim only; drivers raise a softirq slot directly | different, but the ISR side is correct |
| threaded IRQ handlers | module shim only | missing in core |
| `completion` | ad-hoc `wait_for_completion` in block | not a general primitive |
| **lockdep** | **none** | **MISSING** |
| **`might_sleep` / `DEBUG_ATOMIC_SLEEP`** | **none** | **MISSING** |
| `preempt_count` **per-task** | **per-CPU**, not saved/restored across switch | **WRONG** |
| `CONFIG_FRAME_WARN` | none | missing |

### Two findings that reshape the plan

**(a) There is no sleeping mutex in the entire core kernel.** Every lock is a
spinlock. A subsystem that needs to hold a lock across a sleep cannot express
it, so it either busy-waits or holds a spinlock while doing I/O. This is
upstream of a lot of what we have been chasing.

**(b) `spin_lock_bh` does not exist**, so §1's "make the process side BH-safe"
— Linux's most common fix, and the one I recommended for bridge STP — **is not
currently expressible.** It has to be built first. `local_bh_disable/enable`
already exist in `bh.rs`, so it is a thin wrapper, but it is not there today.

---

## 3. What is broken

### 3.0 Step 0 output — the enumerated list  **[V]** (`F702`, arm boot)

lockdep reported 5 classes. It reproduced **every** lock-side row I had
validated by hand, which is the gate that makes this list trustworthy — and
found one I had missed entirely.

| Class | rank | Is it | Hand-audit found it? |
|---|---|---|---|
| `TaskList` | 100 | `REG` — 3.1 #1, #2 | yes |
| `Timer` | 5 | `CLOCK` — 3.1 #3 | yes |
| `Runqueue` | 110 | `WAKE_LISTS` — 3.1 #4 | yes |
| `Socket` | 140 | bridge state / socket — 3.1 #5 | yes |
| **`KMalloc`** | 200 | **the allocator lock** | **NO — missed** |

**`KMalloc` is new and serious:** the heap lock is taken in hard-IRQ context
*and* plain in process context, so any allocation from an ISR can deadlock
against one in a syscall. It is also consistent with the softirq handlers that
allocate (`drv-virtio-blk` collecting completions into a `Vec`). Fix belongs
with those: make the ISR/softirq side allocation-free, or the lock irqsave.

`Tty` did **not** appear in this boot — 3.1 #6/#7 stay **[P]**. They need
console input concurrent with a tty syscall to trigger; re-run with serial input
before committing to the workqueue work they justify.

### 3.1 Violations of `06§3.1` found by hand (subsumed by 3.0)

| # | Site | Sleep? | Correct Linux fix | Move? |
|---|---|---|---|---|
| 1 | ~~`timer_owner` → `registry::lookup` → `REG.lock()` + O(N) scan, **every tick, both paths**~~ **FIXED (F703)** — slots moved to `ThreadGroup`; both hard-IRQ paths are lookup-free, pinned by a test | no | done | no |
| 2 | `loadavg::tick` → `live_counts` → `REG` walk + `Arc`/`Weak` drops (kalloc free in hard IRQ); gated 0.2 Hz so **latent** **[V]** `loadavg.rs:35,50`, `registry.rs:138` | no | lock-free per-CPU atomic (`calc_load_tasks`), **stays in the tick** | no |
| 3 | `vvar::publish` → `timekeeper::realtime_ns` → `CLOCK.lock()` **[V]** `vvar.rs:79`, `timekeeper/state.rs:6,12` | no | seqcount read (`tk_core.seq`) | no |
| 4 | `tick_poll_ktimers` → `wake_list_push` → `WAKE_LISTS` lock + `Vec::push` allocates **[V]** `timer_driver.rs:81`, `ttwu.rs:30,36` | no | lockless list (`llist_add`) | no |
| 5 | `bridge_stp_tick` → bridge `state.lock()` every tick + iface `inner.lock()` + alloc + virtio TX **[V]** `bridge_stp.rs:122,165`, `ingress.rs:270` | no | softirq timer + **`spin_lock_bh`** on the process side — *needs 2(b) built first* | no |
| 6 | UART RX ISR → `TtyStruct::receive_from_driver` → plain `tty.inner`; `^C` → `REG` **[P]** | **yes** | `spin_lock_irqsave` on the port; ldisc push → **workqueue** | **yes** |
| 7 | fbcon answerback slow path → same tty tree **[P]** (fast-path `PENDING` early-out is **[V]**) | **yes** | **workqueue** (`flush_to_ldisc`) | **yes** |

### 3.2 Structural defects

- **`preempt_count` is per-CPU and not switched** **[V]** `preempt.rs:29`. A task
  parking inside `do_softirq` leaks the softirq field to the next task on that
  CPU; that CPU then never drains softirqs, never reschedules, and the eventual
  `preempt_count_sub` underflows. Measured: idle CPU at `preempt_count=0x10000`.
  Makes `in_interrupt()`/`in_atomic()`/`might_sleep()` unreliable — every guard
  built on them is decorative until fixed.
- **Tick policy duplicated in two hand-written dispatchers** **[V]**.
  `deadline::rearm()` is outside the `is_bsp` block on x86, inside it on aarch64;
  `is_bsp` is even computed differently in each. Since `program()` writes *this
  CPU's own* timer hardware **[V]** `deadline.rs:3-19`, the work is per-CPU by
  construction — **aarch64 is the wrong one**, and its APs never program a
  one-shot deadline for their running task.
- **Timekeeping CPU hardcoded to the boot CPU.** Linux's `tick_do_timer_cpu`
  moves on hotplug (`tick_handover_do_timer`); ours cannot, so global timekeeping
  would stop if the BSP were offlined.
- **Stale comment** **[V]** `gic/dispatch.rs:142` calls `charge_current_tick`
  "IRQ-context: atomics only." It reaches `REG`.

---

## 4. What must be built

| # | Primitive | Why it is needed | Linux reference |
|---|---|---|---|
| A | **`spin_lock_bh`** | 3.1 #5 and the general "make the process side safe" fix are inexpressible without it. Thin wrapper over existing `local_bh_disable/enable` | `spin_lock_bh` |
| B | **Workqueue + per-CPU `kworker`** | 3.1 #6/#7 need somewhere sleepable to defer to; today blocking work has nowhere correct to go | `workqueue.c`, `queue_work` |
| C | **Sleeping mutex** | no way to hold a lock across a sleep; forces busy-wait or spinlock-during-I/O | `struct mutex` |
| D | **lockdep (irq-state subset)** | the enumerator that replaces my hand-sampling — see Step 0 | `CONFIG_PROVE_LOCKING` |
| E | **`might_sleep()`** | catches sleep-in-atomic at the offending line; inert until 3.2's `preempt_count` fix | `CONFIG_DEBUG_ATOMIC_SLEEP` |
| F | **`ClockEvent` HAL trait + one generic tick** | removes the duplicated-policy class permanently | `clock_event_device`, `tick_do_timer_cpu` |
| G | **Frame-size build gate** | 135 functions ≥1 KB, worst 37 KB; would have caught the stack-overflow class pre-boot | `CONFIG_FRAME_WARN` |
| H | *(later)* `timer_list` in softirq, `delayed_work`, `tasklet`, threaded IRQs, `kthread_stop/park` | full parity; not needed for the current defects | — |

---

## 5. Plan

Ordered so each step makes the next verifiable.

### Tracking

| Step | Item | Branch | Status |
|---|---|---|---|
| 0 | lockdep irq-state subset (D) | `F702-lockdep-irq-state` | **DONE** — gate passed |
| 1 | process-wide POSIX timers → `ThreadGroup` (Linux `signal_struct`) | `F703-group-leader-direct` | **DONE** |
| 1b | `wall_timer_interrupt`'s *conditional* `registry::lookup` in hard IRQ (only when a wall timer is due) — carry `Weak<ThreadGroup>` in `WallEntry` | — | TODO |
| 2 | `preempt_count` per-task | — | TODO |
| 3a | build `spin_lock_bh` (A) | — | TODO |
| 3b | fix 3.1 #2 loadavg — lock-free in tick | — | TODO |
| 3c | fix 3.1 #3 `vvar` — seqcount | — | TODO |
| 3d | fix 3.1 #4 `WAKE_LISTS` — lockless | — | TODO |
| 3e | fix 3.1 #5 bridge STP — softirq + `_bh` | — | TODO |
| 4a | build workqueue + `kworker` (B) | — | TODO |
| 4b | fix 3.1 #6 UART RX ISR | — | TODO |
| 4c | fix 3.1 #7 fbcon answerback | — | TODO |
| 5 | one generic tick + `ClockEvent` (F) | — | TODO |
| 6 | frame-size build gate (G) | — | TODO |
| 7 | sleeping mutex (C), then H | — | TODO |


**Step 0 — lockdep irq-state subset (D).** Instrument `Spinlock::lock` /
`lock_irqsave` under a `debug-lockdep` feature; the lock class is already a type
parameter so `type_name::<C>()` names it free. Record the acquisition context;
flag any class seen in hard-IRQ context *and* in process context without
irqsave. Boot both arches, `smp=1` and `smp=2`.
**[X] Static analysis cannot do this** — `Spinlock::lock` is `#[inline]` and
absent from the binary: zero `bl` to any lock symbol across 50,602 call sites in
the aarch64 ELF. Linux's lockdep is runtime for the same reason.
*Gate: it must reproduce every **[V]** row in 3.1 before it is trusted.*

**Step 1 — `->group_leader` direct handle.** Kills 3.1 #1, the only constant
offender. `Task` already carries `Arc<ThreadGroup>` **[V]** `task.rs:64` to hang
a `Weak<Task>` leader on (`Weak` avoids the leader↔member cycle). Rewrite
`timer_owner` to read it; delete the `registry::lookup` call.
*Note: the diff parked in `git stash` moves `loadavg`+bridge STP to ktimers.
**Discard it** — by §1 both are wrong for Linux fidelity (2 belongs in the tick
lock-free; 5 belongs in softirq with `spin_lock_bh`).*

**Step 2 — `preempt_count` per-task.** Fixes 3.2; makes Step 0 exact rather than
over-reporting, and makes E meaningful.

**Step 3 — build A (`spin_lock_bh`), then fix 3.1 #2/#3/#4/#5** — all
lock-side fixes, no thread moves.

**Step 4 — build B (workqueue), then fix 3.1 #6/#7** — the only two that
genuinely move.

**Step 5 — build F (one generic tick).** Kills 3.2's duplicated-policy class and
the arch asymmetry permanently; make the timekeeping CPU a variable.

**Step 6 — build G (frame gate), then de-bloat** per `arch-smp2-fault.md`.

**Step 7 — C (mutex), then H** as subsystems need them.

---

## 6. How the plan gets validated *before* implementation

1. **Step 0 must reproduce the known list.** Every **[V]** row in 3.1 must appear
   in the tracker's output. A miss means the tool is wrong and is fixed before
   anything depends on it. *This is the check that stops a seventh wrong plan* —
   it tests my analysis against the machine's.
2. **Step 0's output must be a superset of 3.1.** If it finds violations not
   listed, the hand-audit was incomplete (expected) and the plan's fix list is
   extended before Step 1 starts.
3. **Each [P] row gets read before it is acted on.** #6 and #7 drive the entire
   workqueue effort (B) and I have not read those lines myself. If they are
   wrong, B may not be needed yet.
4. **Each built primitive needs a test that fails today.** `spin_lock_bh`: a
   hosted test showing a softirq re-entering a BH-protected section. Workqueue:
   a work item that sleeps and completes. Mutex: a holder sleeping while another
   task blocks.
5. **Both arches, both `smp` counts, every step.** Per the repo's lockstep rule.

---

## 7. Honest scope

**Will be equivalent to Linux:** `->group_leader`; per-task `preempt_count`;
irqsave/`_bh` on ISR-shared locks; lockless wake lists; seqcount timekeeping;
clockevents split with arch supplying only hardware; frame-size gate;
softirq-raise-only ISRs (already correct).

**Deliberate subsets — must be labelled as such in the code:** workqueue (no
concurrency management, rescuers, or NUMA pools); lockdep (irq-state usage bits
only — no lock ordering or deadlock-cycle detection); mutex (no priority
inheritance or adaptive spinning).

**Still divergent afterwards, tracked separately:** the scheduler is
voluntary-preempt — `oxide_irq_resched_on_exit` switches only on user return —
so a task blocked in the kernel holds its CPU, where Linux under
`CONFIG_PREEMPT` is fully preemptible. This is why deferring softirqs to
`ksoftirqd` deadlocked when tried. Larger work; nothing above depends on it.

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
| seqlock / seqcount | `sync::SeqLock` (`F707`) — lock-free reader, irqsave writer | exists |
| per-CPU vars | `Pcpu<T>` | exists |
| `spin_lock_irqsave` | `lock_irqsave::<I>()` | exists — **36 sites, nearly all inside `slab`/`sync`** |
| `local_bh_disable/enable` | `sched/src/bh.rs` | exists |
| `preempt_disable/enable` | `sched/src/preempt.rs` | exists |
| **`spin_lock_bh`** | `Spinlock::lock_bh::<B: BhGate>()` + `sched::bh::SchedBh` (`F705`); module ABI honest as of `B1400` | exists |
| **sleeping mutex** | `sched::live::Mutex` (`F711`) — gate + `WaitList`; no PI, no adaptive spinning | exists (labelled subset) |
| semaphore / rwsem | module ABI shim only (`linux_sync.rs:30`) | missing in core |
| **workqueue + `kworker`** | `sched::live::workqueue` (`F712`) — bounded per-CPU ring, irqsave, one pinned `kworker` per CPU | exists (labelled subset) |
| `delayed_work` | `sched::live::delayed_work` (`F717`) — deadline table walked by the tick, due items handed to the workqueue | exists |
| `tasklet` | `sched::live::tasklet` (`F717`) — `Slot::Tasklet` softirq drain, never-on-two-CPUs claim | exists |
| `timer_list` (softirq TIMER) | `sched::live::timer_list` (`F718`) — softirq-context, non-sleeping, drained from `Slot::Tasklet`; `register_periodic` stays on ktimers for callbacks that SLEEP | exists (both contexts, deliberately) |
| `hrtimer` | module shim only | missing in core |
| kthread API | `spawn_kernel_thread` + `kthread::{should_stop, stop, park, unpark, park_if_requested}` (`F717`) | exists |
| NAPI | module shim only; drivers raise a softirq slot directly | different, but the ISR side is correct |
| threaded IRQ handlers | `sched::live::threaded_irq` (`F718`) — hard half in the ISR, threaded half on a kworker | exists |
| `completion` | ad-hoc `wait_for_completion` in block | not a general primitive |
| **lockdep** | **none** | **MISSING** |
| **`might_sleep` / `DEBUG_ATOMIC_SLEEP`** | **none** | **MISSING** |
| `preempt_count` **per-task** | **per-CPU**, not saved/restored across switch | **WRONG** |
| `CONFIG_FRAME_WARN` | none | missing |

### Two findings that reshape the plan

**(a) There was no sleeping mutex in the entire core kernel.** Every lock was a
spinlock, so a subsystem needing to hold a lock across a sleep could not express
it and either busy-waited or held a spinlock while doing I/O — upstream of a lot
of what we have been chasing. Built in `F711` as `sched::live::Mutex`: a
`MutexGate` spinlock deciding "take it or enqueue", a `WaitList` for the
sleepers, and the enqueue performed UNDER the gate so an unlocker cannot slip
between "saw it locked" and "became visible as a waiter" (the same ordering
`inode_wait` uses). Subset per §7: no priority inheritance, no adaptive
spinning.

**(b) `spin_lock_bh` did not exist**, so §1's "make the process side BH-safe"
— Linux's most common fix, and the one recommended for bridge STP — **was not
expressible.** Built in `F705` as `Spinlock::lock_bh::<B: BhGate>()`: `BhGate`
mirrors the existing `IrqGate` (generic, monomorphized, no `dyn`) because the
bottom-half count lives in `sched`'s `preempt_count`, above `sync` in the dep
order. The guard releases the lock *before* `local_bh_enable`, so the inline
drain may take that same lock — pinned by a test.

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

### 3.0i lockdep never checked the softirq pair at all  **[V]**

Step 3e-bh assumed a sweep of ~83 `Socket` call sites. There are only **9**
`Socket`-class lock declarations, and the real problem was upstream: lockdep
reported `used-in-hardirq AND taken-plain-in-process` and nothing else. Linux
keeps BOTH pairs (`LOCK_USED_IN_HARDIRQ` and `LOCK_USED_IN_SOFTIRQ` against the
matching ENABLED bits); ours only had the first, so **the entire
`spin_lock_bh` violation class was invisible** — the class Step 3a built the
primitive for.

Adding the softirq check found two violations immediately, and only two:

| Lock | softirq side | plain-process side | Fix |
|---|---|---|---|
| `rq.inner` (`Runqueue`) | ttwu / wake enqueue | `halt_forever` -> `newidle_balance` -> `pop_one_cfs` | `lock_irqsave` |
| `PACKET_REGISTRY` (`Socket`) | `packet::deliver` (RX softirq) | `register_packet`, ns teardown, membership detach, `packet_ring_timer` on ktimers | `lock_bh` |

The runqueue one is worth recording: `lock_bh` was the obvious fix and it HUNG
THE BOOT. `balance_once` holds two runqueue locks at once, and the inner guard's
`local_bh_enable` drains softirqs while the outer lock is still held — and those
softirqs take a runqueue lock. Masking interrupts excludes softirqs with no
drain on release, which is exactly why Linux's rq lock is
`raw_spin_lock_irqsave`. `lock_bh` is right only where the guard nests nothing,
as at the four `PACKET_REGISTRY` sites.

After both: a boot with the softirq check active emits **zero** lockdep reports.

### 3.0h Acquisition-IP provenance closed the last two  **[V]**

The lock ADDRESS said which lock; it did not say where the two conflicting
acquisitions were, and with a class shared by ~180 locks the name did not
either. `C219` records one call site per side (the same frame-pointer/x30 trick
`kalloc::caller` uses) and prints both, so `addr2line -i` names them:

| Report | hardirq site | plain-process site | Verdict |
|---|---|---|---|
| `KMalloc` | allocation from an ISR | `KAlloc::init` <- `kmain::early::init:16` | **false positive** — boot-time init runs single-CPU with IRQs masked, but lockdep's IRQ-state hook is installed later (`early.rs:251`), so it was filed as plain-process |
| `TaskList` | `Task::comm` -> `exe_path` (the sysrq dump) | `Task::with_exe_path` <- `WaitList::park_with_deadline` | **real** |

Both fixed: lockdep records nothing before its hooks exist (guessing at
unobservable state is what produced the false report), and the sysrq dump reads
`exe_path`/`comm` non-blocking — the diagnostic yields rather than forcing every
process-side access to become irqsave to serve it.

**Result: a forced sysrq boot (`SMOKE_TIMEOUT=70`) now emits ZERO lockdep
reports.** The enumeration is clean on the timeout path as well as the normal
one.

### 3.0g lockdep was keyed per CLASS, and the classes are catch-alls  **[V]**

The residual `TaskList` / `KMalloc` reports were not the sysrq dump (3g's
theory). `LockClass` doubles as lockdep's identity, and the classes are shared:
**`TaskList` (rank 100) is used by ~180 files** and `KMalloc` (200) by five
unrelated locks (kalloc, `rcu::STATE`, vmalloc, and two `mm-vmm` maps). Judged
per class, "some rank-100 lock ran in hard IRQ" plus "some OTHER rank-100 lock
was taken plainly in process" combined into a violation report for two locks
that never interact.

Linux gives every lock its own `lock_class_key`. `B1406` keys the usage table on
the lock's ADDRESS instead, which is the same identity without touching 180 call
sites, and prints it. The two reports that survive are now genuine single-lock
findings with addresses — see Step 3h.

### 3.0b The x86 "hang" is a ~45 s I/O stall, not a lost wakeup  **[V]**

`pb.md` recorded this as "a lost wakeup, same class as the ARM `smp=2` hang".
Measured on `main` @ `81f8707bc`, 3 sequential boots, `OXIDE_SMOKE_ATTEMPTS=1`,
`SMOKE_TIMEOUT=420`: **2/3 pass** — 94 s, FAIL, 372 s. A 4x spread between the
two passes is itself the finding. The failing log says something different.

| Evidence | Reading |
|---|---|
| System-wide log silence `5.538` → `50.251` (**44.7 s**), no task of any kind | one stall, not a wedge |
| `elf-load: interp` for tid 4123 begins `5.512`, `interp read ok` lands `50.281` | the stall IS the ELF-interpreter read (`ld-linux`) |
| systemd PID1 then logs `Failed to fork off sandboxing environment ...: Protocol error` → `Freezing execution.` | userspace gave up *because of* the stall |
| sysrq at `374 s`: both CPUs ticking (age 9 ms / 0 ms), `nr_run 0`, every task `S` | not a spin deadlock — both CPUs are alive |
| `ktimers`/`ksoftirqd` carry `wake_dl_ns` ~90 ms in the future | the timer + deadline machinery is healthy throughout |

So the terminal "everything asleep, nothing runnable" state is **systemd having
frozen itself**, which is a consequence, not the fault. There is no lost wakeup
to find. The fault is a multi-tens-of-seconds stall while blocked on block I/O
in the exec path, and it is the same class as the recorded boot-slowness root
cause: the kernel waits for an IRQ-driven completion with `IF=0`.

Stall magnitude per boot, measured as the largest gap between consecutive klog
timestamps — the stalls dominate every boot, and the failure is simply the run
where one exceeded systemd's tolerance:

| Boot | Wall | Largest stalls |
|---|---|---|
| run1 PASS | 94 s | 12.2 s |
| run2 FAIL | 429 s | **44.7 s** (then systemd froze) |
| run3 PASS | 372 s | **129 s**, **292 s** |

This is not a separate blocker sitting in front of the campaign — it is the
campaign's payoff. `switch.rs:62-71` states the dependency outright: the kernel
is safe from the hard-IRQ lock-sharing deadlock *only because* syscalls run
`IF=0`, since the process-context locks the timer ISR also takes are held
**without irqsave**. Every such lock must become irqsave/BH-safe (Steps 3a–3f)
before that global masking can be lifted. Fixing the locks is what removes the
stall; there is no separate 2b fix that precedes them.

### 3.0d Step 0 re-run confirms 3b/3c/3d landed  **[V]**

Same lockdep instrument, x86 `smp=2`, on `main` @ `7721355b1` (after 3a-3d).
The report is now two classes, not five:

```
[LOCKDEP] class=Socket  rank=140 used-in-hardirq AND taken-plain-in-process (also softirq)
[LOCKDEP] class=KMalloc rank=200 used-in-hardirq AND taken-plain-in-process (also softirq)
```

`TaskList` (100), `Timer` (5) and `Runqueue` (110) are **gone** — exactly the
three that 3b, 3c and 3d fixed. This is the machine confirming the fixes rather
than the author, which is the whole point of Step 0 (§6 rule 1).

Remaining: `Socket` is 3e, `KMalloc` is 3f.

### 3.0c No `preempt_count` leak is involved  **[V]**

`C216`'s per-CPU dump, on a stalled x86 attempt (`verify2`, boot reached
`basic.target` on the retry):

```
  CPU  age_ms  last-tid  last-syscall  nr_run  preempt_count  resched
    1    0     65536     none          0       0x0000000000000000   1
```

`preempt_count = 0` on the idle CPU, with `need_resched` set and nothing
runnable. So the HARDIRQ/SOFTIRQ field is **not** leaked, and neither
`[PREEMPT-LEAK]` detector fired. That eliminates the mechanism `pb.md`
attributed the hang to and that Step 2 was built to fix — Step 2 remains a real
correctness fix for 3.2, but it is not this bug and does not gate anything.

Combined with 3.0b: both CPUs alive, count clean, timer machinery healthy,
nothing runnable because everything is genuinely waiting on I/O.

### 3.0e 3.1 #6 read at last — it does NOT sleep, so B is not needed for it **[V]**

§6 rule 3 says each **[P]** row must be read before it is acted on, and warns
that #6/#7 "drive the entire workqueue effort (B) and I have not read those
lines myself. If they are wrong, B may not be needed yet." #6 has now been
read. It was wrong.

The path, from the UART RX ISR:

| Step | Site |
|---|---|
| `TtyStruct::receive_from_driver` | `core/tty.rs:98` — `self.inner.lock()`, **plain** |
| → `NTty::receive_buf` | `ldisc/n_tty/ops.rs:7` |
| → `handle_isig` (`^C`/`^\`/`^Z`) | `ldisc/n_tty/state.rs:256` |
| → `drv.signal_fg_pgrp(sig)` | `state.rs:280` |
| → `KernelFgSignal::raise` | `console/static_console.rs:45` |
| → `registry::tasks_in_pgrp(pgrp)` | takes `REG.lock()` **and allocates a `Vec`** |

So the violations are real and worse than recorded — `tty.inner` is taken
plainly in hard IRQ *and* in process context (`read`, `core/tty.rs:126`), and
the `^C` path additionally takes `REG` plainly and allocates, all in the ISR.

**But nothing on it sleeps.** The signal is delivered by `fetch_or` on
`sigpending`; the ECHOCTL echo is a `driver_write` into a UART FIFO. By §1's
one rule — "Does this work need to SLEEP? No → leave it where it is and fix the
*lock*" — #6 is a lock fix, not a thread move:

- `tty.inner` → `lock_irqsave` (it is shared with a hard-IRQ handler)
- the `^C` path → `REG` access that neither spins nor allocates in the ISR
  (Linux takes `tasklist_lock` with `read_lock_irqsave` on this exact path)

The row's "Sleep? **yes** → workqueue" was the unvalidated assumption behind
Step 4a. #7 must be read the same way before B is built for it either.

### 3.0f 3.1 #7 read too — same answer, so Step 4a has no remaining justification **[V]**

`fbcon::answerback`'s own module header states the design: queue under the
per-VT lock, drain later into the tty input ring. The drain is
`answerback::drain()`, reached from `fbcon::kernel::tick_drain()`, called by
`tick_poll_combined` — **the hard-IRQ timer tick** — and its sink is
`TtyStruct::receive_from_driver`, i.e. the same plain `tty.inner` as #6.

So #7 is the same violation as #6 by a second route, and by the same reading it
does not sleep: the sink sets `sigpending` bits and writes a FIFO.

**Both rows that justified building a workqueue turn out to be lock fixes.**
Step 4a (workqueue + `kworker`) therefore has no remaining consumer in this
plan. It stays on the list as genuine Linux parity work (§2 lists it MISSING),
but it is no longer a prerequisite for anything, and 4b/4c collapse into one
change: make `tty.inner` irqsave.

That single change fixes both, because both reach it from hard IRQ. Note
`fbcon` already raises `Slot::FbconFlush` from `vt_write`, so the softirq
plumbing to move the drain off the tick as well already exists if wanted.

### 3.1 Violations of `06§3.1` found by hand (subsumed by 3.0)

| # | Site | Sleep? | Correct Linux fix | Move? |
|---|---|---|---|---|
| 1 | ~~`timer_owner` → `registry::lookup` → `REG.lock()` + O(N) scan, **every tick, both paths**~~ **FIXED (F703)** — slots moved to `ThreadGroup`; both hard-IRQ paths are lookup-free, pinned by a test | no | done | no |
| 2 | ~~`loadavg::tick` → `live_counts` → `REG` walk + `Arc`/`Weak` drops (kalloc free in hard IRQ)~~ **FIXED (F706)** — folds `rq.nr_running` per CPU (Linux `calc_load_account_active`); no lock, no alloc, stays in the tick | no | done | no |
| 3 | ~~`vvar::publish` → `timekeeper::realtime_ns` → `CLOCK.lock()`~~ **FIXED (F707)** — `CLOCK` is a `sync::SeqLock` (Linux `tk_core.seq`); readers acquire nothing, writers are irqsave | no | done | no |
| 4 | ~~`tick_poll_ktimers` → `wake_list_push` → `WAKE_LISTS` lock + `Vec::push` allocates~~ **FIXED (F708)** — `AtomicPtr` llist chained through `Task::wake_next`; push is one cmpxchg, drain one xchg, no lock and no alloc | no | done | no |
| 5 | `bridge_stp_tick` → bridge `state.lock()` every tick + iface `inner.lock()` + alloc + virtio TX **[V]** — hard-IRQ half **FIXED (F709)** via `Slot::BridgeStp`; process-side `_bh` sweep is 3e-bh | no | softirq timer (done) + `spin_lock_bh` on the process side (3e-bh) | no |
| 6 | UART RX ISR → `TtyStruct::receive_from_driver` → plain `tty.inner`; `^C` → `REG` **+ `Vec` alloc** **[V]** (3.0e) | **no** — nothing on the path sleeps | `spin_lock_irqsave` on the port; `^C` path must not spin/alloc in the ISR | **no** |
| 7 | fbcon answerback drain → `tick_drain` in the hard-IRQ tick → same plain `tty.inner` **[V]** (3.0f) | **no** | same fix as #6 — `lock_irqsave` on the port | **no** |

### 3.2 Structural defects

- ~~**`preempt_count` is per-CPU and not switched**~~ **FIXED (F704)** `preempt.rs:29`. A task
  parking inside `do_softirq` leaks the softirq field to the next task on that
  CPU; that CPU then never drains softirqs, never reschedules, and the eventual
  `preempt_count_sub` underflows. Measured: idle CPU at `preempt_count=0x10000`.
  Makes `in_interrupt()`/`in_atomic()`/`might_sleep()` unreliable — every guard
  built on them is decorative until fixed.
- ~~**Tick policy duplicated in two hand-written dispatchers**~~ **FIXED (B1402)**.
  Sharper than first recorded: `rearm()` did TWO jobs with different CPU
  scoping — `program()` writes *this CPU's own* timer hardware (per-CPU), while
  `wall_timer_interrupt()` services one global queue behind one try-lock. So
  **both** dispatchers were wrong, in opposite directions: x86 ran the combined
  call on every CPU (global half done N times), aarch64 ran it only on the BSP
  (APs never armed a deadline at all). Split into `rearm_local()` (every CPU)
  and `service_wall_timers()` (timekeeping CPU), after which the two
  dispatchers state the same policy. `is_bsp` is still computed differently in
  each — folding that into a `ClockEvent` trait remains Step 5.
- ~~**Timekeeping CPU hardcoded to the boot CPU.**~~ **FIXED (F715)** — `arch_irq::tick::TIMEKEEPER_CPU` is a variable with `set_timekeeper_cpu` (Linux `tick_handover_do_timer`), and both dispatchers ask `is_timekeeper()` in ONE id space (logical). aarch64 was comparing a LOGICAL id against `boot_cpu_id()` (a HARDWARE id) and was correct only because its boot MPIDR is 0.
- ~~**Stale comment** `gic/dispatch.rs:142` calls `charge_current_tick`
  "IRQ-context: atomics only."~~ **FIXED (B1401)** — F703 already removed the
  `REG` reach; the comment was corrected on both dispatchers and on
  `cpustat::charge_current_tick` itself, which is hard-IRQ safe because nothing
  on the path blocks (the timer backend is a non-blocking `try_lock`), not
  because it is atomics-only.

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
| G | **Frame-size build gate** — built (`C218`): `tools/frame-size-gate.py`, ratcheted per arch. Found **9 x86 frames ≥8 KiB, worst 21,624 B** — larger than the whole 16 KiB kernel stack. aarch64 is clean (worst 4160) | would have caught the stack-overflow class pre-boot | `CONFIG_FRAME_WARN` |
| H | *(later)* `timer_list` in softirq, `delayed_work`, `tasklet`, threaded IRQs, `kthread_stop/park` | full parity; not needed for the current defects | — |

---

## 5. Plan

Ordered so each step makes the next verifiable.

### Tracking

One item = one branch = one lane. A row is only **DONE** once its PR is merged
to `main`; a branch that exists but is unmerged is **IN PROGRESS** and must be
continued, never duplicated by a second lane.

| Step | Item | Branch | Status |
|---|---|---|---|
| 0 | lockdep irq-state subset (D) | `F702-lockdep-irq-state` | **DONE** #3925 — gate passed |
| 1 | process-wide POSIX timers → `ThreadGroup` (Linux `signal_struct`) | `F703-group-leader-direct` | **DONE** #3926 |
| 2 | `preempt_count` per-task (3.2) | `F704-preempt-count-per-task` | **DONE** #3938 — per 3.0c NOT the x86 stall, but 3.2 is a real defect |
| 2a | `CONFIG_DEBUG_PREEMPT` subset — the instrument 2/2b are diagnosed with | `C216-preempt-leak-diag` | **DONE** #3928 |
| 2b | x86 intermittent stall — **rediagnosed 3.0b**: a ~45 s block-I/O stall in the exec path, not a lost wakeup; systemd's self-freeze is the consequence. Fixed by 3a-3f, not separately | — | FOLDED INTO 3a-3f |
| 1b | `wall_timer_interrupt`'s *conditional* `registry::lookup` in hard IRQ — `WallEntry` now carries a `Weak<Task>` | `F713-wallentry-weak` | **IN PROGRESS** |
| 3a | build `spin_lock_bh` (A) | `F705-spin-lock-bh` | **DONE** #3929 |
| 3b | fix 3.1 #2 loadavg — lock-free in tick | `F706-loadavg-lockfree` | **DONE** #3930 |
| 3c | fix 3.1 #3 `vvar` — seqcount (builds `sync::SeqLock`) | `F707-vvar-seqcount` | **DONE** #3931 |
| 3d | fix 3.1 #4 `WAKE_LISTS` — lockless | `F708-wake-list-lockless` | **DONE** #3932 |
| 3e | fix 3.1 #5 bridge STP — move off the hard-IRQ tick into a softirq | `F709-stp-softirq` | **DONE** #3934 |
| 3e-bh | softirq-vs-process violations — lockdep extended to CHECK them, then both it found were fixed (`rq.inner` on the idle-loop balancer, `PACKET_REGISTRY` on four process paths) | `F716-socket-bh` | **IN PROGRESS** |
| 3f | 3.0 `KMalloc` — allocator already masks IRQs across alloc/dealloc; lockdep was false-reporting it. Fixed by teaching lockdep to read ACTUAL IRQ state | `C217-lockdep-irq-state-hook` | **DONE** #3937 |
| 6a | burn down the baselined x86 frames >=8 KiB | `B1405-reaper-frame` | **DONE for all OUR code** — 9 -> 6, and every remaining one is vendored `structured_zstd`. Root cause was `TxQueue.jobs` inline in `IngressGate`: `Arc::new` builds its value on the stack, so every gate construction reserved ~9.9 KiB |
| 6b | the 6 remaining are vendored `structured_zstd` (worst 21,624 B) — zram codec | `F719-zstd-in-tree`, `F720-zstd-zram` | **DONE** — neither bounded nor excepted: the vendored codec is REPLACED by an in-tree one (§3.0j). `#[inline(never)]` was tried first and did not split a single one of the six. x86 is now 0 frames >= 8 KiB and the baseline file is empty |
| 3g | ~~sysrq dump~~ **misattributed — the real cause was lockdep CLASS conflation**, fixed by keying per lock instance | `B1406-lock-class-identity` | **IN PROGRESS** |
| 3h | both surviving reports resolved: `KMalloc` was a pre-hook false positive, `TaskList` was `Task::exe_path` read from the serial ISR | `C219-lockdep-ip` | **IN PROGRESS** |
| 4a | build workqueue + `kworker` (B) | `F712-workqueue` | **IN PROGRESS** — built as parity (3.0e/3.0f removed its original consumers); it is now the only place sleepable work can be deferred to from a non-sleepable context |
| 4b | fix 3.1 #6 **and #7** — `lock_irqsave` on `tty.inner` | `F710-tty-irqsave` | **DONE** #3942 |
| 4d | `^C` path: `REG` taken plainly in the RX ISR — whole `TaskList` class made irqsave | `B1403-tasklist-irqsave` | **DONE** #3944 |
| 4e | `tty` write no longer holds the irqsave port lock across the UART busy-wait — the ldisc buffers under the lock and a detached sink transmits after release | `F714-tty-tx-detached` | **IN PROGRESS** |

| 5a | `deadline::rearm` split — per-CPU arm vs global wall-timer service; both dispatchers agreed | `B1402-deadline-rearm-split` | **DONE** #3939 |
| 5 | one generic tick owner + timekeeping CPU as a variable (`arch_irq::tick`, Linux `tick_do_timer_cpu`) | `F715-clockevent` | **IN PROGRESS** |
| 6 | frame-size build gate (G) | `C218-frame-size-gate` | **IN PROGRESS** |
| 7 | sleeping mutex (C) | `F711-sleeping-mutex` | **IN PROGRESS** |
| 8 | H — `delayed_work`, `tasklet`, `kthread_stop`/`park` | `F717-h-parity` | **IN PROGRESS** |
| 8b | H remainder — softirq `timer_list` + threaded IRQs | `F718-timer-softirq` | **IN PROGRESS** |
| 9 | module-ABI `_bh`/`_irq`/`_irqsave` lock variants were all bare `raw_spin_lock` | `B1400-module-abi-lock-variants` | **DONE** #3935 |
| 10 | stale comment `gic/dispatch.rs:142` — `charge_current_tick` is not "atomics only" | `B1401-tick-charge-comment` | **DONE** #3936 |

**3f: the allocator is already IRQ-safe; the residual report comes from the
diagnostic itself.**  **[V]**

Two separate findings, both from reading the code and then re-running lockdep.

*The allocator is correct.* `KAlloc` masks interrupts itself across the whole
alloc/dealloc op: `irq_save`/`irq_restore` fn-pointer hooks, installed at boot
in `kmain::early.rs:177` for both arches, with `alloc`/`dealloc` opening on
`self.irq_off()` before taking the hole-list lock. The install site's own
comment gives the reason: "must disable IRQs across the whole op — else the
plain hole-list Spinlock deadlocks (ISR spins on the mainline-held lock)". The
only `inner.lock()` sites not under `irq_off` are `init` (boot, single-CPU,
IRQs already off) and the `debug-heappoison`/`debug-dealloc-diag` validators.

*Our lockdep could not see that.* It inferred IRQ state from **which lock method
was called** — `lock()` = plain, `lock_irqsave()` = gated — so a caller that
masks IRQs by other means and then calls plain `lock()` was necessarily
misreported. Linux's lockdep has no such gap: it asks the hardware
(`raw_irqs_disabled()`). `C217` gives ours the same question via an installed
`set_irq_state_hook` reading RFLAGS.IF / DAIF.I, consulted alongside `irqsafe`.
Conservative by construction — a null hook reports "enabled", which can only
over-report.

*What is left is real, but is the diagnostic's own doing.* Measured, x86
`smp=2`, two attempts: the **passing** boot emits **zero** lockdep reports. The
two that appear at all are in the timed-out attempt, both stamped `367.8 s`,
i.e. inside the sysrq dump that only runs after a timeout: the dump executes in the serial hard-IRQ handler and
there walks the task registry (`TaskList`) and allocates (`KMalloc`). That is a
genuine `06§3.1` violation, but it is confined to the timeout path and it is
the debug tooling wedging its own diagnosis. Tracked as Step 3g rather than
left implicit in a "KMalloc" row that suggests the allocator is at fault.

**Consequence for the plan: Step 0's list was over-reporting, so any class must
be checked against actual IRQ state before being believed.** The three already
fixed (3b/3c/3d) were all genuine — each took a plain lock with IRQs live — so
no earlier work is invalidated.

**3f was missing from the original plan.** §6 rule 2 requires Step 0's output to
extend the fix list before dependent work starts, and `KMalloc` — the one
violation the hand audit missed — never got a row. Added.


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

## 3.0j zstd: in-tree codec replaces the vendored crate

`crates/shared/zstd` (`F719`) + zram switched over (`F720`). Closes Step 6b,
which `#[inline(never)]` could not: the six remaining >8 KiB kernel stack frames
were all inside vendored zstd, and marking them out-of-line did not split them.

| Piece | Where | Note |
|---|---|---|
| Decoder | complete | raw/RLE/Huffman literals, all 4 FSE modes, 4-stream, repeat offsets, multi-block, skippable, XXH64, dictionaries |
| Encoder | conforming subset | raw literals + predefined-FSE sequences, RLE for uniform pages, raw-block fallback so a page never expands |
| Dictionaries | both forms | raw content and RFC 8878 §5 serialized, as zram's `algorithm_params dict=` requires |
| Conformance | both directions | our frames through the reference decoder, its frames at all 5 levels through ours, every length 0..=4096 |

Bugs the conformance test caught that a self-round-trip could not:
- ML predefined distribution had 5 low-probability entries, not 7. Both sum to 64, so the table built and every long match decoded wrong.
- Huffman table laid out by descending weight. The mirror layout is also a valid prefix code, so streams decoded into a permuted alphabet rather than failing.
- FSE weight stream terminated a pair late.

The vendored crate stays ONLY as a dev-dependency oracle for that test. It is out
of the kernel build entirely; deleting `vendor/rust/structured-zstd-0.0.49`
would now cost just the conformance test.

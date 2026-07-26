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

### 3.1 Violations of `06§3.1` found by hand (subsumed by 3.0)

| # | Site | Sleep? | Correct Linux fix | Move? |
|---|---|---|---|---|
| 1 | ~~`timer_owner` → `registry::lookup` → `REG.lock()` + O(N) scan, **every tick, both paths**~~ **FIXED (F703)** — slots moved to `ThreadGroup`; both hard-IRQ paths are lookup-free, pinned by a test | no | done | no |
| 2 | ~~`loadavg::tick` → `live_counts` → `REG` walk + `Arc`/`Weak` drops (kalloc free in hard IRQ)~~ **FIXED (F706)** — folds `rq.nr_running` per CPU (Linux `calc_load_account_active`); no lock, no alloc, stays in the tick | no | done | no |
| 3 | ~~`vvar::publish` → `timekeeper::realtime_ns` → `CLOCK.lock()`~~ **FIXED (F707)** — `CLOCK` is a `sync::SeqLock` (Linux `tk_core.seq`); readers acquire nothing, writers are irqsave | no | done | no |
| 4 | ~~`tick_poll_ktimers` → `wake_list_push` → `WAKE_LISTS` lock + `Vec::push` allocates~~ **FIXED (F708)** — `AtomicPtr` llist chained through `Task::wake_next`; push is one cmpxchg, drain one xchg, no lock and no alloc | no | done | no |
| 5 | `bridge_stp_tick` → bridge `state.lock()` every tick + iface `inner.lock()` + alloc + virtio TX **[V]** — hard-IRQ half **FIXED (F709)** via `Slot::BridgeStp`; process-side `_bh` sweep is 3e-bh | no | softirq timer (done) + `spin_lock_bh` on the process side (3e-bh) | no |
| 6 | UART RX ISR → `TtyStruct::receive_from_driver` → plain `tty.inner`; `^C` → `REG` **[P]** | **yes** | `spin_lock_irqsave` on the port; ldisc push → **workqueue** | **yes** |
| 7 | fbcon answerback slow path → same tty tree **[P]** (fast-path `PENDING` early-out is **[V]**) | **yes** | **workqueue** (`flush_to_ldisc`) | **yes** |

### 3.2 Structural defects

- ~~**`preempt_count` is per-CPU and not switched**~~ **FIXED (F704)** `preempt.rs:29`. A task
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
| G | **Frame-size build gate** | 135 functions ≥1 KB, worst 37 KB; would have caught the stack-overflow class pre-boot | `CONFIG_FRAME_WARN` |
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
| 2 | `preempt_count` per-task (3.2) | `F704-preempt-count-per-task` | **IN PROGRESS** — merged on its own merit; per 3.0c it is NOT the x86 stall, but 3.2 is a real defect |
| 2a | `CONFIG_DEBUG_PREEMPT` subset — the instrument 2/2b are diagnosed with | `C216-preempt-leak-diag` | **DONE** #3928 |
| 2b | x86 intermittent stall — **rediagnosed 3.0b**: a ~45 s block-I/O stall in the exec path, not a lost wakeup; systemd's self-freeze is the consequence. Fixed by 3a-3f, not separately | — | FOLDED INTO 3a-3f |
| 1b | `wall_timer_interrupt`'s *conditional* `registry::lookup` in hard IRQ (only when a wall timer is due) — carry `Weak<ThreadGroup>` in `WallEntry` | — | TODO |
| 3a | build `spin_lock_bh` (A) | `F705-spin-lock-bh` | **DONE** #3929 |
| 3b | fix 3.1 #2 loadavg — lock-free in tick | `F706-loadavg-lockfree` | **DONE** #3930 |
| 3c | fix 3.1 #3 `vvar` — seqcount (builds `sync::SeqLock`) | `F707-vvar-seqcount` | **DONE** #3931 |
| 3d | fix 3.1 #4 `WAKE_LISTS` — lockless | `F708-wake-list-lockless` | **DONE** #3932 |
| 3e | fix 3.1 #5 bridge STP — move off the hard-IRQ tick into a softirq | `F709-stp-softirq` | **IN PROGRESS** |
| 3e-bh | `Socket`-class process-side takes → `lock_bh` (~83 sites in `net`); the softirq half of 3.1 #5 | — | TODO |
| 3f | 3.0 `KMalloc` — allocator already masks IRQs across alloc/dealloc; lockdep was false-reporting it. Fixed by teaching lockdep to read ACTUAL IRQ state | `C217-lockdep-irq-state-hook` | **IN PROGRESS** |
| 3g | sysrq dump runs in the serial hard-IRQ and there walks `REG` + allocates — the only lockdep reports left, and only on the timeout path | — | TODO |
| 4a | build workqueue + `kworker` (B) | — | TODO |
| 4b | fix 3.1 #6 UART RX ISR | — | TODO |
| 4c | fix 3.1 #7 fbcon answerback | — | TODO |
| 5 | one generic tick + `ClockEvent` (F); timekeeping CPU a variable | — | TODO |
| 6 | frame-size build gate (G) | — | TODO |
| 7 | sleeping mutex (C) | — | TODO |
| 8 | H — `timer_list` in softirq, `delayed_work`, `tasklet`, threaded IRQs, `kthread_stop`/`park` | — | TODO |
| 9 | module-ABI `_bh`/`_irq`/`_irqsave` lock variants were all bare `raw_spin_lock` | `B1400-module-abi-lock-variants` | **IN PROGRESS** |
| 10 | stale comment `gic/dispatch.rs:142` — `charge_current_tick` is not "atomics only" | `B1401-tick-charge-comment` | **IN PROGRESS** |

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

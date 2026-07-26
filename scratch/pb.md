# Handoff — hard-IRQ lock discipline campaign

`main` @ `32d2e06cf`. Plan of record: **`scratch/skizm.md`** (inventory, per-item
tracking table, validation gates). This doc is state + the next action only.

---

## FIRST TASK NEXT SESSION

**Fix the x86 intermittent hang. It gates everything else — do not start Step 3.**

It is not caused by any of this campaign's work: it reproduces on clean `main`.

```
git checkout main && git pull
make x86
D=/tmp/x; rm -rf $D; mkdir -p $D
OXIDE_SMOKE_ATTEMPTS=1 SMOKE_KEEP_LOG_DIR=$D SMOKE_TIMEOUT=420 tools/boot-smoke.sh x86
grep -a -A4 "per-cpu heartbeats" $D/*timeout*.log
```

Signature: wedges at ~50 s just after `[wait4 ECHILD]`, **both CPUs idle,
`nr_run 0`, nothing runnable** — a lost wakeup, same class as the ARM `smp=2`
hang. x86 default is `smp=2`.

Measured, so it is not this branch and not host contention:

| Config | Result |
|---|---|
| `main` @ `32d2e06cf` | timeout |
| `main`, earlier same day | PASS 114 s (×2) |
| `F703` at merge | PASS 372 s |
| `F704` branch | timeout ×4 |

Boot times crept 114 s → 372 s → 396 s → timeout. No stale qemu processes;
load 1.66 on 48 cores. So: intermittent, and worsening.

**Tools to bring back for it** — prototyped this session, then dropped with a
discarded stash. Re-land them properly first; they turn this from guesswork into
a named failure:

1. `preempt_count` in the sysrq per-CPU heartbeat dump
   (`sched/src/diag/percpu.rs`, `dump_cpus`) — a non-zero HARDIRQ/SOFTIRQ field
   on an idle CPU is the leak, visible directly.
2. `irq_exit` underflow detector — report once per CPU when the HARDIRQ field is
   already clear on exit.
3. Idle-loop leak check — in `halt_forever`, report once if `in_interrupt()` is
   true when a CPU is about to park.
4. `debug-lockdep` (merged, `F702`) — boot x86 with it and diff the reported
   classes against the ARM run recorded in `skizm.md` §3.0.

---

## State

| Step | Item | Branch | Status |
|---|---|---|---|
| 0 | lockdep IRQ-state subset | `F702-lockdep-irq-state` | **merged** #3925 |
| 1 | POSIX timers → `ThreadGroup` | `F703-group-leader-direct` | **merged** #3926 |
| 2 | `preempt_count` per-task | `F704-preempt-count-per-task` | **pushed, NOT merged** |
| 1b | `wall_timer_interrupt`'s conditional `registry::lookup` in hard IRQ | — | TODO |
| 3+ | see `skizm.md` §5 | — | TODO |

### F704 — do not merge until x86 is green

Code is complete and believed correct: `preempt_count` moves to `Task`, per-CPU
slot swapped on **switch-out only** (x86 Linux's model —
`pcpu_hot.preempt_count` swapped in `__switch_to`).

A restore on the resume side is wrong: redundant, because whoever switches back
performs the matching load; and racy, because between storing on `prev` and
reloading it another CPU can pick `prev` up and update it. An earlier revision
had that restore — it was removed, not merely disabled.

Verified: `cargo test -p sched` **189 passed / 0 failed**, including a test that a
task carries its softirq field away across a switch instead of leaking it to the
next task on that CPU. arm gate **PASS** `basic.target` 116 s. x86 unverifiable
(see above).

---

## What Step 0 bought, and why it matters for everything after

`sync::lockdep` (merged) enumerates violations at runtime instead of by reading
code. Its gate: it must reproduce every violation already validated by hand.
**It did — and found one the hand audit missed:**

| Class | rank | Is | Hand audit found it? |
|---|---|---|---|
| `TaskList` | 100 | `REG` | yes — fixed by `F703` |
| `Timer` | 5 | `CLOCK` (`vvar::publish`) | yes |
| `Runqueue` | 110 | `WAKE_LISTS` | yes |
| `Socket` | 140 | bridge state | yes |
| **`KMalloc`** | **200** | **the heap lock** | **no** |

`Tty` did **not** appear, so `skizm.md` 3.1 #6/#7 (the two findings that justify
building a workqueue) remain **unvalidated**. Re-check them with console input
concurrent with a tty syscall *before* starting that work.

Static analysis cannot replace this: `Spinlock::lock` is `#[inline]` and absent
from the binary — zero `bl` to any lock symbol across 50,602 call sites. Linux's
lockdep is runtime for the same reason. Recorded as **[X]** in `skizm.md` so it
is not re-attempted.

---

## Process rules earned the hard way this session

- **Validate before claiming.** Six successive diagnoses of the ARM `smp=2` bug
  were wrong because the culprit was found by reading a few call paths and
  generalising. `skizm.md` tags every claim **[V]** / **[P]** / **[X]**; keep
  doing that, and do not act on a **[P]** row without reading the lines.
- **Establish the baseline before suspecting your own change.** Three x86 boots
  were spent blaming `F704` before testing `main`, which fails too. Boot `main`
  first, always.
- **A single boot proves nothing about an intermittent bug.** Both the ARM and
  x86 hangs are intermittent. Report clean/total, never one result.
- **`ESR_EL1` is stale for IRQ entries** on aarch64 (IRQs do not write it). An
  `esr` decoding as a syscall/abort on an IRQ-vector report is residue from the
  last synchronous exception. This produced one of the wrong diagnoses.
- **`boot-smoke.sh` deletes a failed attempt's log.** Always pass
  `SMOKE_KEEP_LOG_DIR=<dir>`.
- **The Bash tool caps at 10 min**, shorter than an arm boot budget. Run boots
  backgrounded with `SMOKE_TIMEOUT`.

## Also worth fixing when nearby

- `raw_spin_lock_bh` in the Linux-module ABI is literally `raw_spin_lock(l)`
  (`modules/src/linux_sync.rs:152`) — it does **not** disable bottom halves. A
  module using `spin_lock_bh` gets no BH protection. `spin_lock_bh` also does not
  exist as a core primitive (`skizm.md` §2, item A).
- No sleeping mutex exists anywhere in the core kernel (`skizm.md` §2, item C).

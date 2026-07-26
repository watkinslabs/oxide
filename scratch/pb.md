# Handoff — hard-IRQ lock discipline campaign

`main` @ `ad82798c3`. Plan of record: **`scratch/skizm.md`** (inventory,
tracking table with Branch + Status, validation gates). This doc is state and
the next action only.

---

## Landed this session — 16 PRs, every one boot-verified on `main` after merge

| Step | Item | PR |
|---|---|---|
| 2 | `preempt_count` per-task | #3938 |
| 2a | `CONFIG_DEBUG_PREEMPT` subset — `[PREEMPT-LEAK]` + count/resched in the sysrq dump | #3928 |
| 3a | `spin_lock_bh` — `sync::BhGate` + `Spinlock::lock_bh` + `sched::bh::SchedBh` | #3929 |
| 3b | loadavg folds per-CPU `nr_running` instead of walking the task list in hard IRQ | #3930 |
| 3c | timekeeper `CLOCK` behind a seqlock — builds `sync::SeqLock` | #3931 |
| 3d | wake list as a lock-free `llist` — no lock, no alloc, safe from the ISR | #3932 |
| 3e | bridge STP moved to a softirq (`Slot::BridgeStp`) | #3934 |
| 3f | lockdep judges IRQ state by the hardware, not by the lock method | #3937 |
| 4b | tty port lock is irqsave — closes 3.1 #6 **and** #7 | #3942 |
| 5a | `deadline::rearm` split: per-CPU arm vs global wall-timer service | #3939 |
| 9 | module-ABI `_bh`/`_irq`/`_irqsave` actually exclude something | #3935 |
| 10 | `charge_current_tick` "atomics only" comment corrected | #3936 |
| — | doc: 3.0b/3.0c (x86 rediagnosis), 3.0e/3.0f (tty validation) | #3933, #3940, #3941 |

Three Linux primitives the inventory listed as MISSING now exist:
`spin_lock_bh`, `seqlock`, and an honest module-ABI lock set.

**Machine-verified, not argued:** re-running the Step 0 lockdep instrument on
x86 `smp=2` after this work, **a passing boot emits zero lockdep reports**. The
original five classes (`TaskList`, `Timer`, `Runqueue`, `Socket`, `KMalloc`)
are gone from normal operation.

---

## Three plan corrections that came out of validating rather than assuming

1. **The x86 gate was misdiagnosed** (3.0b, 3.0c). The previous handoff called
   it "a lost wakeup" and gated the campaign behind it. It is a multi-tens-of-
   seconds *block-I/O stall* in the exec path; the terminal "nothing runnable"
   state is systemd's own `Freezing execution.` Measured stalls: 12 s / 44.7 s /
   129 s + 292 s across three boots. `preempt_count = 0` on the idle CPU, no
   `[PREEMPT-LEAK]` — so Step 2 was never the fix for it.

2. **`KMalloc` was a false positive** (3.0d, 3f). The allocator already masks
   IRQs across alloc/dealloc via its own `irq_off()` gate. Our lockdep inferred
   IRQ state from *which method was called*, so it could not see that. Linux's
   asks the hardware; now ours does too. **Step 0's original list was
   over-reporting** — check any future class against actual IRQ state first.

3. **The workqueue (4a) has no remaining consumer** (3.0e, 3.0f). §6 rule 3
   said #6/#7 justify the whole effort and had not been read. Read now: both
   are real violations, both worse than recorded — but **neither sleeps**, so
   both are lock fixes, and #4b fixed them with one irqsave. 4a stays on the
   list as genuine Linux parity, but it is no longer a prerequisite for
   anything. That removed the largest item from the critical path.

---

## FIRST TASK NEXT SESSION

**Step 4d — the `^C` path.** `TtyStruct` is now irqsave, but the ISR continues
into `KernelFgSignal::raise` → `registry::tasks_in_pgrp`, which takes `REG`
**plainly and allocates a `Vec`**, inside the UART RX ISR. That is the last
known hard-IRQ violation on a real path. The fix is to make the `TaskList`
class irqsave — Linux takes the `tasklist_lock` read side with irqsave exactly
where IRQ context reads it. ~15 `REG.lock()` sites in `registry.rs`.

Then, in rough value order:

- **3e-bh** — `Socket`-class process-side takes → `lock_bh` (~83 sites in
  `net`); the softirq half of 3.1 #5. `spin_lock_bh` exists for it now.
- **3g** — the sysrq dump walks `REG` and allocates from the serial hard-IRQ.
  Only fires on the timeout path, and it is the debug tooling wedging its own
  diagnosis. Note `try_snapshot` already try-locks, so attribute precisely
  before changing anything.
- **5** — one generic tick + `ClockEvent`; `is_bsp` is still computed
  differently in each dispatcher even after 5a.
- **6** frame-size gate, **7** sleeping mutex, **8** the H items, **4a** if
  wanted for parity.

---

## Process notes that held up

- **A single boot proves nothing.** The stall is ~1-in-3 at one attempt;
  `boot-smoke.sh` defaults to 3 attempts, which is why the normal gate usually
  passes and hid this for so long.
- **`boot-smoke.sh` deletes a failed attempt's log** — always pass
  `SMOKE_KEEP_LOG_DIR=<dir>`.
- The pre-push hook **skips boot-smoke for PR-branch pushes**; boot-verify after
  each merge to `main` instead, and before merging anything on the console path.
- **Worktrees have no `vendor/`** (gitignored, fetched). ARM boots need
  `vendor/grub` *and* `vendor/firmware` copied in, or they fail with
  "incomplete vendored arm64-efi modules" / "missing ovmf-aarch64.fd" — which
  looks like a code failure and is not.
- Measuring the largest gap between consecutive klog timestamps turns "the boot
  was slow" into a number with no extra boots. Script in `skizm.md` 3.0b.
- **`metadata/index.md` counters drift** when several branches merge in
  sequence — each resolution can drop a bump. F708/F709 were both used while
  the file still said 707. Check it against `git branch -a` before naming a
  branch.

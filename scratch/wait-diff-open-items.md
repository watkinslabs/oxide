# Guest-differential open items — post-B1455

Sister ledger to `scratch/interruptible-wait-plan.md` (which is at its size cap).
Everything still open on the `tools/boot-smoke-wait-diff.sh` differential and on
the accounting path B1455 opened up. One row = one lane; claim by putting the
branch in the Branch column and committing that before writing code.

Status: `OPEN` unclaimed · `CLAIMED` lane exists · `DONE` merged · `WONTFIX`.

## 1 Ledger

| Status | Item | Branch | Arch | Evidence |
|---|---|---|---|---|
| DONE | W1 `sleep\|stopcont_restart_block` — stop taken inside the park loop | `B1456-stop-unwinds-sleep` | both | §2 |
| CLAIMED | W2 `fire_due_timers` runs on every syscall return | `B1457-timers-off-syscall-return` | both | §3 |
| OPEN | W3 tick-quantised CPU accounting overshoots wall time | | arm | §4 |
| CLAIMED | W4 per-CPU tick/arm state never exercised at `SMP>1` | `B1458-smp-tick-state` | both | §5 |
| OPEN | W5 nine hosted tests fail on every full-workspace run | | hosted | §6 |
| OPEN | W6 `delayed_work` tests flake under parallel load | | hosted | §7 |
| OPEN | W7 post-fix tick-gap distribution never re-measured | | x86 | §8 |
| DONE | W8 every kernel timeout had a ~100 ms floor (`latency|*` records added) | `B1460-wait-deadline-timer-floor` | both | §10 |

Record count is **44** since B1460 added `latency|nanosleep_short` and
`latency|epoll_wait_short` (it was 42 after F760's `mqapi` block; the 29 below
predates both).

Differential state at `8b4c9a668` + B1456, own runs, clean builds: **29/29
identical records on BOTH arches — zero divergences**, the first time that has
held. x86 `x86-20260727-192336-a52Dqp`, arm `arm-20260727-192540-46DkYl`.

## 2 W1 — the job-control stop never unwinds the sleep — DONE (B1456)

The last differing record, reproducing on both arches:

```
-wdiff|sleep|stopcont_restart_block|rc=0|errno=OK|sig=0|rem_written=1   <- Linux
+wdiff|sleep|stopcont_restart_block|rc=0|errno=OK|sig=0|rem_written=0   <- oxide
```

Pre-existing on unmodified `main`: proven by a clean baseline run with the
B1455 fix stashed (`x86-20260727-164718-NP1nwe`), which diverges on this row
too. Not a B1455 regression.

**Root cause** (`syscalls/src/035_nanosleep.rs:133-146`). The park loop takes
the stop itself and resumes in place:

```rust
SleepWake::Stop(sig) => {
    sched::live::stop::stop_until_cont_sig(sig as u8);
    continue;                    // never unwinds to interrupt_result
}
```

`interrupt_result` is the only caller of `write_remaining` and the only site
that arms `RESTART_NANOSLEEP`, so a stop reaches neither. The sleep resumes
against the same absolute `deadline` and falls out of the
`monotonic_ns() >= deadline` arm with `0` — the right `rc` by a different
mechanism, with `rmtp` untouched.

Linux `do_nanosleep` (`kernel/time/hrtimer.c:2404`) loops
`while (t->task && !signal_pending(current))`, and a pending stop signal makes
`signal_pending` true. So the loop EXITS, the tail copies the remainder to
`rmtp` and returns `-ERESTART_RESTARTBLOCK`; the stop is taken later in
`get_signal()` on the way back to user mode, and SIGCONT resumes through
`arch_do_signal_or_restart` → `restart_syscall(2)` → the armed block.

Two consequences, only the first of which the probe can see:

| | oxide | Linux |
|---|---|---|
| `rmtp` on the pre-stop pass | not written | written (`nanosleep_copyout`) |
| resume mechanism | in-place `continue` | armed restart block via slot 219 |

So a stop during a sleep bypasses the whole F743 restart machinery. Fixing W1
means making the stop unwind — return through `interrupt_result` and let the
syscall-return tail's `stop_until_cont_sig` arm take it, which is where F743
already put it.

**Same shape, same fix, 2 more sites**: `syscalls/src/034_pause.rs:19` and
`:31` both `stop_until_cont_sig(...); continue;` inside the park loop. `pause`
has no `rmtp`, so no probe record changes, but the resume mechanism diverges
identically. `grep -rn "SleepWake::Stop" crates/` is the full site list (6 hits,
3 of them these loops).

Scope it as one lane covering all three loops; do not sweep beyond that grep.

**Fix as shipped.** `SleepWake::Stop(u32)` is deleted — `Task::sleep_wake` is
now `signal_pending(current)` and nothing else, so a stop can no longer be
expressed as an in-loop action. It also stops consuming the stop signal:
`dequeue_signal` inside `get_signal` (`kernel/signal.c:643`) is Linux's only
consumer, and the tail's `take_lowest_pending` is ours. Both park loops
(`035_nanosleep.rs` `sleep_until_deadline`, shared with slot 230 and the 219
continuation; `034_pause.rs` both arms) return through their interrupted tail.
Hosted causality: `a_job_control_stop_writes_the_remainder_and_arms_the_restart_block`
and `timer_abstime_under_a_job_control_stop_still_writes_nothing`
(`fs::sys_nanosleep_shape`) FAIL on the pre-fix source and pass after;
`pause_default_stop_signal_unwinds_for_the_dispatch_tail` replaces the test
that asserted the old shape.

## 3 W2 — POSIX timers are serviced on the syscall-return path

`syscalls/src/dispatch/core.rs:480` calls `sched::timers::fire_due_timers()` on
EVERY syscall return. Linux has no such call: POSIX timer expiry is driven from
the hrtimer/tick, never from syscall exit.

This is what made B1455 fatal rather than merely wasteful — `fire_due_timers`
ends in `program(next_interrupt_deadline())`, so the hottest path in the kernel
was reprogramming the timer hardware. B1455 fixed the two consequences (the
tick no longer slides, and an unchanged deadline no longer rewrites the LVT and
MSR), but the call itself is still there, still O(SLOTS) per syscall, still
re-deriving timer state from a path Linux does not use.

Open question for the lane, not a foregone conclusion: which expiries would be
LOST if it were deleted? If the answer is "none, the tick covers them", delete
it. If some class only fires here, that class is missing from the tick and the
fix belongs there.

## 4 W3 — tick-sampled accounting can overshoot wall time

One ARM run in three reported `sibling_burn_completes|outcome=ok|slept=0|cpu=1`
— `cpu=1` correct, but the probe's `slept` bit (wall elapsed ≥ 300 ms) missed.
The other two ARM runs and every x86 run matched exactly.

`charge_current_tick` attributes the WHOLE inter-tick delta to whatever task the
tick interrupted (Linux `CONFIG_TICK_CPU_ACCOUNTING`), so charged CPU time can
lead wall time by up to one tick period. At `HZ=100` that is 10 ms against the
probe's 300 ms floor — tight enough that TCG's irregular cadence lands the other
side of it sometimes. The host oracle does not have this granularity: it runs
`VIRT_CPU_ACCOUNTING_GEN`, which charges at context-switch boundaries.

Two candidate lanes, pick deliberately:
- accept tick granularity and widen the probe's margin (cheap, hides nothing
  the record does not already report via `cpu=`);
- move to precise accounting at switch/entry boundaries (Linux
  `vtime_task_switch`), which is the real fidelity gap.

Not a blocker for W1; it makes that row flaky on ARM, not wrong.

## 5 W4 — `SMP>1` is untested for the new per-CPU tick state

`make smoke` and the differential both run `SMP=1`, so B1455's
`NEXT_TICK_NS` / `ARMED_NS` arrays (`sched/src/timers/runtime.rs`) are only ever
touched at index 0. The CAS in `tick_deadline` and the skip-if-unchanged guard
in `program` are reasoned-correct against an IRQ racing process context on ONE
CPU; nothing has exercised two CPUs arming their own deadlines.

`mcp__qemu__qemu_start(smp=N, accel="tcg")` is the tool — some SMP timing bugs
only reproduce under TCG.

## 6 W5 — the nine standing hosted failures

`cargo test --workspace --no-fail-fast` at `a5791c6d3`: **7860 passed, 9 failed**,
the same nine on repeated runs.

| Test | Crate |
|---|---|
| `write_path_produces_e2fsck_clean_image` | `ext4` |
| `htree_leaf_split_stays_e2fsck_clean` | `ext4` |
| `boot_like_balloc_into_uninit_group_keeps_fsck_clean` | `ext4` |
| `concurrent_churn_keeps_fsck_clean` | `ext4` |
| `linux_debugfs_automount::tests::debugfs_automount_resolves_through_vfs_walk` | `modules` |
| `swap::tests::final_swap_reference_reclaims_zram_slot` | `drv-zram` |
| `sys_dup2_reserved_target_is_ebusy_and_preserves_reservation` | `fs` |
| `tests::default_queue_limits_are_canonical_single_block_topology` | `block` |
| `tests::vsock_destination_and_interrupt_errors_match_linux` | `socket` |

`interruptible-wait-plan.md` §8 lists twelve and is stale — `sys_dup2_without_current_or_fdtable_is_ebadf`,
the `pmm` zram-provider `Ebusy` row, `try_populate_defaults_is_idempotent_for_existing_pseudo_devices`
and `lookup_prefers_longest_prefix` no longer fail. §8 now points here.

Four of the nine are ext4 e2fsck-cleanliness — one lane, per the
no-booting rule in memory (iterate hosted, e2fsck is the gate). The other five
are independent and can go in parallel.

## 7 W6 — `delayed_work` flakes under parallel load

`live::delayed_work::tests::the_earliest_deadline_gates_the_walk` and
`::a_full_table_refuses_rather_than_dropping_silently` failed on one
full-workspace run and passed on the next, with the same binary. `cargo test -p
sched --lib` is 560/560 clean three times running, and the two pass in isolation.

Same class as B1446 (§9 of the plan): process-global state shared across tests
that cargo runs on parallel threads. Fix it the way B1446 did rather than
re-diagnosing.

## 8 W7 — the tick-gap distribution was never re-measured after the fix

The `debug-cputime` `[CPUT irq]` trace on the PRE-fix kernel showed twelve gaps
over 0.5 s in one boot, the largest 5.19 s (the bug) but also 1.89 s, 1.11 s and
nine more in the 0.5-0.7 s band during early boot. B1455 explains and removes
the mechanism behind all of them, and nothing re-ran the trace to confirm the
distribution actually collapsed.

One boot with `FEATURES=debug-cputime` settles it:

```
FEATURES=debug-cputime ./tools/boot-smoke-wait-diff.sh x86 900
```

then re-run the gap histogram over `[CPUT irq]` timestamps in the UART log. If
sub-second gaps survive, something else stalls the tick and W2 is the first
suspect.

## 9 The probe to reach for

`debug-cputime` (`crates/kernel/sched/src/cputime_trace.rs`, wired through
`kmain` → `boot-{x86_64,aarch64}`) is in-tree and default-off. Its header names
the four signatures that separate a mis-charged group, a mis-read sample, an
uninterruptible child and an absent interrupt. `ticks=` on the non-tick events
is the one that cracked B1455: identical either side of a window means no timer
interrupt arrived, which no amount of reading the accounting code would have
shown.

## 10 W8 — the ~100 ms timeout floor — DONE (B1460)

`park_with_deadline` only stamped `Task::wakeup_deadline_ns`. Its sole consumer
was `tick_wake_expired`, a registry walk registered as a **100 ms** periodic on
the `ktimers` kthread, self-throttled to 100 ms, on a kthread that parks 100 ms
per loop — and `next_interrupt_deadline()`, which programs the hardware
one-shot, was fed only by the POSIX-timer wall heap and the CPU timers. No wait
deadline ever reached the hardware. `epoll_wait(.., 1)` and `nanosleep(1ms)`
both blocked ~100 ms, and so did every futex timeout, `poll`, `select`,
`SO_*TIMEO` and mqueue/SysV timed wait.

Fix: `sched::hrtimeout`, Linux's hrtimer range model —
`soft = deadline`, `hard = soft + slack`, queue keyed by HARD (Linux's rbtree
key, `include/linux/hrtimer.h:91-95`), sweep everything SOFT-due
(`kernel/time/hrtimer.c:2093`). `next_interrupt_deadline()` folds the queue head
into the one-shot; the arch timer dispatchers sweep on every CPU before
re-arming. Slack is `current->timer_slack_ns` (50 us) for the generic waits and
`select_estimate_accuracy` (0.1% of the remaining timeout, floored at the task
slack, capped at 100 ms) for poll/select/epoll — the coalescing that keeps a
machine full of pollers off the interrupt path.

Two new records, both falsifiable: `latnowait` (ask for no wait — the
return-immediately kernel) flips `ge_req`, `latslow` (spend 100 ms per wait —
the defect itself) flips `within_budget`.

**Measured, x86, same probe both sides** (20 iterations of a 1 ms wait, run as
the boot-time systemd oneshot; a temporary non-record `latms|` print carried the
raw total out on the UART and was reverted before merge):

| | `nanosleep(1ms)` | `epoll_wait(.., 1)` |
|---|---|---|
| oxide before (`x86-20260727-233627-niTEfx`) | 2092 ms / 20 = **104.6 ms** per call | 2189 ms / 20 = **109.5 ms** |
| oxide after (`x86-20260727-233854-LPUmvg`) | 152 ms / 20 = **7.6 ms** | 120 ms / 20 = **6.0 ms** |
| host Linux oracle, both runs | 21 ms / 20 = **1.05 ms** | 21 ms / 20 = **1.05 ms** |

The before-run diverges on those two records and NOTHING else (4 diff lines,
all `latency|*`), which is the falsification the case exists to provide.

**Not isolated — the honest gap.** The post-fix residual is ~5-6 ms per wait
above the host oracle. It is measured while the probe races the rest of userspace
starting, so contention is the obvious candidate, but this lane did NOT separate
wake->run scheduling latency from any remaining timer quantisation: no
request-length experiment can, because tick quantisation adds a CONSTANT to the
latency rather than scaling it, so it is invisible in a difference of two request
lengths. The discriminator is kernel-side — `FEATURES=debug-wakelat` already
reports wake->run latency (H2) — and it is one boot plus a histogram. Worth a
lane; the 14-18x already banked does not depend on the answer.

**Interaction with W2.** W2 (`fire_due_timers` on every syscall return) is
UNCHANGED by this lane and still open on `B1457-timers-off-syscall-return`. It
is now less load-bearing, not more: wait expiries no longer depend on any
syscall-return reprogram, so deleting that call can no longer lose a timeout —
but the audit W2 asks for (which expiries would be LOST) is still W2's to do.

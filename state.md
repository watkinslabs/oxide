# state.md — session hand-off

Branch: `main` @ `aca89904f`. Clean tree, no open PRs, no stray worktrees.
`make smoke` PASS both arches on this code (x86 90s, ARM 109s, own runs, exit 0).

## Headline

The guest differential (`tools/boot-smoke-wait-diff.sh`) went from three
divergent records to **one on each arch**. Two accounting/wake bugs closed:

- `a5791c6d3` (#4064, B1455) — the accounting tick was derived as
  `now + TICK_NSEC` on every reprogram, and `fire_due_timers` reprograms on
  EVERY syscall return, so any task syscalling faster than 100 Hz postponed its
  own tick forever. Measured: **zero** timer interrupts in 5.01 s while a thread
  spun (`TICK_COUNT` 2432→2433, 214835 re-arms in the same window). No tick ⇒ no
  `charge_current_tick` ⇒ `CLOCK_PROCESS_CPUTIME_ID` frozen, and no preemption of
  a CPU-bound thread either. Now an absolute per-CPU deadline advanced only when
  it fires (Linux `hrtimer_forward`).
- `f964bb16c` (#4063, B1454) — TCP receive wake.

`aca89904f` (#4065) wrote down what is left.

## Open work

`scratch/wait-diff-open-items.md` — seven rows, Status + Branch columns, claim
before writing code.

| | Item | State |
|---|---|---|
| W1 | `sleep\|stopcont_restart_block` | **root cause found, ready to start** |
| W2 | `fire_due_timers` on every syscall return | needs a "what expiry would be lost" audit first |
| W3 | tick-quantised accounting overshoots wall time | ARM-only flake, pick a lane deliberately |
| W4 | per-CPU tick/arm state untested at `SMP>1` | qemu MCP, `accel="tcg"` |
| W5 | nine standing hosted failures | 4 ext4 e2fsck + 5 independent |
| W6 | `delayed_work` flakes under parallel load | same class as B1446 |
| W7 | post-fix tick-gap distribution never re-measured | one boot settles it |

W1 is the last differential divergence, on both arches, and is NOT a B1455
regression (proven with a clean baseline run with the fix stashed).
`sleep_until_deadline`'s `SleepWake::Stop` arm (`035_nanosleep.rs:133-146`) takes
the stop *inside* the park loop and `continue`s, so it never unwinds through
`interrupt_result` — the only caller of `write_remaining` and the only site that
arms `RESTART_NANOSLEEP`. `rmtp` is never written; the resume is an in-place
`continue` rather than `restart_syscall(2)`, so `rc=0` is right by the wrong
mechanism. Linux exits the loop on `signal_pending` (true for a pending stop,
`hrtimer.c:2404`), copies the remainder out, takes the stop in `get_signal()`.
`034_pause.rs:19` and `:31` are the identical shape — one lane, all three loops,
do not sweep past `grep -rn "SleepWake::Stop" crates/`.

## First command next session

    cd /home/nd/oxide/kernel && git pull && gh pr list --state open \
      && sed -n '1,20p' scratch/wait-diff-open-items.md

Then claim W1 as `B1456-...` (counter is current in `metadata/index.md`), put the
branch in its Branch column, commit that claim, and work in a fresh worktree.

## Reusable from this session

- **`debug-cputime`** (`crates/kernel/sched/src/cputime_trace.rs`, default-off,
  both arches) is the probe that cracked B1455. Its header names the four
  signatures that separate a mis-charged group, a mis-read sample, an
  uninterruptible child, and an absent interrupt. `ticks=` on the non-tick events
  is the decisive one: identical either side of a window means no timer interrupt
  arrived — which no amount of reading the accounting code would have shown.
- **The differential is a ~2 min loop**, not a boot-per-hypothesis slog:
  `FEATURES=<feat> ./tools/boot-smoke-wait-diff.sh x86 900` builds, boots, runs
  the same binary on the host oracle, and diffs the record streams. Seven
  instrumented runs fit in one session.
- **A record's extra bits are the falsifier.** `cpu=0|burn=1` is what proved
  B1455 was a kernel bug and not a probe artifact; `outcome=ok` alone would have
  read as a match. When adding a probe case, carry the evidence bits that
  separate "did the right thing" from "did nothing".
- **Attribute before you fix.** Stash the fix and re-run to prove a neighbouring
  divergence pre-exists. That is how W1 was cleared of being a B1455 regression,
  and it cost one 2-minute run.

# wait_diff — interruptible-wait / restart-semantics differential

Host-oracle differential for the `ERESTARTSYS`-vs-`EINTR` work
(`scratch/interruptible-wait-plan.md`). One glibc-ABI binary runs on this
machine's Linux kernel and inside one oxide boot; the `wdiff|` record
streams must match byte-for-byte.

    make -C userspace/wait_diff run     # oracle only
    make wait-diff-selftest             # falsification gate, ~2min, no boot
    make smoke-wait-diff-x86            # oracle + one boot + diff
    make smoke-wait-diff-arm

## 1 Record contract

`wdiff|<area>|<test>|k=v|...`, fixed order, one line per case. Never print a
raw duration, pid, pointer or a value the two kernels may legitimately
disagree about for reasons unrelated to the semantics under test — print
BUCKETS (`rem_lt_req=1`) and named classes (`outcome=eintr`).

## 2 Read this before changing a sleep case

`nanosleep`/`clock_nanosleep` are **never restarted by `SA_RESTART`**.
`signal(7)` lists the sleep family among the interfaces that always fail
with `EINTR` when a handler runs: they return `-ERESTART_RESTARTBLOCK`,
which `handle_signal` rewrites to `-EINTR` for any handler delivery,
`SA_RESTART` or not. The restart_block continuation is reachable only when
NO handler runs — `sleep|stopcont_restart_block` (SIGSTOP/SIGCONT) is the
case that exercises it.

This is recorded here because the lane was commissioned on the opposite
assumption ("install SA_RESTART, assert `nanosleep` RESUMES"). The oracle
disagreed with the remembered claim before it disagreed with the kernel —
which is the whole argument for running the real syscall on a real Linux
instead of writing down what it ought to do. `sleep|rel_sarestart` and
`sleep|rel_norestart` are deliberately identical; that identity IS the
assertion.

Second non-obvious one: `stopcont_restart_block` returns `rc=0` **with
`rem_written=1`**. Linux copies the remainder out on the first
(pre-stop) pass before arming the block, then completes at the original
absolute deadline. A kernel that only writes `rem` on a final `EINTR`
shows `rem_written=0`.

## 3 Raw syscall vs glibc wrapper

| Case | Uses | Why |
|---|---|---|
| every `sleep\|*` | `syscall(SYS_clock_nanosleep)` | glibc's wrapper RETURNS the errno instead of setting it, and its `nanosleep` is a `clock_nanosleep(CLOCK_REALTIME,0,…)` shim on both arches — raw keeps both arches and both kernels on one ABI |
| `syslog\|*` | `syscall(SYS_syslog)` | no glibc wrapper for the kernel ring |
| everything else | ordinary glibc entry point | the wrapper IS the interface under test, and each is a thin passthrough here |

## 4 Every case must be falsifiable

`WAIT_DIFF_MUTANT=<name>` breaks exactly one case;
`tools/wait-diff-selftest.sh` asserts each mutant changes the records it
should and **no others**. A differential probe that cannot fail makes a
green boot look like evidence.

| Mutant | Breaks |
|---|---|
| `eintr` | strips `SA_RESTART` — every must-resume case |
| `restartall` | forces `SA_RESTART` on — every must-`EINTR` case |
| `absrem` | runs the ABSTIME case relatively (`rem` writeback) |
| `handler` | replaces stop/cont with a handled signal |
| `nofg` | continues the tty job without foregrounding it |
| `wallcpu` | CPU clock -> `CLOCK_MONOTONIC` (the pre-F751 bug) |
| `noburn` | no sibling to advance the process CPU clock |
| `mqnokill` | never signals the parked mq receiver |
| `nosig` | drops the mid-wait interrupt entirely (blanket) |

## 5 Every blocking case is bounded

Cases whose failure mode is "never returns" run in a child behind
`wait_bounded`, so a stall records `outcome=blocked` instead of eating the
run. This is not defensive padding: oxide's `fcntl(F_SETLKW)` blocked past
the holder's release on the first guest run and, as an in-process call,
cost all 21 records behind it.

## 6 Not covered

| Gap | Why |
|---|---|
| blocking `connect` | no deterministic arrangement — an unreachable peer never completes, so the `SA_RESTART` arm would hang rather than resume |
| `syslog(2)` by default | needs `CAP_SYSLOG` and an EMPTY ring, reachable on the oracle only by CONSUMING the host's kernel ring (global cursor). Opt in with `WAIT_DIFF_SYSLOG=1` |
| PI futexes | `-ENOSYS` in this tree (plan §7, own project) |
| `mq_timedsend` full-queue block | only the receive side is exercised |

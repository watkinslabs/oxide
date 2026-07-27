# state.md — session hand-off

Branch: `F754-wait-fix-integration` (integration point). Seven fix/harness
branches open, **none merged to main** — deliberately, see below.

## Headline

F753 built the first guest differential for the interruptible-wait campaign
(`userspace/wait_diff`, merged PR #4053). It found **15 diverging records of 29**
against the host Linux oracle. Six fix lanes closed most of them.

Integrated stack boot-verified on BOTH arches:

| arch | before | now | remaining |
|---|---|---|---|
| x86_64  | 15/29 diverge | **2/29** | `tcp_recv_sarestart`, `cputime\|sibling_burn_completes` |
| aarch64 | 15/29 diverge | **5/29** | those 2 + `sleep\|rel_norestart`, `sleep\|abs_sarestart`, `stopcont_restart_block` |

Read `scratch/interruptible-wait-plan.md` §17-§21 first. **§20 is the finding
that matters** (correctness was verified where the code wasn't); §21 records the
two regressions only integration caught.

## NOTHING IS MERGED TO MAIN. That is deliberate.

B1449 was hosted-green and would have shipped a TCP hang. B1453 was x86-green
and would have shipped an aarch64 regression. Both were invisible to every
per-lane gate this repo has. **Do not merge a lane on its own green.**

## Branches (all pushed, none merged)

| Branch | PR | State |
|---|---|---|
| `F754-wait-fix-integration` | — | all six merged + plan §20/§21. THE integration point |
| `B1448-signal-frame-eintr-normalize` | #4055 | DONE, boot-verified both arches. Closed 7 records alone |
| `B1449-socket-restart-erestartsys` | #4056 | good for AF_UNIX; **regressed TCP to a hang**. Lane re-tasked |
| `B1450-cpu-clock-nanosleep-wall` | #4057 | half-fixed; sleep now parks but is never woken. Lane re-tasked |
| `B1451-tty-sigttin-resume` | #4060 | DONE, both jobctl records match |
| `B1452-setlkw-killable-park` | #4059 | DONE, `setlkw_sarestart` matches |
| `B1453-sleep-engine-residuals` | #4061 | works x86, **fails + regresses aarch64**. Lane re-tasked |
| `C229-wait-diff-timing-margin` | #4058 | probe hardening, falsification gate green |

Three lanes were resumed with the boot evidence and had not reported at handoff.

## The 3 open defects

1. **`fd|tcp_recv_sarestart` = blocked** (both arches). B1449 made TCP emit
   `-ERESTARTSYS`; the tail restarts it and the restarted call never completes
   though the peer wrote 1.5s in. AF_UNIX restarts fine on the same commit, so
   the bug is specific to RE-ENTRY of the TCP wait. Was `eintr` before — a
   wrong errno became a hang, strictly worse.
2. **`cputime|sibling_burn_completes` = eintr|slept=1** (both arches).
   `slept=1` proves the sleeper genuinely parks for its full 300ms, so B1450's
   resolution fix works; it is released by the probe's 5s guard, never by the
   CPU clock. The accounting-tick wake never fires for a sleeper on a
   thread-group clock when a DIFFERENT thread is ticking.
3. **Three aarch64-only sleep rows** (`rel_norestart`, `abs_sarestart`,
   `stopcont_restart_block`) share one shape: syscall returns 0, `rem`
   untouched — the interrupted tail (rmtp copyout + restart-block arm) is
   skipped on aarch64. `rel_norestart` was CORRECT at the B1448 tip
   (run `arm-20260727-135433-DIJ9l8`) and wrong on the stack
   (`arm-20260727-142738-I1IdiZ`), so it is a B1453 regression. Lead: B1453
   threads `syscall_restart_allowed` through a path where aarch64 has an early
   `return sig_rv` that x86 does not.

## First commands next session

    cd /home/nd/oxide/wt-integ && git fetch origin
    # merge whatever the three lanes pushed, then:
    cargo run -p xtask -- kernel --arch x86_64 && cargo run -p xtask -- kernel --arch aarch64
    ./tools/boot-smoke-wait-diff.sh x86 900
    ./tools/boot-smoke-wait-diff.sh arm 1500
    # compare: diff <run>/linux.records <(grep -a '^wdiff|' <run>/oxide-uart.log | sed 's/\r$//')

Merge order when clean: C229, B1448, then B1449/B1450/B1451/B1452/B1453.
**Re-run the two-arch differential AFTER the final merge, not only before** —
both regressions arose from interaction, so the last lane merged earns the same
integration check as the first.

## Gotchas that cost time here

- `tools/wait-diff-selftest.sh` (~4min, no boot) is the harness's own gate: 9
  mutants, each must change exactly its own records and no others. Run it after
  ANY probe edit.
- The probe can go green for the wrong reason — `userspace/wait_diff/README.md`
  §5. Both such cases were found by fix lanes, not by the probe itself.
- B counter: lanes bumped it independently and conflicted. Integration branch
  holds `metadata/index.md` at **B=1454**; keep that on merge.
- `scratch/interruptible-wait-plan.md` conflicts on every lane merge (each
  appends its own outcome section). Resolution is to KEEP BOTH SIDES.
- Wrapping a smoke run in `( ...; echo EXIT=$? )` masks its exit status; the
  script itself reports FAIL/exit 1 correctly.
- Worktrees do not inherit `vendor/{cross,firmware,grub}` or
  `crates/kernel/ext4/tests/*.img` — symlink/copy them from the main tree.

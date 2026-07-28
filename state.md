# state.md — session hand-off

## Headline

Syscall compliance campaign **closed**: `NEEDS-AUDIT` is 0 (was 198). Matrix now
161 IMPL / 197 PARTIAL / 22 LINUX-ENOSYS / 3 DONE across 385 rows.

Four Linux subsystem audits ran and merged (~689 findings, 34 BLOCKER, 95
SECURITY). Consolidated index: **`scratch/linux-compliance-findings.md`** — read
this first; it deduplicates blockers across the four source docs, orders them by
impact, and records what could not be determined rather than guessing.

Source docs: `scratch/audit-{mm,sched,vfs,net-sec}.md`.

## Landed this session (selected)

| What | Effect |
|---|---|
| `B1460` timeout floor | `nanosleep(1ms)` 104.6ms → **7.6ms**; `epoll_wait(..,1)` 109.5ms → **6.0ms** (host oracle 1.05ms) |
| `B1459` signal frames | arm64 `rt_sigreturn` let userspace run at **EL1**; x86 EFLAGS let it clear IF. Same hole existed via `PTRACE_SETREGS` (duplicate rule copy, arm64 one missing the RES0 mask) |
| `B1464` exec creds | `S_ISUID`/`MAY_EXEC`/`AT_SECURE`/`MNT_NOSUID` all absent; file-cap decoder read the interleaved `vfs_cap_data` as contiguous, granting the wrong caps above bit 31 |
| `F768` `AT_RANDOM` | was a clock reading — glibc's stack canary + pointer guard were predictable |
| `F767` timestamps | `Iattr` unsigned ns → `{sec: i64, nsec: u32}`; relatime compared unsigned (pre-1970 looked *newer*); ext4 read 1901 back as 2106 |
| `F766` perf/bpf/uring | `perf_event_open` discarded all 5 args and returned a timestamp as any counter; aarch64 295..402 fell through to the **x86 table** (`syscall(300)` ran `fanotify_mark`); 3 io_uring ring-layout bugs |
| `F763` mempolicy/mseal | `mmap(MAP_FIXED)` replaced a **sealed** range; `memfd_secret` never worked (args rewritten into `memfd_create`) |
| `F764` admin/tty | `reboot(2)` in a container **halted the host**; `vhangup` never touched a tty; `futimesat` was wired to `utimensat` (µs read as ns) |
| `C232`/`C233` tooling | vendor firmware pinned to a rolling nightly that had drifted; boot-smoke now self-heals a fresh worktree's `vendor/` |

## In flight

Open PRs: #4093 (SysV differential), #4097 (procfs creds + inotify names),
#4098 (durable write). Lanes running: `B1461` poll-subscribers/`POLL_OUT`,
`B1465` TCP ISN, `B1466` signal-frame FPU state, `B1467` SMP TLB+runqueue.

## Open, no lane yet

- **Blocker #3**: signals only delivered at the syscall-return tail → a compute-bound
  loop issuing no syscalls is **unkillable**. Needs the IRQ/exception return path,
  both arches (`docs/54`). Hold until `B1466` lands — same files.
- **Blocker #10**: no global OOM killer (`kill_memcg` has one caller, memcg-only).
- ASLR does not exist (`docs/31§6`) while `randomize_va_space` reports 2.
- `timerfd` still polls — not covered by the `B1460` timeout fix.
- The O(N) all-task scan survives at 100ms cadence for `alarm(2)`/itimers.
- 197 PARTIAL rows; `scratch/partial-gap-triage.md` splits them (33 functional
  gaps vs coverage debt) but predates the audits — re-derive against the findings doc.

## Standing hazards (cost real hours; do not relearn)

1. **Phantom tests.** Files under `#[cfg(target_os = "oxide-kernel")]` compile their
   `#[cfg(test)] mod tests` out **silently** while cargo prints "ok". Hit **five** times
   in shipped code; `stat_common.rs`'s tests had never compiled once. Put decision
   logic in ungated modules; prove tests run by breaking an assertion and watching
   the count drop.
2. **Machinery with no callers** is the dominant defect class — not missing code.
   `age_anon`, `psi::task_stall`, the readahead state machine, the slab allocator,
   `update_rtt` (TCP RTO stuck at 1s), `timer_slack_ns`, `atime_needs_update`,
   `is_nosuid`. **Grep call sites, not definitions.** Many "features" are wiring jobs.
3. **`tools/boot-smoke.sh` reuses /tmp log names** across concurrent runs. Trust only
   your own invocation's exit status and `PASS/FAIL` line — never a log found by
   timestamp. This has produced a retracted before/after claim.
4. **A weak implementation passes a naive test.** `AT_RANDOM`'s "two execs differ"
   test passed with the broken clock formula. The load-bearing assertion was
   "upper half not derivable from lower half." Design the assertion against the
   *actual* failure mode.
5. Absence of an `arm_abi` mapping is **not** `ENOSYS` — unmapped aarch64 numbers
   fall through to the x86 table and run the wrong syscall.

## First task next session

```
git -C /home/nd/oxide/kernel pull && cat scratch/linux-compliance-findings.md
```
Then: land the remaining lanes, and **boot GNOME** — it has not been run since any
of this work, and the timeout fix is the most likely desktop unblocker.

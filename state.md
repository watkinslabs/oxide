# state.md — session hand-off

Branch: `main` @ `2e87e64cd`. Clean tree, no open PRs. Both arches boot to
`basic.target` (x86 105s, ARM 121s, attempt 1 each, verified on this commit).

## Headline

Syscall-compliance campaign against `scratch/syscall-compliance-matrix.md`.
IMPL 44 → **96**, NEEDS-AUDIT 198 → **103**, IN-PROGRESS 5 → **0**. All 385
rows carry a Branch column; `tools/matrix-lint.py` is green and now guards the
ledger itself (see below).

Every claim was verified against **`/home/nd/oxide/linux-master`** (v7.2.0-rc4).
`/usr/src/kernels/*` is the headers-only devel package — no `kernel/sys.c`, no
`ipc/*.c`. Six agents were briefed at the wrong path and corrected mid-flight;
CLAUDE.md now records this as a hard rule.

## Defects found (representative, all merged)

- `.` and `..` emitted by **nothing but ext4** — /proc, /sys, /dev, /run,
  cgroupfs all listed dotless; `vfs::dirent::emit_dots` had zero callers.
- ext4 `d_type` read `name_len`'s high half without the FILETYPE feature bit,
  so every entry incl. subdirectories reported `DT_REG` — and wrote `DT_REG`
  **to disk** for device/FIFO/socket hardlinks.
- `sched_setaffinity`: no permission check at all; mask not inherited on fork.
- `exit_group` from a non-leader reported SIGKILL not `WIFEXITED(N)`; a STOPPED
  sibling never took the zap's SIGKILL, hanging the parent's `wait4` forever.
- `syslog`: no permission check — any process could read the kernel log.
- `setxattr` copied unbounded user data before the size check.
- pselect6/ppoll restored the sigmask *before* signal delivery (the race those
  syscalls exist to close) and left the temporary mask installed permanently.
- Unprivileged `setuid` could re-acquire an identity dropped via `setresuid`;
  NGROUPS_MAX was 32 not 65536; no dumpability downgrade on privilege drop.
- `CLOCK_PROCESS_CPUTIME_ID` ran **backwards** (summed only live threads).
- Console output had no lock — Linux serialises all printk→console.
- ARM syscall 42 dispatched as x86 `connect`; other 296 pairs audit clean.

## Open work

1. **Two lanes may still be in flight** — `F738-prctl-audit`,
   `F739-pivot-root-adjtimex`. Check `git branch -a` / `gh pr list` first.
2. **`sched/src/compat.rs` still blanket-EPERMs ~8 syscalls** (`init_module`,
   `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `iopl`,
   `ioperm`). EPERM lies about the reason, so root retries forever. F739
   removes `pivot_root`/`adjtimex`/`clock_adjtime`; the rest need real
   implementations per the docs/15 hard rule.
3. **`ext4/tests/e2fsck_image.rs` `include_bytes!("htree.img")`** — fixture is
   not in the repo, the sole remaining `cargo test --workspace` failure.
4. **Unexplained x86 boot wedge**: one attempt hung at ~20s guest time, both
   vCPUs spinning, no serial for 6 min on an idle box; attempt 2 passed. Not
   root-caused, rate not bounded. Data point if a sysinit spin resurfaces.
5. Timer-delivered *standard* signals carry no `si_value`/`si_overrun`
   (signal-subsystem change). `SCHED_RR`/`SCHED_BATCH` stored but not
   scheduled differently. Both disclosed as PARTIAL, not hidden.

## Traps that cost real time — now enforced, do not re-learn

- **Kernel-gated files swallow tests.** `syscalls/src/kernel_body.rs` and every
  slot file it `#[path]`-includes are `#[cfg(target_os = "oxide-kernel")]`, so
  a `#[cfg(test)] mod tests` there compiles out **silently** while cargo prints
  "ok". `314_sched_setattr.rs` shipped such a block that never ran once; five
  lanes hit it. Put decision logic in a non-gated module and confirm the test
  count goes UP.
- **boot-smoke reuses its /tmp log filenames.** A log found by timestamp can
  hold another worktree's build output entirely. Trust your own run's exit
  status and its `boot-smoke: PASS/FAIL` line — nothing else. I retracted one
  before/after claim to this, and separately read an unflushed empty log as a
  failure when the run had in fact passed.
- **Concurrent boots manufacture false failures.** A lane reported ARM "fails
  3/3" on a box running 6+ smokes; ARM was fine (PASS attempt 3). Another
  nearly filed an ARM-specific stall that was a stale branch point.
- **`cargo test --workspace` was dead** — 111 vendored-crate errors hid real
  rot, incl. glibc test modules that had **never compiled** (189 tests now
  run). Keep it green.
- **Never assert Linux behaviour from memory.** I briefed a lane that
  pselect6/ppoll do not write back the remaining timeout; `fs/select.c`
  `poll_select_finish` does `put_timespec64` — the raw syscalls do, glibc's
  wrapper hides it. The lane checked source and corrected me.

## First command next session

    cd /home/nd/oxide/kernel && git pull && gh pr list --state open \
      && python3 tools/matrix-lint.py scratch/syscall-compliance-matrix.md

Then pick the next NEEDS-AUDIT row with real userspace traffic:

    awk -F'|' '{n=$2;st=$9;gsub(/ |`/,"",n);gsub(/ |`/,"",st); \
      if(st=="NEEDS-AUDIT") printf "%s %s\n", n, $4}' \
      scratch/syscall-compliance-matrix.md | head -20

# state.md — session hand-off

Branch: `main` @ `5e03ae09e`. Clean tree, no open PRs. Both arches boot to
`basic.target` (x86 98s, ARM 115s, own runs, exit 0 — last verified at the
socket-sweep merge; subsequent merges are doc/scoping only).

## Headline

Syscall-compliance campaign against `scratch/syscall-compliance-matrix.md`.
IMPL 44 → **108**, NEEDS-AUDIT 198 → **84**, IN-PROGRESS 5 → **0**. 56 PRs. All 385
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

## Open work — in priority order

1. **Phase 3a: CPU-time `clock_nanosleep`.** Sized against the tree, not
   guessed — inventory in `scratch/interruptible-wait-plan.md` §14. CPU
   accounting, per-domain sampling, `account_cpu_tick`, restart dispatch and
   clock admission all already exist and are correct. What is missing: a
   per-task CPU-sleep deadline on the accounting tick, routing CPU clocks off
   the monotonic engine, a `RESTART_CPU_NANOSLEEP` kind, and the
   per-thread-clock EINVAL. ~200 lines across `sched`/`syscalls`. Start from
   the sizing, not from a grep.
2. **Guest differential tests** for the three 1c sites, which are the
   least-verified changes in the whole sweep (no boot path, no hosted
   coverage, source-reading only). Probes are named in the plan: `flock` under
   LOCK_EX contention with an SA_RESTART SIGALRM; `F_SETLKW` over a byte range
   plus the no-SA_RESTART EINTR case; `syslog` READ on an empty ring.
3. **PI futexes (phase 3c) — DEFERRED, do not start casually.** ~2500-3400
   lines building rt_mutex + PI inheritance from scratch. Its own project with
   its own design review.
4. **`compat.rs` still blanket-EPERMs 8 syscalls** (`init_module`,
   `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `iopl`,
   `ioperm`). EPERM lies about the reason, so root retries forever.
5. **No GNOME boot since any of this landed.** `basic.target` is not a
   desktop. The new `unshare` capability check in particular could fail a unit
   *after* `basic.target`, where smoke cannot see it.
6. Smaller, each named on its matrix row rather than hidden: blocking lease
   break missing entirely (`lease_force_break` revokes immediately); fuse's
   second killable phase; alarm-timer RTC wake (unobservable until suspend
   exists); AF_VSOCK/netlink `SO_{RCV,SND}TIMEO` (marked in-struct where the
   fields would be added).

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

## Rules earned this campaign — apply before sweeping anything

- **"Timed wait ⇒ EINTR" is socket-specific.** `sock_intr_errno` says so
  because a residual timeout cannot cross a restart. Everywhere else the
  timeout is orthogonal: `wait_event_interruptible_timeout` returns
  ERESTARTSYS on a signal whether or not a timeout was armed. `fs/locks.c`
  contains neither errno anywhere.
- **Classify per site; never sweep uniformly.** Each phase found at least one
  site that looked mechanical and was not — AF_VSOCK connect (always finite
  timeout ⇒ EINTR is correct), tty job control (ERESTARTSYS paired with
  TIF_SIGPENDING so a backgrounded read resumes after `fg`). 8 sites are on a
  do-not-touch list; moving them would be the regression.
- **Grep counts are upper bounds only.** Two phases came in at 15-vs-~30 and
  11-vs-~19. A phase exceeding its bound means the pattern was wrong — stop
  and re-derive rather than sweep the extras.
- **State what the boot is evidence *for*, not just that it passed.** tty job
  control is exercised by login/bash, so a clean boot is direct evidence;
  `flock`/`F_SETLKW`/`syslog` are not on the boot path at all, so the same
  boot is merely compatible with those changes.
- **Markers belong in the struct, not the plan file.** A conditional
  correctness that depends on a field's absence must be commented where
  someone would add that field.

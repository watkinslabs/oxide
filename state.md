# Session hand-off

## Headline
**systemd 259 PID1 passes the chroot gate on oxide** — F350-namehandle-chroot
(8e91f976, gate push bcmhtkuu9 in flight). systemd no longer freezes at
"Cannot be run in a chroot() environment."; it runs past into mount-option
probing + console/terminfo setup. Two prior F350 fixes merged: console
O_NONBLOCK (#1471), and the `xtask stats` tooling feature recovered cleanly
(#1472). Branch: F350-namehandle-chroot @ 8e91f976.

## What the chroot fix was (F350 #2)
systemd's `running_in_chroot()` does `inode_same("/proc/1/root","/")`: opens
both O_PATH, FID-probes via `name_to_handle_at`, compares handles. Two gaps:
1. `/proc/<pid>/{exe,cwd,root}` were StaticFileInode regular files ("/"), not
   symlinks → O_PATH didn't follow to real root. Now `ProcPidLinkInode` magic
   symlink (proc_links.rs) via `sched::proclink`; readdir d_type fixed too.
2. `name_to_handle_at(303)` was ENOSYS → systemd fell back + froze. Now real
   impl `kernel/src/syscalls/handle.rs`: 8-byte inode-id FID + const mount id,
   EOVERFLOW retry. `open_by_handle_at(304)` stays ENOSYS. Added Errno::Eoverflow(75).

## Diagnosis method (reuse)
Recon: temp-swap PID1→/lib/systemd/systemd in kernel/src/smoke/elf.rs (lookup
+ argv); boot NORMAL kernel x86; grep console output. Decisive bisect: inject
`SYSTEMD_IN_CHROOT=0` into PID1 env (elf.rs build_user_stack envp) → systemd
proceeded → confirmed chroot was the wall. PID1-only syscall trace at
oxide_syscall_dispatch (gate `c.vtid.load(Acquire)==1`) pinpointed getpid=1,
name_to_handle=ENOSYS×76, fstat-match-but-still-froze → handle path was the key.
ALL recon edits reverted before commit.

## Open work — NEXT GAP (after gate merges)
1. **F350 #3: next systemd freeze/wedge after chroot.** With this fix systemd
   reaches mount-option probing + `[6n` terminal query. Re-recon (PID1=systemd
   + SYSTEMD_LOG_LEVEL=debug env, NO chroot-override) to see the next stuck
   point — likely a mount (securityfs/devpts/pstore/bpf returned ENOENT in the
   env-experiment = fs types not registered; recoverable) or sd-event/target.
   Fix ONE gap per branch; iterate until a target/getty; then switch default
   PID1 to systemd.
2. Low-pri: x86 #UD→catchable-SIGILL parity (hal-x86_64/fault.rs).

## First command (next session)
Re-apply recon (elf.rs PID1=/lib/systemd/systemd + envp SYSTEMD_LOG_LEVEL=debug),
boot x86, read systemd's last log line; fix the next gap in its own branch.

## CRITICAL harness rules
- Both-arch gate: backgrounded PLAIN git push (run_in_background +
  dangerouslyDisableSandbox; `git push 2>FILE; echo PUSH_DONE rc=$? >>FILE`).
  rc=0=pass. rc=141/closed-but-PASSED → re-push SKIP_SMOKE=1. Hook gates
  kernel/*, tools/xtask/*, vendor/*.
- Boot harness: dev shell is `set -e` — guard EVERY pgrep/grep/ss/pkill with
  `|| true` or the whole command aborts with no output (lost an hour to this).
  Launch boots via run_in_background:true; poll the output file in a SEPARATE
  bg cmd; pkill -9 -f qemu-system-x86_64 only at the END. NEVER `pkill -f qemu`
  (self-kill). Clear stale port 2222/1234 before each boot.
- spec-lint clean before commit. main.rs + procfs/mod.rs hover at the 1000-line
  cap — count lines after edits, trim comments to fit. Branch per change.
- Untracked vendor/*/install-*/lib/pkgconfig — never `git add`.
- A tree-wide `cargo fmt` is NOT wanted (project uses manual alignment per
  docs/08/09). If 100s of files show formatting churn, it's an external fmt —
  stash + drop it, don't commit. (#1472 recovered the stats feature from one.)

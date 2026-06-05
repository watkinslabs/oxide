# Session hand-off

## Headline
Bug-sweep session. 7 PRs merged to main. Live-test bugs A/B/C plus new ones
found while testing (D/E/F/G/H). B + D + D-followup shipped; A needs white-box;
C/E/F/G/H tracked with findings. Merge-as-you-go cadence.

## Merged to main this session
- #1529 BUG B — mremap source-PTE leak (python import SIGSEGV) + 10 regression probes
- #1528 — commit-msg hook banning AI/tool attribution (Claude/Copilot/Codex/…)
- #1530 — `make qemu-x86{,-debug}`→GRUB (kill dead Limine target) + Linux-way
  select/poll/pselect/ppoll blocking (POLL_WAIT, park not busy-yield)
- #1531 BUG D — find/ls ENOENT recursing into subdirs: fstatat/statx/fchmodat/
  fchownat/utimensat now route through resolve_at(dirfd)
- #1532 BUG D follow-up — faccessat + unlinkat/mkdirat/symlinkat/mknodat/renameat honor dirfd
- #1533 — rebuild libpam clean (drop stale PAM_DEBUG console spam)

## OPEN BUGS (tracked, with findings)

### BUG A — no echo at bash prompt (task #6)
NOT bash (works everywhere) → oxide breaks a readline contract. Kernel tty all
verified correct (raw RX, blocking read, poll, termios, winsize, isatty, writev,
canonical echo via `cat`). readline reads each char but suppresses per-keystroke
redisplay (prompt shows, incremental doesn't). select/poll busy-poll fixed
(#1530) — echo still broken, so wait-model wasn't it. NEXT: white-box readline —
build a readline binary WITH symbols from vendor/bash sources, gdb rl_redisplay.

### BUG C — cgroup ENOTEMPTY on destroy (task #7)
systemd SIGKILLs procs then rmdir's the cgroup; rmdir races the async on_exit
removal → ENOTEMPTY. Verdict (transient vs real leak) still pending. LIKELY
shares root with BUG G. cgroup::on_exit (kernel/src/syscalls/mod.rs:318) fires
at task-exit (not reap) + notify_events_chain → IN_MODIFY on cgroup.events.

### BUG G — login respawn ~19-21s after exiting bash (task #13)  [user-emphasized]
exit→Deactivated = 0.2s (systemd notices FAST), RestartSec=1, but total ~19s.
systemd debug shows the window is cgroup work for the NEW getty: ~15 'Failed to
set memory.swap.max/pids.max/zswap/oom.group' + xattr set/remove on
/system.slice/console-getty.service. CAVEAT: systemd.log_level=debug inflates
total to 120s (console-write overhead), so it can't localize the 19s cleanly.
NEXT: non-distorting kernel trace (dtrace!/COM2 timestamps) of syscalls systemd
issues between getty-exit and getty-exec → find the slow op (suspect cgroup
setxattr / control-file write slow path). Driver: /tmp/run_respawn.py (phase-split).

### BUG E — /dev/console fchown/fchmod EINVAL (task #11)
systemd "Failed to reset TTY ownership/access mode of /dev/console to 0:5,
ignoring: Invalid argument". ConsoleInode has no set_owner/set_perm; the
fchown/fchmod path should accept it (overlay) and return 0, not EINVAL. Find the
EINVAL source for an fd-backed chardev.

### BUG F — systemd SCM_CREDENTIALS handoff (task #12)
"Received handoff timestamp message without valid credentials. Ignoring." AF_UNIX
sendmsg/recvmsg doesn't attach/deliver SCM_CREDENTIALS (ucred). Implement it.

### BUG H — rm -rf of a tmpfs dir returns rc=1 (task #14)
`rm -rf /tmp/regd` fails though mkdir/touch/mv/ls on the same /tmp path work
(path resolution fine) → tmpfs unlink/rmdir backend quirk. Orthogonal to BUG D.

### Cleanups (task #8)
libpam debug DONE (#1533). REMAINING: Limine removal for aarch64 (dead
cmd_image/cmd_qemu/check_vendor + arm Limine boot) — blocked on arm GRUB/EFI-stub
(F376 #1525, open). x86 already on GRUB.

## Env / test harness (cost hours)
- NEVER build/copy shared kernel/blobs/rootfs-x86_64.img while a qemu has it open
  — corrupts the guest. Use /tmp/rootfs-*.img copies. Driver: /tmp/oxide_drive.py.
- Boot/iterate: `cargo run -p xtask -- grub --arch x86_64 --features debug-boot`
  builds the ISO (it also launches a qemu that fails headless — ignore; ISO is built).
- `set -e` in the dev shell: guard `pkill ... || true`. Write driver .py with the
  Write tool, not heredocs.
- systemd.log_level=debug DISTORTS timing (console-write overhead) — use only for
  state-machine ordering, not wall-clock.

## First command next session
```
cd /home/nd/oxide2 && git checkout main && git pull && git log --oneline -8
# BUG G: kernel COM2/dtrace timestamp trace on the cgroup write/setxattr path,
# boot, exit bash, find the slow op in the 19s respawn window.
```

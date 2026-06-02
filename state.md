# Session hand-off

## Headline
**systemd PID1 now reaches SERVICE START** — clears cgroup setup, creates
init.scope/system.slice, runs its sd-event loop, and attempts to spawn
console-shell.service (/bin/sh): logs "Will spawn child: /bin/sh". Next gap:
the service spawn FAILS before forking (no clone/execve traced) — the exec
reason was rate-limited out of the debug log. main clean @ #1484 (+ this PR).

## Merged this session
| PR | Fix |
|----|-----|
| #1482 | /proc/<pid> reports namespace PID (init shows 1) |
| #1483 | first-light default.target (Wants=console-shell only) |
| #1484 | mkdir EEXIST + materialize /sys/fs,/sys/kernel → cgroup mkdir_p OK |
| (pending) | name_to_handle_at per-fs mount_id (fsid) + inotify read=EAGAIN/poll → systemd escapes infinite mount-walk + inotify epoll-spin, reaches service start |

## The systemd-PID1 wedge chain solved (in order)
1. cgroup root EROFS (#1484).
2. **Infinite mount-walk**: name_to_handle_at returned a CONSTANT mount_id →
   systemd's is_mount_point never finds a boundary. Fix: Inode::fsid() (per-fs
   superblock id); cgroup inodes return CGROUP2 magic; handle.rs writes
   inode.fsid() (root domain=1). [this PR]
3. **inotify epoll-spin**: inotify read() returned Ok(0)=EOF on empty queue +
   default poll()=always-readable → sd-event spun read(7)→0 forever. Fix:
   read() returns EAGAIN when empty; poll() POLLIN only when events queued.
   inotify ino base = 0x7100_0000. [this PR]
After these, systemd reaches "Will spawn child: /bin/sh".

## NEXT — service spawn (one PR each, NO HACKS)
Recon (proven): elf.rs PID1 = lookup_blob_by_path(b"/lib/systemd/systemd") +
argv [same] (load_static_blob resolves its PT_INTERP musl loader — load
systemd DIRECTLY, NOT ld-musl-as-argv0); build_user_stack envp +=
SYSTEMD_LOG_LEVEL=debug. P1 syscall trace at oxide_syscall_dispatch
(mod.rs ~L568) gated c.vtid==1. ALL REVERT before commit.
- console-shell.service "Will spawn child: /bin/sh" → "[FAILED] Failed to
  start". Only [P1fx] waitid traced, NO clone/fork/execve → spawn fails
  BEFORE fork. systemd uses systemd-executor (double-fork): check executor
  path resolution / cgroup-attach / stdio(TTYPath=/dev/console) setup.
- The exec failure reason was hidden: "Too many messages being logged to
  kmsg, ignoring" (systemd debug-log rate limit). To see it: drop
  SYSTEMD_LOG_LEVEL=debug → info, OR trace the exec path. THEN fix the gap.
- Likely next: systemd-executor invocation, or service cgroup (system.slice)
  attach, or the 5 unwired syscalls 142/251/252/314/315.
When systemd forks /bin/sh on console → flip default PID1 busybox→systemd
(elf.rs L639/L658) + login smoke. THEN distro: busybox→bash+coreutils,
Limine→GRUB, vim/python.

## Diagnosis recipes (proven)
- systemd-PID1 recon: see NEXT. Boot SMP=1 to halve trace volume + dodge the
  cat-smoke ("A") SMP flake.
- syscall trace: [P1nr] at dispatch gated vtid==1, klog nr+a0; decode openat
  path by reading cstr from a1 (257/332/303) or a0 (2). Narrow to fork/exec
  (56/57/59/322/435/247) once you know the phase. NEVER klog in sys_openat.
- fd identity: in sys_read gate vtid==1 && fd==N, klog file.inode().ino() +
  result, cap via a static AtomicU32. Found the inotify spin (ino 0x71000000,
  read→0).
- systemd[1] debug log lines split across 3 output lines; grep single tokens.
  Debug log is RATE-LIMITED ("Too many messages...kmsg") — it drops the very
  error you want; lower the log level to see late failures.

## CRITICAL harness rules
- dev shell `set -e`: a trailing grep/pgrep returning 1 aborts the whole
  compound → run `make ... > file` ALONE. Recurring "no file created" cause.
- ALWAYS `pkill -9 -f qemu-system 2>/dev/null || true; sleep 2` BEFORE a boot.
  NEVER put `&` inside a run_in_background make (breaks the redirect).
- A wedged systemd recon explodes the log to MILLIONS of lines — kill early,
  analyse a slice; bound pollers with a line-count break.
- Gate: `git push --dry-run origin <branch>` = both-arch boot-smoke; PASS →
  SKIP_SMOKE=1 push + `gh pr merge --merge --delete-branch=true`.
- spec-lint clean; default PID1 still busybox (login smoke green); flip to
  systemd only at a shell/login prompt.

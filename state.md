# Session hand-off

## Headline
**systemd as PID1 boots oxide to an interactive `sh-5.2#` shell on
/dev/console.** The entire systemd-PID1 bring-up chain is fixed — cgroup
setup, event loop, unit transaction, service fork, and the full exec-setup
cascade. Verified under a systemd-PID1 recon boot (x86). main @ #1486.
Default PID1 is STILL busybox (login smoke green); the systemd path is
recon-only until verified interactive on BOTH arches + a login smoke exists.

## Merged this session (6 PRs)
| PR | Fix |
|----|-----|
| #1482 | /proc/<pid> stat+status report namespace PID (init shows 1) |
| #1483 | first-light default.target (Wants=console-shell, no sysinit chain) |
| #1484 | mkdir EEXIST + materialize /sys/fs,/sys/kernel → cgroup mkdir_p OK |
| #1485 | per-fs name_to_handle_at mount_id (Inode::fsid) + inotify EAGAIN/poll → escapes mount-walk + epoll spin |
| #1486 | service exec-setup syscalls: PR_CAP_AMBIENT, keyctl SETPERM/LINK, capget/capset vpid, PR_SET/GET_SECUREBITS → /bin/sh runs |

## The systemd-PID1 wedge chain solved (in order)
1. cgroup root EROFS (#1484: mkdir EEXIST + /sys/fs dirs).
2. Infinite mount-walk: constant name_to_handle_at mount_id (#1485: Inode::fsid).
3. inotify epoll-spin: read=Ok(0) + poll always-ready (#1485: EAGAIN + poll).
4. Service spawn exec-setup steps, each EINVAL/ENOTSUP/ESRCH (#1486):
   AMBIENT (PR_CAP_AMBIENT) → KEYRING (keyctl SETPERM/LINK) →
   CAPABILITIES (capget/capset vpid≠tid) → SECUREBITS (PR_SET_SECUREBITS).
Result: `Started Console Shell` + `sh-5.2#` prompt.

## NEXT (one PR each, NO HACKS, careful)
1. **Verify systemd→shell on aarch64** (lockstep). The x86 milestone used
   elf.rs recon (PID1=/lib/systemd/systemd). Confirm the arm PID1 spawn
   path reaches sh too; fix any arm-specific exec gap. (Recon, not a PR
   unless a gap is found.)
2. **Flip default PID1 busybox→systemd** — BIG/risky. The login smoke
   (tools/boot-smoke.sh) waits for `oxide login:` but console-shell gives
   `sh-5.2#`. So flipping needs EITHER (a) a getty/login service in the
   systemd unit tree (vendor/systemd/build.sh) that prints `oxide login:`,
   OR (b) update the smoke success marker. Do NOT flip until systemd is
   reliably interactive on BOTH arches. Own branch, careful verification.
3. Distro track: /bin/sh is already bash 5.2; extend to GNU coreutils;
   Limine→GRUB; vim/python.

## systemd-PID1 recon recipe (proven)
- elf.rs: init_blob = lookup_blob_by_path(b"/lib/systemd/systemd") (load
  DIRECTLY — load_static_blob resolves its PT_INTERP musl loader; NOT
  ld-musl-as-argv0), argv=[same]; build_user_stack envp +=
  SYSTEMD_LOG_LEVEL=info (info dodges the kmsg rate-limit that hides late
  errors at debug). [P1fx] fork/exec trace at oxide_syscall_dispatch
  (mod.rs ~L568) gated c.vtid==1. ALL recon REVERT before commit:
  git checkout -- kernel/src/smoke/elf.rs kernel/src/syscalls/mod.rs.
- Boot SMP=1 (halves trace volume; the cat-smoke 'A' can wedge pre-PID1
  intermittently — kill+reboot if frozen at 'A').
- grep boot log with -a (binary escape codes); systemd[1] log lines split
  across 3 output lines — grep single tokens. Look for `Failed at step X`
  (exec-setup gap) + `sh-5.2#` (shell reached).
- fd identity: in sys_read gate vtid==1 && fd==N, klog file.inode().ino().

## CRITICAL harness rules
- dev shell `set -e`: a pkill/grep/[test] prefix in a compound aborts it →
  the `make ... > file` never runs (empty file). Run boots ALONE:
  bare `make SMP=1 qemu-x86 > /tmp/rN.txt 2>&1` run_in_background; clear
  stale qemu in a SEPARATE `pkill -9 -f qemu-system 2>/dev/null||true;
  sleep 2` first; guard EVERY grep/pgrep/pkill/[test] with ||true.
- NO foreground sleep — use run_in_background until-loops with a line-count
  break (a wedged systemd recon explodes the log to millions of lines).
- Never put `&` inside a run_in_background make (breaks the redirect).
- Gate: `git push --dry-run origin <branch>` = both-arch boot-smoke; arm
  can flake (re-run once / `make qemu-arm` to confirm before calling it a
  regression). PASS → SKIP_SMOKE=1 push + `gh pr merge --merge
  --delete-branch=true` (NO separate git branch -D).
- NEVER klog in sys_openat (wedges SMP). spec-lint clean; sched/fs/procfs
  files near the 1000-line cap; branch per change; explicit git add; never
  add vendor/*/install-*/lib/pkgconfig; tree-wide cargo fmt NOT wanted.
- The `cred`/`keyring`/`prctl` syscall handlers are cfg(oxide-kernel) — NOT
  hosted-testable (need current() + user memory); verify via the boot.

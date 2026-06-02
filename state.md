# Session hand-off

## Headline
**OXIDE boots systemd as its DEFAULT init (PID 1) to `oxide login:` on BOTH
x86_64 AND aarch64** (keystone, done+merged), with a GNU userland: /bin now
hosts GNU coreutils + grep/sed/awk/find/tar + less/vi(vim)/gzip/gunzip (NOT
busybox). 18 PRs this session (#1482-#1497). main @ #1497, tree clean.

## DONE this session
- Full systemd bring-up → default PID1 → login, both arches (#1482-#1491,
  B22 arm dynamic-loader entry, F357 flip).
- xtask main.rs split into rootfs.rs (#1495, was at cap).
- busybox→GNU /bin migration: coreutils (#1493), grep/sed/awk/find/tar
  (#1496), less/vi/gzip/gunzip (#1497). Largely complete — remaining busybox
  /bin entries (ash/hush/echo/test/which/clear/more/xxd/hostname/dmesg/net
  tools) have no separate GNU package; leave them.

## NEXT (larger tracks, one PR each, both-arch gate)
1. **systemd full sysinit chain** — default.target is first-light
   (Wants=console-getty, DefaultDependencies=no). Expand to real distro init:
   stage unit fragments (systemd-tmpfiles-setup, sysinit/basic/multi-user
   deps, an fstab mount) in vendor/systemd/build.sh + install-{x86_64,
   aarch64} + tools/xtask/src/l2_deps.rs; keep boot-smoke green (console-getty
   prints `oxide login:`). Verify via the systemd-default boot; fix new
   `Failed at step`/missing-unit gaps Linux-correct.
2. **Limine→GRUB** (x86; vendor/limine present — add a grub recipe + switch
   tools/xtask image_qemu image build). LARGE.
3. **python** cross-build. LARGE.
4. DEFERRED: interactive-login-completion refinement (flaky — x86 cat-smoke
   SMP wedge; needs SMP=1 boot + serial drive; session/foreground-pgid under
   systemd, NOT the tty since /dev/console==ttyS0==vt0).

NOTE: tools/xtask/src/rootfs.rs is at ~998 lines (near 1000-cap) — compact or
sub-split BEFORE adding more to it.

## Merged this session (the full systemd bring-up)
| PR | What |
|----|------|
| #1482 | /proc/<pid> namespace PID (init shows 1) |
| #1483 | first-light default.target |
| #1484 | mkdir EEXIST + /sys/fs,/sys/kernel dirs (cgroup mkdir_p) |
| #1485 | per-fs name_to_handle_at mount_id (Inode::fsid) + inotify EAGAIN/poll |
| #1486 | service exec-setup syscalls: PR_CAP_AMBIENT, keyctl SETPERM/LINK, capget/capset vpid, PR_SET/GET_SECUREBITS |
| #1489 | console-getty.service → `oxide login:` (getty/login path) |
| #1490 | B22: arm PID1 spawn enters dynamic-loader (user_ip) not program entry |
| #1491 | F357: FLIP default PID1 busybox→systemd (both arches) |
(+ #1487/#1488 state docs)

## The systemd wedge chain solved (in order)
cgroup EROFS (#1484) → infinite mount-walk from constant mount_id (#1485) →
inotify epoll-spin (#1485) → exec-setup steps AMBIENT/KEYRING/CAPABILITIES/
SECUREBITS (#1486) → arm dynamic-loader entry (#1490 B22, the arm-only
blocker, found via targeted klog tracing not blind boots) → flip (#1491).
Both arches reach `oxide login:` in the boot-smoke (x86 35s, arm 40s).

## OPEN (refinement, NOT blocking — keystone is merged+green)
**Interactive login completion under systemd UNVERIFIED.** tools/boot-smoke-
login.sh (types alice/swordfish → checks id=uid=1000) STALLS after the
`oxide login:` prompt. Could not capture the post-`alice` behavior — 3
harness runs blocked by mechanics (orphaned redirects from `&`/pkill-prefix
compounds) + the x86 cat-smoke SMP flake (boot spins 100% CPU at "A" under
default `make qemu-x86`=SMP2). KEY: /dev/console == /dev/ttyS0 == same
ConsoleInode vt0 (devfs.rs:37/40) → NOT the tty. So it's session/job-control:
foreground-pgid / controlling-tty (TIOCSCTTY/TIOCSPGRP) handover under
systemd's already-setsid'd service session vs busybox-init's getty child.
NEXT-SESSION login diag: run the harness with KEEP_LOG=/path and SMP=1
(`SMOKE_TIMEOUT=300` env, but the harness calls `make qemu-x86` — may need to
pass SMP=1 via the Makefile/xtask or dodge the cat-smoke flake), read
/tmp/login_full.log around the prompt; trace TIOCSCTTY/foreground_pgid in
crates/kernel/tty + the console park/wake path (park_current_for_tty_vt in
kernel/src/dev/console.rs). One PR, both-arch gate. The merged keystone is
fine regardless (prompt appears, boot-smoke green).

## NEXT roadmap (one PR each, both-arch gate)
1. Login-completion fix (above) — makes the milestone fully usable.
2. **Distro userland**: rip busybox → GNU coreutils. Vendor + cross-build
   static-musl via the xtask pkg system (study how bash F216 / vim F251 /
   nano F255 were vendored: vendor/<pkg>/build.sh + install-{x86_64,aarch64}
   + tools/xtask l2_deps staging). Stage, switch /bin applet symlinks
   busybox→coreutils, verify under the booted system. One program/batch/PR.
3. Expand systemd unit tree to a real sysinit chain (mount -a, tmpfiles).
4. Limine→GRUB bootloader. 5. vim/python cross-built.

## CRITICAL harness rules
- dev shell `set -e`: a pkill/grep/[test] prefix in a compound aborts it AND
  a trailing `&` orphans the redirect (qemu alive, EMPTY file). Run boots/
  harnesses ALONE: bare `make ... > /tmp/rN.txt 2>&1` run_in_background;
  pkill SEPARATELY first (`pkill -9 -f qemu-system 2>/dev/null||true; sleep
  2`); guard EVERY grep/pgrep/pkill/[test] with ||true.
- Stale qemu squats :2222 → 'Could not set up host forwarding'. Always clear.
- NO foreground sleep (bg until-loops + line-count break; qemu %cpu: 0%=idle/
  wedged, 100%=busy/spinning/slow-TCG). arm TCG slow (qemu MCP too slow);
  targeted klog traces work on arm. NEVER klog in sys_openat.
- x86 cat-smoke ("A") can wedge under SMP=2 (spins 100% CPU pre-PID1) — boot
  SMP=1 for systemd tests, or retry.
- systemd[1] log lines split across 3 output lines; grep -a (binary escapes).
- Gate: `git push --dry-run origin <branch>` = both-arch boot-smoke; arm
  flakes → re-run. PASS → SKIP_SMOKE=1 push + `gh pr merge --merge
  --delete-branch=true` (NO separate git branch -D).
- Default PID1 is now systemd (no recon needed to test it). spec-lint clean;
  files <1000 lines; branch per change; explicit git add; never add
  vendor/*/install-*/lib/pkgconfig; tree-wide cargo fmt NOT wanted.

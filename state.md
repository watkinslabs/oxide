# Session hand-off

## Headline
**systemd as PID1 boots oxide to an interactive `sh-5.2#` (bash) shell on
x86** — the entire systemd bring-up chain is fixed. 7 PRs merged this
session (#1482-#1487). main @ #1487. arm parity is the open blocker before
flipping default PID1. Default PID1 stays busybox (login smoke green).

## Merged this session (7 PRs)
| PR | Fix |
|----|-----|
| #1482 | /proc/<pid> reports namespace PID (init shows 1) |
| #1483 | first-light default.target (Wants=console-shell only) |
| #1484 | mkdir EEXIST + materialize /sys/fs,/sys/kernel → cgroup mkdir_p |
| #1485 | per-fs name_to_handle_at mount_id (Inode::fsid) + inotify EAGAIN/poll |
| #1486 | service exec-setup syscalls: PR_CAP_AMBIENT, keyctl SETPERM/LINK, capget/capset vpid, PR_SET/GET_SECUREBITS → /bin/sh runs |
| #1487 | state doc |

## systemd-PID1 wedge chain solved (x86, in order)
cgroup EROFS (#1484) → infinite mount-walk from constant mount_id (#1485
fsid) → inotify epoll-spin (#1485) → exec-setup steps each EINVAL/ENOTSUP/
ESRCH: AMBIENT→KEYRING→CAPABILITIES→SECUREBITS (#1486). Result: `Started
Console Shell` + `sh-5.2#` prompt on /dev/console.

## OPEN BLOCKER — arm systemd parity (critical path to PID1 flip)
3 arm systemd-recon boots (elf_arm.rs PID1=/lib/systemd/systemd) all WEDGED
at "keymap loaded", BEFORE the "init-fork-exec works" smoke (which runs
before PID1 in elf_arm.rs:270). qemu idle at ~0-1% CPU = halted, not slow.
- The wedge is at a spot my elf_arm change does NOT touch (pre-PID1 smoke),
  and busybox arm boots fine (gate green, ~38s) → likely the INTERMITTENT
  arm early-smoke wedge (cf. CAT-smoke wedge memory), NOT systemd. But not
  confirmed — could be systemd-on-arm parking silently before any output.
- arm systemd binary IS present + correct (aarch64 PIE, ld-musl-aarch64).
- exec-setup syscalls (#1486) are arch-neutral → should cover arm too.
- NEXT (do NOT blind-boot arm 13min at a time): use the qemu MCP
  (mcp__qemu__qemu_start arch=aarch64, qemu_break/qemu_backtrace/qemu_regs)
  to inspect WHERE the boot parks after "keymap loaded" — is it the smoke
  ELF spawn, spawn_init_from_rootfs_arm (systemd load), or a console/timer
  block? OR first reproduce the early-smoke wedge with busybox (re-boot arm
  clean a few times) to confirm it's the known flake. If it's the flake,
  fix THAT (separate from systemd); if systemd-on-arm parks, inspect the
  park point.

## NEXT increments (one PR each, NO HACKS)
1. **Fix arm boot to reach systemd→shell** (above) — lockstep gate.
2. **getty/login unit** (x86-verifiable now): rootfs HAS /sbin/agetty,
   /sbin/getty, /bin/login, /usr/bin/login (busybox applets). Replace/add a
   console-getty.service in vendor/systemd/build.sh that runs agetty on
   /dev/console → prints `oxide login:` (matches the boot-smoke marker) →
   login → shell. Verify via x86 systemd recon; watch for getty exec gaps
   (TIOCSCTTY/setsid/vhangup). Prereq for the flip.
3. **Flip default PID1 busybox→systemd** — only after 1+2 work on BOTH
   arches. elf.rs ~L639/L658 + elf_arm.rs ~L310/L397 → /lib/systemd/systemd;
   update boot-smoke marker. Dedicated branch, full both-arch gate.
4. Distro: GNU coreutils (beyond bash); Limine→GRUB; vim/python.

## systemd-PID1 recon recipe (proven, x86)
elf.rs init_blob=lookup_blob_by_path(b"/lib/systemd/systemd") (load
DIRECTLY — load_static_blob resolves PT_INTERP musl loader; NOT
ld-musl-as-argv0), argv=[same], build_user_stack envp +=
SYSTEMD_LOG_LEVEL=info (info dodges the kmsg rate-limit that hides late
errors). REVERT before commit: git checkout -- kernel/src/smoke/elf.rs
kernel/src/smoke/elf_arm.rs kernel/src/syscalls/mod.rs. Boot SMP=1. grep -a
the log (binary escape codes); systemd[1] lines split across 3 output
lines; `Failed at step X`=exec-setup gap, `sh-5.2#`=shell reached.
**The [P1fx]/[P1nr] every-syscall trace may interact badly with arm — use
narrow traces or the qemu MCP on arm.**

## CRITICAL harness rules
- dev shell `set -e`: a pkill/grep/[test] prefix aborts the compound → the
  `make ... > file` never runs (empty file). Run boots ALONE; pkill
  SEPARATELY first (`pkill -9 -f qemu-system 2>/dev/null||true; sleep 2`);
  guard EVERY grep/pgrep/pkill/[test] with ||true.
- NO foreground sleep — run_in_background until-loops with a line-count
  break (wedged systemd recon explodes the log). Check qemu %cpu to tell
  wedge (idle) from slow-TCG (busy). Never put `&` inside a bg make.
- Gate: `git push --dry-run origin <branch>` = both-arch boot-smoke; arm
  flakes — re-run / `make qemu-arm` before calling a regression. PASS →
  SKIP_SMOKE=1 push + `gh pr merge --merge --delete-branch=true` (NO branch -D).
- NEVER klog in sys_openat. spec-lint clean; files <1000 lines; branch per
  change; explicit git add; never add vendor/*/install-*/lib/pkgconfig.
- cred/keyring/prctl handlers are cfg(oxide-kernel) — NOT hosted-testable;
  verify via boot.

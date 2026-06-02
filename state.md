# Session hand-off

## Headline
**systemd as PID1 boots oxide to `oxide login:` on BOTH x86 AND aarch64.**
The entire systemd bring-up chain is fixed, including a real getty/login
path, on both arches. 10 PRs merged (#1482-#1489 + B22). The default-PID1
flip (busybox→systemd) is now UNBLOCKED — that's the next PR (F357).
Default PID1 currently still busybox.

## arm-systemd root cause (B22) — FIXED
The arm PID1 spawn (elf_arm.rs) entered at `img.entry` (the program e_entry),
but a DYNAMIC init (systemd → ld-musl-aarch64) must enter at the INTERP/
loader entry = `img.user_ip()`. Entering the unrelocated program entry made
systemd fault before its first syscall (0 syscalls, kernel idle). Static
busybox has no interp so entry==user_ip → it worked, masking the bug. x86
already used user_ip(). One-line fix; arm now reaches `oxide login:`.
Localized via targeted klog traces (SI-*/ARM-* markers + a capped vtid==1
syscall trace), NOT blind boots — the qemu MCP arm boot was too slow.

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
3 arm systemd-recon boots (elf_arm.rs PID1=/lib/systemd/systemd, with AND
without the [P1fx] trace) all WEDGED at "keymap loaded", qemu idle ~0% CPU.
A CLEAN busybox arm boot (no recon) WORKS: init-fork-exec works / sem_smoke
PASS / hello-from-dyn / `oxide login:` in 38s, qemu parked at login. So:
- NOT the early-smoke flake — the smokes run fine on clean arm.
- The wedge CORRELATES with the systemd-recon (elf_arm init blob = systemd),
  yet that code (spawn_init_from_rootfs_arm, elf_arm.rs:303) runs AFTER the
  smokes — so a wedge at "keymap" (before the smokes) is mechanistically
  puzzling. Possible: (i) the 3 recon boots hit a real-but-frequent flake;
  (ii) loading the 308KB dynamic systemd blob early perturbs timing/memory;
  (iii) something in the rootfs/build differs. arm systemd binary IS valid
  (aarch64 PIE, ld-musl-aarch64). exec-setup syscalls (#1486) are arch-neutral.
- NEXT (do NOT blind-boot arm — 4 boots already): use the qemu MCP
  (mcp__qemu__qemu_start arch=aarch64; let it reach the wedge; qemu_interrupt
  + qemu_backtrace + qemu_regs) to see EXACTLY where the CPU parks after
  "keymap loaded" with the systemd recon applied — that pinpoints whether
  it's the smoke ELF, the systemd load, or a console/timer block. This is
  the right tool vs. blind 13-min TCG boots.

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

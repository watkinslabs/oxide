# Handoff — console+desktop = one sysinit stall (multi-bug); 4 fixes merged

## Merged this session (main a0962d5e)
- **F696** ext4 read-verify completion (extent-block/dirent-tail/bitmap csum).
- **B677** AF_UNIX nonblocking read → EAGAIN (was blocking; console2.md suspect #1).
  Correct Linux-compat + hosted tests, but NOT the boot blocker.
- **B678** zombie-reap epoll-gen race: `enqueue_zombie` now bumps GLOBAL_EPOLL_GEN
  AFTER the zombie is in ZOMBIES (signal_child_exit's exit-time bump fires before
  the zombie is reapable → EPOLLET-suppressed reap ~45s). Code-proven; low-risk;
  NOT yet boot-verified sufficient (earlier stall blocks first).
- **D167** state handoff.

## THE reframing (correct now)
Console-login and live-gnome are the SAME problem: the graphical window is a
working fbcon/klog mirror, but **no `getty@tty1` ever runs because sysinit never
completes**. The console/VT/fbcon stack + /dev/console routing are already Linux-
correct (see console2.md "Code analysis update"). The serial `sh` prompt is the
`systemd.debug_shell=ttyS0` **debug hack** (remove for a real install), NOT a getty.
So the ONLY thing to fix is the sysinit stall.

## The sysinit stall = MULTIPLE distinct bugs (live-boot confirmed via qemu MCP)
Clean boot (features=debug-watchdog, no debug-boot flood): systemd reaches the
socket/target setup in ~2.5s, then CRAWLS ~45s per userland-touching service.
Kernel + serial debug-shell stay fully alive throughout (not hung). Two confirmed:

1. **~10s stall: tmpfiles-setup-dev-early / udev-trigger "Starting", never Finish,
   ZERO zombies present.** NOT a reap issue — the service itself is blocked on
   something (udev coldplug? a device/sysfs access? a fork child?). **UNDIAGNOSED —
   this is the current front blocker.** Next: find which task is R/D and on what.
2. **Later stall: sysusers/userwork exit → zombies unreaped ~45s** while init/userdbd
   sleep in epoll_wait. B678 targets this (reap-wake gen race). Unverified because
   #1 blocks first.

Earlier debug-boot run also showed a userdb varlink stall (tmpfiles↔userdbd,
userwork idle in ppoll) — may be same root as #1 or #2.

## /proc bugs found (real, separate, worth fixing)
- `/proc/<pid>/syscall` always returns `running` (never the blocked syscall) —
  breaks `has_zombies`-independent diagnosis. Stub/broken.
- `/proc/<pid>/comm` not updated on exec (stays `fork-child`). Cosmetic but wrong.

## qemu MCP recipe (WORKS this session — use it)
- `qemu_start(arch=x86_64, accel=kvm, features="debug-watchdog", paused=false)` —
  builds+boots; clean klog so the serial debug-shell is readable.
- Image: `../images/output/live-gnome-x86_64-root.img` is a symlink → lite (I made
  it so the MCP's default profile boots; the images repo hasn't built live-gnome).
- `qemu_run_until(pattern, timeout)`, `qemu_send_serial`, `qemu_serial(clear=True)`,
  `qemu_screen`. Serial task dump: SYSRQ_ARM=0x00 then 't' — but I couldn't send a
  raw NUL via qemu_send_serial; `/proc/sysrq-trigger` is EROFS (not wired). The
  debug-boot watchdog auto-dumps tasks (`[sysrq] task dump`) on no-progress — that's
  how I got the ST/last-syscall table. **image has NO awk, NO ps** — use /proc + sh.

## First task next session
Diagnose stall #1: `qemu_start` clean, at the ~10s stall dump task states
(comm/State/PPid via /proc, no awk) — find the R/D task and what tmpfiles-setup-dev-
early or udev-trigger is blocked on. That's the front blocker; everything else is
downstream. Then re-check B678 helps the reap stall once #1 clears.

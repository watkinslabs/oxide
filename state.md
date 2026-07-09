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
socket/target setup in ~2.5s, then CRAWLS ~45s+ per userland-touching service.
Kernel + serial debug-shell stay fully alive throughout (not hung). Confirmed:

1. **FRONT BLOCKER — `systemd-hwdb update` BUSY-SPINS in pure userspace.** At the
   ~10s stall, exactly one non-shell task is state `R`: `/proc/39 [systemd-hwdb
   update]`. `/proc/39/stat` utime≈5712 stime=0 → ~57s of USERSPACE CPU, ZERO
   kernel time, under KVM (native speed). It reads the 35 input files
   (/usr/lib/udev/hwdb.d/*.hwdb, 9.3MB, all read fine) then loops FOREVER building
   the trie — **never reaches the write phase** (no hwdb.bin temp file appears; the
   old 13.5MB /etc/udev/hwdb.bin stays read-only+untouched). In a debug-boot run it
   spun to the 90s DefaultTimeoutStartSec and systemd killed it ("Failed to start
   systemd-hwdb-update"), then the boot limped on. On real Linux this is <2s.
   → **A userspace infinite/pathological loop triggered by our env** (a libc/hwdb
   interaction over some syscall result). NOT ext4-read (inputs read correctly),
   NOT slow I/O (stime=0), NOT TCG (KVM confirmed by fast boot).
   **BLOCKED ON TOOLING:** gdb `qemu_interrupt` can't stop the guest under the 100%
   spin; `/proc/<pid>/syscall`+`wchan` are stubbed (always running/0). Need either
   userspace-symbol gdb on hwdb, or a startup syscall trace of tid=hwdb to see the
   LAST syscalls before it stops syscalling (what data/config it consumed).
2. **Later stall: sysusers/userwork exit → zombies unreaped ~45s** while init/userdbd
   sleep in epoll_wait. B678 targets this (reap-wake gen race). Unverified because
   #1 blocks first.
3. Earlier debug-boot run also showed a userdb varlink stall (tmpfiles↔userdbd,
   userwork idle in ppoll) — may be same root as #2.

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
Root-cause the `systemd-hwdb update` userspace spin (front blocker). Options:
(a) run gdb with hwdb's userspace symbols (or catch RIP by interrupting BEFORE the
spin starts — break early, single-step into the loop); (b) boot `features=debug-all`
and grep the syscall trace for hwdb's tid to see the LAST syscalls before it stops
syscalling (what it read/mmapped/configured); (c) test the hypothesis that a
specific libc call (getline/mmap/qsort/nss) returns wrong data by running a minimal
repro under the debug-shell. Once hwdb finishes, re-verify B678 clears the reap
stall and whether getty.target is reached.

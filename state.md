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
   **Perf hypotheses DISPROVEN (rigorously, via debug-shell micro-bench):**
   - register arithmetic: 50k shell iters in ~1s → NORMAL.
   - memory/CPU: 1st sha256 of 13.5MB hwdb.bin = 5s but 2nd (cached) = ~1s → the 5s
     was ext4 COLD-READ I/O, hashing itself is ~1s = NORMAL. So userspace mem/CPU is
     NOT uncached/slow; hwdb's stime=0 spin is a genuine INSTRUCTION-COUNT blowup =
     a real loop, not slowness. Manual `systemd-hwdb update` ran >200s, never
     returned → effectively infinite.
   **ROOT-CAUSE LOCALIZED (2026-07-09d): hwdb is in a `write()`-returns-0 retry
   loop.** The spin RIP `0x7ffff71af75e` = libc offset `0x6e75e` (mapping
   7ffff7141000-…, lite libc.so.6 single R+E seg @vaddr0) = the instr right AFTER
   the `syscall` in `__internal_syscall_cancel` (objdump: `6e75c: syscall / 6e75e:
   leave`). So NOT a pure-userspace loop — hwdb hammers a cancellable syscall that
   returns instantly (stime rounds to ~0). With the task dump's last_syscall=write
   nsysc=15952 → **write() returns 0 on hwdb's output fd**, so glibc's write-all
   loop `while(left){n=write();left-=n}` with n==0 spins forever. FIX = find the fd
   type hwdb writes hwdb.bin (or its stdout/pipe) to and stop write() returning 0
   for a non-zero request (must write, block, or error). CONFIRM the exact
   syscall+fd+retval with `features=debug-all` filtered to hwdb's tid, or test
   writes to the same fd type in the debug-shell. **This likely also explains the
   general boot crawl** (any service hitting the same write-0 path).
   **FULLY TRACED (2026-07-09e): hwdb makes SUCCESSFUL write() syscalls in an
   infinite loop.** [USERIP]+lastsc: tid=4135 starts `lastsc=0` (read, ~10-11s
   reading input) then LOCKS `lastsc=1` (write) for 60+s at rip 0x7ffff71af75e =
   libc `__internal_syscall_cancel` FAST-PATH post-`syscall` return (objdump). The
   write neither returns 0 (`[WRITE0]` silent) nor errors (`[WRITEERR]` silent for
   hwdb) → each write SUCCEEDS. Target is a pipe/socket DRAINED by journald (tid
   4123 wakes constantly in [WLBLK]) — no output file, no backpressure. So hwdb
   isn't blocked; it's genuinely writing forever. Most likely mechanism: the read
   phase got bad/premature-EOF data → hwdb built a CIRCULAR/corrupt trie → the
   serialization walk writes forever. **NEXT: full arg-trace** (features=debug-all,
   filter hwdb tid) to see write(fd,buf,len) target + the read() that preceded it
   (did a read return 0 early / wrong bytes?), or read hwdb's source. Suspect the
   read/EOF path (ties to the ext4 cold-read slowness + a possible premature-EOF).
   **INCIDENTAL BUG FOUND: write to `/proc/pressure/memory` returns EINVAL(22)** for
   systemd PSI threshold setup (init + several children) — a real /proc PSI-write
   gap, separate from hwdb.
   Diagnostics landed (all debug-wakelat-gated, zero-cost off): `[USERIP]`+lastsc,
   `[WRITE0]`, `[WRITEERR]`.

   **UPDATE: NOT plain write().** Added a `[WRITE0]` trace in sys_write (Ok(0) on a
   non-zero request, debug-wakelat) — it NEVER fired while hwdb spun. So the looping
   cancellable syscall is NOT the `write` slot: it's another cancellation-point
   syscall returning instantly in a retry loop — `writev`/`ppoll`/`pselect`/
   `sendmsg`/`nanosleep`/`fsync` etc. (the task dump's `last-sysc=write` was likely
   stale). **NEXT: name the exact syscall** — boot `features=debug-watchdog,debug-
   wakelat`, at the spin read the `[sysrq] task dump` `last-sysc` column for tid=4135
   (auto-dumps on no-progress), OR add a rate-limited syscall-nr trace in the syscall
   dispatch filtered to the spinning tid. Then fix that syscall's return-0/instant
   path (must make progress, block, or error — not return a value that spins the
   glibc cancellable-syscall retry). Two reusable diagnostics landed: `[USERIP]`
   (C103) + `[WRITE0]` (this change).
   NOTE the earlier "infinite userspace loop / mem-cache / write-0" framings were
   each WRONG — corrected step by step by [USERIP]+objdump+[WRITE0] (disprove-don't-
   hack).

   **(prior localization) hwdb spins at a FIXED user RIP `0x7ffff71af75e`** for
   100+s straight — captured by a NEW `[USERIP]` sampler I added to the timer ISR
   (arch-irq lapic/dispatch.rs, gated `debug-wakelat`: reads user rip from IRQ
   frame+88, rate-limited). Boot with `features=debug-wakelat` → `[USERIP rip=...
   tid=4135 ...]` repeats the same rip = the spin site. It's in libc/libsystemd
   (0x7ffff7... region), a userspace busy-WAIT loop (NOT the vDSO — init's hot rip
   0x7ffffe71f75e is a different offset). init/journald do NOT spin (they block+wake
   every ~500ms — see [WLBLK]); only hwdb is stuck.
   **NEXT (to name the function):** boot debug-wakelat, at the spin `cat
   /proc/<hwdb-pid>/maps` (find pid via `grep -la hwdb /proc/*/cmdline`) BEFORE
   systemd kills hwdb at its 90s timeout; compute `0x7ffff71af75e - libbase`; then
   `objdump -d` that library (from ../images) at the offset. That names the exact
   busy-wait (likely a clock/futex/timeout spin) → then fix the kernel syscall/clock
   whose wrong return traps the loop.
   **Also:** init+journald block/wake on a ~500ms cadence (`[WLBLK] waited_us≈500000
   ready=1`) — looks like a 500ms poll timeout instead of event-driven wakeups;
   likely the epoll-wake latency issue (B678 area) — a SECOND contributor.

   **SEPARATE perf bug found: ext4 COLD-READ is slow (~2.7 MB/s)** — 13.5MB took 5s
   cold, ~1s cached. Contributes to the general boot crawl (every service reads
   files cold). Real ext4 (goal-2) perf item; not the hwdb loop but stacks with it.
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

# console2 — graphical console is a klog mirror, not a real console. SOW.

Supersedes the "blank window" framing in `console.md` (that was written before we
watched a live boot). Scope: make the virtio-gpu window a **real, interactive
Linux console** (login you can type into), with serial as the *secondary* aid —
not the other way around. No hacks.

## What the user observes (ground truth)

- The GTK/virtio-gpu window shows kernel boot text, keeps scrolling **kernel log**
  during userland, and updates live — running a command on the **serial** shell
  makes that command's **kernel debug traces appear in the window**. So the window
  is NOT frozen and fbcon scanout works.
- All *interactive* work happens on **serial**: the user presses Enter and gets a
  root prompt immediately (`debug-shell.service`, `systemd.debug_shell=ttyS0`).
- The window never shows a **login prompt**, never accepts **keyboard input**, and
  never hosts a **shell** — it is a passive kernel-log display.

## What that means (console-level root cause)

The window is fed ONLY by the klog aux sink (`drv-virtio-gpu/.../scanout.rs:247`
→ fbcon). It renders `/dev/kmsg`-class output. It is **not** hosting a tty session
because **nothing runs an interactive tty on the VT**:

- The only interactive shell is `debug-shell.service`, nailed to **ttyS0** (serial).
- `getty@tty1` (the window login) **never starts** — `getty.target` is gated behind
  `sysinit.target`, and the boot appears to stall in sysinit before it. Treat the
  userdbd/tmpfiles varlink story in `poll.md` as the leading hypothesis, not as a
  proven root cause until a fresh task/fd trace pins it.
- So the window shows klog because klog is the only thing writing to fbcon; the VT
  side of fbcon (`/dev/tty1`) has no writer.

This is NOT the same as console.md's G1 (scanout) — scanout works. It is a
combination of **G2 (no getty reaches the VT)** plus a **console-role inversion**
(serial is primary/interactive; the window is a log sink).

## Verified facts (live MCP boot, x86_64, this session)

| # | Fact | Evidence |
|---|---|---|
| V1 | fbcon scanout works; window renders live text | screendump shows systemd `[20.9xx]` klog lines; user sees traces update on serial activity |
| V2 | cmdline is `console=ttyS0,115200 console=tty0` | `tools/xtask/src/image_qemu/x86_64.rs:23` |
| V3 | `/dev/console` (5:1) routes by `preferred_console()` → `Vt(0)` for this cmdline | `console/src/vt_console.rs:154-188`; `cmdline/src/lib.rs:192` test |
| V4 | Only interactive shell is `debug-shell` on ttyS0 (early) | serial gives instant root prompt; boot log `debug-shell.service … /dev/ttyS0` |
| V5 | Boot stalls in sysinit before `getty.target` | live boot wedges after `graphical.target` queued; no getty starts |
| V6 | virtio-keyboard + fg-VT ldisc input path exists in kernel | `console.md §3`; `drv-virtio-input/.../key_event.rs:90` → fg VT `receive_from_driver` |

## Whole-boot code/image audit — 2026-07-09

Scope: source + packed-image audit only. Prior boot notes are hints, not
authority. Findings below are from code paths and the live-gnome image content in
this tree.

### Boot path in this repo

1. `make qemu-x86`/`xtask grub` builds a kernel with `debug-boot`, copies the
   `live-gnome` root image from `../images/output`, and boots GRUB with:
   `root=/dev/oxide0 rw quiet console=ttyS0,115200 console=tty0
   systemd.debug_shell=ttyS0` plus several service masks.
2. QEMU exposes root/home disks by virtio-blk serials `oxide-root` and
   `oxide-home`; `kmain/rootfs.rs` mounts those, creates `/dev`, `/proc`, `/sys`,
   cgroup, `/tmp`, `/run`, `/dev/shm`, and then hands off to PID1.
3. PID1 is selected from `/init`, `/lib/systemd/systemd`, `/sbin/init`; fd
   0/1/2 are installed from `/dev/console` before userland runs. With the current
   cmdline, kernel console preference says the last console wins: `/dev/console`
   should be VT/tty0, while the serial debug shell is an extra escape hatch.
4. systemd's image graph gates the visible login behind early boot services:
   `basic.target` requires `sysinit.target`; `getty.target` and `getty@tty1`
   come later. A stall before `sysinit.target` makes the window look like a
   console problem even when the framebuffer and VT driver are alive.

### What the image proves

- `getty@tty1` is enabled in the image:
  `/etc/systemd/system/getty.target.wants/getty@tty1.service` points at the
  template unit. So the missing login is not an obvious image omission.
- `getty@.service` has `ConditionPathExists=/dev/tty0`; the kernel creates the
  console/tty device side early, so this condition should be checked in a fresh
  boot trace rather than assumed false.
- `systemd-userdbd.socket` is enabled under `sockets.target` and listens on
  `/run/systemd/userdb/io.systemd.Multiplexer`.
- `systemd-userdbd.service` is ordered `Before=sysinit.target`,
  `DefaultDependencies=no`, `Type=notify`, and has heavy sandboxing
  (`PrivateDevices=yes`, `ProtectProc=invisible`, `ProtectSystem=strict`,
  restricted address families).
- tmpfiles has three sysinit-frontier units:
  `systemd-tmpfiles-setup-dev-early.service`,
  `systemd-tmpfiles-setup-dev.service`, and
  `systemd-tmpfiles-setup.service`, all ordered before `sysinit.target`.
- `/etc/nsswitch.conf` resolves `passwd`, `shadow`, `gshadow`, and `group`
  through `systemd`; `group` uses `files [SUCCESS=merge] systemd`. That means a
  local group hit can still ask userdbd for merge data.
- tmpfiles rules under `/dev` name groups such as `audio`, `disk`, and `kvm`.
  Therefore "tmpfiles touches `/dev`, NSS calls systemd-userdbd, userdbd is
  socket-activated before sysinit" is a plausible boot path from image content,
  not just a log-story.

### Corrected AF_UNIX read finding

Do not chase the old "AF_UNIX `O_NONBLOCK` read blocks" finding as an open bug in
the current tree. `crates/kernel/net/src/sock/io.rs` now snapshots `SockKind` and
handles `SockKind::Unix` and `SockKind::UnixMsgPair` directly in
`read_nonblock()`:

- queued data is copied immediately;
- empty + peer EOF returns `Ok(0)`;
- empty + open peer returns `EAGAIN`;
- it no longer falls through to the blocking `read()` path for AF_UNIX streams.

The test module in that file also covers empty-open `EAGAIN`, available data,
peer-close EOF, and drain-then-EOF behavior. This may have been a real prior
sysinit blocker, but the current boot analysis must verify whether the frontier
moved after this fix.

### Remaining kernel risks in the sysinit path

- Blocking AF_UNIX `recvmsg` still uses `tick_yield()` in some paths instead of
  the same waitlist model as stream `read()`. Nonblocking `recvmsg` returns
  `EAGAIN` correctly, so this is a scheduler/latency/correctness smell, not the
  same closed bug as `read_nonblock()`.
- Epoll has generation support for `EPOLLET`, including a global generation bump,
  but the subscription model is still fragile: `ADD` subscribes by `ep.id`,
  `MOD` changes the entry without refreshing the subscriber mask, `DEL`
  unsubscribes by `ep.id`, and `EPOLLEXCLUSIVE` is not wired through
  `epoll_ctl`. Complex sd-event loops can trip this class.
- AF_UNIX listener readiness is manually wired:
  `UnixRegistry::connect()` pushes `accept_q`, wakes blocking `accept()`, then
  notifies listener subscribers. That is plausible, but it is not yet proven
  equivalent to Linux's `poll_wait()` model under all races.
- The current smoke marker is `Reached target basic.target`; the script comment
  explicitly says the glibc/systemd image does not print serial `oxide login:`.
  Passing this smoke proves sysinit/sockets/timers progressed to `basic.target`;
  it does not prove getty, logind, gdm, graphics, or keyboard login.

### Why boot is a recurring problem

`live-gnome` is not one boot test. It is a dense Linux compatibility test spanning
ELF, VFS, ext4, procfs/sysfs/devfs, cgroups, namespaces, signals, futexes, AF_UNIX,
netlink, epoll, timerfd/signalfd/pidfd, service sandboxing, udev/logind, DRM, and
VT/fbcon. Fixing one frontier often exposes the next. That is why "the boot is
broken" is too vague to be actionable; every run needs an exact first-missing
milestone.

The other recurring trap is stale measurement: the repo has explicit warnings
that `xtask kernel` alone does not export `target/artifacts`, imagectl can boot
the main tree instead of a worktree, and single boots can lie when the failure is
intermittent. A boot claim is only useful when the kernel artifact, image, marker,
and first stalled task are recorded together.

### Boot-frontier map to use from now on

Use these markers instead of generic "boot works/broken":

| Frontier | Marker | Meaning |
|---|---|---|
| B0 | kernel selects and execs PID1 | kernel/device/rootfs handoff works |
| B1 | systemd parses units and starts early jobs | ELF, mmap, procfs basics work |
| B2 | `sockets.target` jobs active | AF_UNIX socket activation path begins |
| B3 | tmpfiles-dev-early exits | `/dev` tmpfiles + NSS/group lookup survived |
| B4 | `Reached target sysinit.target` | early service graph completed |
| B5 | `Reached target basic.target` | current smoke marker; still not login |
| B6 | `Reached target getty.target` / `getty@tty1` started | VT login can appear |
| B7 | multi-user/graphical target reached | service graph is mostly complete |
| B8 | logind/gdm/seat0 graphical | desktop path, DRM/input/session stack |

### Recommended next diagnostic

Run one instrumented boot, not another blind boot loop, and identify the first
missing frontier above. At the stall, capture task states/syscalls via serial
debug shell or sysrq task dumps.

If the frontier is still tmpfiles/userdbd, trace only these calls first:
`epoll_wait`, `accept4`, `read`, `readv`, `recvmsg`, `sendmsg`, `poll/ppoll`,
`futex`, task state, fd flags, and AF_UNIX peer/listener identity. Since
`read_nonblock()` is fixed in this tree, the question is now whether userdbd is
blocked in epoll/listener readiness, blocking recv/yield behavior, notify/futex,
or a different syscall entirely.

If the frontier has moved to journal flush, udev/logind, or graphics, stop
debugging AF_UNIX as the primary suspect and capture the blocked task's syscall
and stack before forming the next hypothesis.

## Linux reference (what "correct" is)

`console=ttyS0 console=tty0` → last wins → `/dev/console` = `tty0` = the window.
- `getty@tty1` runs the **login in the window**; user types on the (virtio) keyboard,
  N_TTY echoes on fbcon.
- `serial-getty@ttyS0` runs a login on **serial** (secondary).
- systemd PID1 status → `/dev/console` = the window.
- `debug-shell` (if enabled) is an extra serial root shell for debugging only.

Net: the **window is the primary interactive console**; serial is a convenience.

## Statement of Work (ordered; each item has an acceptance test)

**SOW-1 — Unblock sysinit so `getty.target` is reached. [PREREQUISITE, hardest]**
The window can't host a login until `getty@tty1` starts, and it won't until sysinit
completes. Current code/image audit says to classify the first missing boot
frontier, then inspect the exact stalled task/syscall. If the frontier is still
tmpfiles/userdbd, focus on AF_UNIX epoll/listener readiness, blocking
recvmsg/wait semantics, and futex/notify behavior. Do not reopen AF_UNIX
`O_NONBLOCK` stream `read(2)` as the leading bug unless a fresh trace contradicts
the current `read_nonblock()` implementation and tests.
- *Accept:* live boot reaches `Reached target getty.target` on serial; no ~9.8s wedge.

**SOW-2 — `getty@tty1` runs and renders a login in the window.**
Ensure the image starts `getty@tty1` on the VT (autovt/getty.target wiring) and its
`login:` prompt renders on fbcon tty1, with tty1 as the foreground VT.
- *Accept:* screendump shows `oxide login:` in the window (not just klog).

**SOW-3 — Keyboard input drives the window's tty (type + echo).**
virtio-keyboard EV_KEY → fg-VT N_TTY → echo on fbcon; login accepts typed username.
- *Accept:* `qemu_send_*` keyboard (or MCP) into the window logs in; typed chars echo
  on the window, not serial.

**SOW-4 — Console roles correct: window primary, serial secondary.**
`serial-getty@ttyS0` provides the serial login; `debug-shell` stays debug-only (or is
dropped for "normal install" feel). systemd PID1 status shows in the window
(`/dev/console` = tty0). Confirm the VT render path carries `/dev/console` writes to
fbcon (not only the klog aux sink) so a login prompt + status are visible without
debug klog.
- *Accept:* with `quiet` and NO debug features, the window shows systemd status +
  login; serial shows the serial-getty login; the two are independent.

**SOW-5 — Polish (console.md G3–G6): `console=` baud reprogram, VTIME, data-driven
printk console set, stale doc.** Non-blocking.

## Open verifications to do FIRST (no guessing)

1. **VT vs klog on the window:** boot with `quiet`, NO debug features; at userland,
   does the window show systemd's `/dev/console` (VT) output, or does it go quiet
   because only klog feeds fbcon? Determines whether SOW-4 needs a `/dev/console`→VT
   render fix or just getty. (This session's window output was klog under
   `debug-boot`; must re-check clean.)
2. **Fresh first-missing-frontier capture:** record kernel artifact mtime/hash,
   image path, final reached target, first blocked task, syscall, fd flags, and
   task state. The image audit already proves `getty@tty1` is enabled, so the
   next useful fact is why the graph does or does not reach it.

## What NOT to do

- Don't "fix a frozen window" — it isn't frozen (klog updates it live).
- Don't rewrite the ldisc/VT/fbcon stack — it works (console.md §3).
- Don't treat serial as the intended primary — that inversion is the bug.
- Don't start SOW-2+ before SOW-1: no getty runs until sysinit completes.

## Bottom line

The window works as a **kernel-log display** but is **not a console session**. Making
it a real Linux console needs: (SOW-1) fix the sysinit deadlock so getty.target is
reached, (SOW-2/3) run `getty@tty1` in the window with working keyboard+echo, and
(SOW-4) restore correct console roles (window primary, serial secondary). SOW-1 is
the gate and the same blocker as the desktop goal.

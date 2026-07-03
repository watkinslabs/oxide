# state.md — session handoff

## Headline
**GNOME reaches `graphical.target`; gdm.service starts. Remaining blocker: a
graphical seat0 (the display-stack / udev chain).** Two hard storms that made the
boot impossible are FIXED & merged this session. Next work follows the
udev-correctness roadmap in **`udevfix.md`** (author: user), and driver work is
in progress on branch **`codex/driver-fixes`**.

## Merged this session (10 PRs, #2311–#2320, all boot-verified)
- #2311 mount_setattr AT_EMPTY_PATH + mount-aware bind — killed domainname 226.
- #2312 O_PATH must not invoke device-driver open (FMODE_PATH) — /dev/kmsg 226.
- #2313 socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX — system D-Bus up.
- #2314 eventfd blocking read must BLOCK not EINVAL — EXIT_USER(217).
- #2315 AF_UNIX accept SO_DOMAIN + epoll-wake listener on connect.
- #2316 share a socket's poll_subs into its inode — epoll targeted wakes.
- **#2317 recvmsg AF_UNIX honours O_NONBLOCK/MSG_DONTWAIT (EAGAIN)** — THE dbus
  fix. dbus-broker's edge-triggered epoll never got EAGAIN → tore every conn
  down. `Connection terminated` 60→0; multi-user + graphical.target reached.
- #2318 /sys/class/drm class node — udev DRM seat-discovery prerequisite.
- **#2319 route raw kernel uevents to netlink group 1 only** — THE uevent-storm
  fix. Raw blobs were delivered to systemd PID1's cooked (group-0) monitor,
  which couldn't parse them, never consumed them → PID1 spun ~3.8M epoll scans
  ("Looping too fast"). Also emit card0 seat-master uevent.
- **#2320 NETLINK_KOBJECT_UEVENT userspace cooked multicast** (udevfix.md Phase 1)
  — `netlink::rebroadcast_cooked_uevent`; threads dest sockaddr through
  sys_sendto→netlink_fd::sendto. Correct transport for udevd's cooked
  re-broadcast (currently unexercised — udevd doesn't re-broadcast yet).

## Current blocker — graphical seat0 (follow `udevfix.md`)
gdm.service Starts (~70s) then idles; NO gnome-shell/greeter; `/dev/dri/card0`
never opened → seat0 not graphical. Traced chain state:
- card0 raw uevent IS emitted and reaches **1 group-1 socket (udevd)**
  (`[DRMUEV] card0 act=add reached=1`). Raw delivery works.
- **SHARP FINDING: udevd writes ZERO `/run/udev/data/*` entries for ANY device**
  (traced openat for `udev/data` across a full coldplug boot — 0 hits, not even
  a failed-open attempt). So udevd is NOT processing devices into its db at all —
  this is SYSTEMIC, not card0-specific. It never reaches the rule-apply / tag /
  cooked-re-broadcast stage (`rebroadcast_cooked_uevent` never fires either).
- Consequence: no `master-of-seat` tag in the udev db → logind's seat
  enumeration finds card0 untagged → seat0 not graphical → gdm idles.
- `/sys/dev/char/*` is never looked up; `/sys/dev/block/254:0` IS (2×) — so
  `/sys/dev/{char,block}` (plan Phase 4) is a real gap but NOT the root here.
- **SHARPEST FINDING (this session): udevd (pid 49) POLLS its uevent socket but
  NEVER READS it.** Traced end-to-end:
  - The card0 raw uevent lands on netlink `port=6, grp=1` (`[UEVEMIT] port=6`),
    which IS udevd's monitor (only udevd binds group 1; reached=1).
  - port 6 is polled ~66k× and `poll()` returns POLLIN every time (`ne=1`) —
    the socket is readable, data is sitting in its rx_queue.
  - The poller is **pid=49 (systemd-udevd)** (traced via `visible_pid()` in
    `NetlinkSocket::poll`).
  - But udevd issues **ZERO** read syscalls on it — instrumented ALL of
    `recvmsg` (47), `recvfrom` (45), `read` (0), and `recvmmsg`(299)→recvmsg:
    every UEVREAD counter = 0. So udevd's epoll/ppoll never returns port 6 as
    ready → its read callback never fires → it drains nothing → processes no
    device.
  - Tried a fix: make netlink `enqueue` wake pollers
    (`sched::live::notify_epoll_waiters`) — udevd STILL never read (UEVREAD=0),
    so it's NOT a missing wake. Reverted (also: global epoll broadcast on every
    rtnetlink reply is too costly).
- **KERNEL POLL MACHINERY FULLY VERIFIED CORRECT — EPOLLET suspect RULED OUT.**
  Traced scan_once's view of the netlink fds in epoll: `ev=0x0001` (EPOLLIN,
  **NOT** EPOLLET — bit 0x80000000 clear), `ready=0x0001` (POLLIN), `et_seen=0`.
  So they are LEVEL-triggered and scan_once REPORTS them every scan (the
  `else if ready==0 {continue} else {report}` path). Also verified: `POLL_IN`==
  `POLLIN`==0x1 across vfs/ppoll/epoll (no bit mismatch); `et_seen` inits to 0 at
  `epoll_ctl(ADD)` (epoll.rs:240); `sys_ppoll` returns any fd whose `poll()`
  reports POLLIN (007_poll.rs:100-108); `NetlinkSocket::poll` returns POLLIN when
  rx_queue non-empty. Every kernel path correctly signals the uevent socket
  readable to pid 49. An `enqueue`→`notify_epoll_waiters` wake did not change it.
- **CONCLUSION: the kernel side is correct; the fault is inside pid 49 (udevd) —
  it is told its uevent fd is readable but issues no read.** This is a userspace
  (systemd-udevd) internal dispatch/fd-set issue, NOT a kernel poll bug and NOT
  device-model. Resolve it by introspecting udevd itself: an INTERACTIVE serial
  session (getty.target IS reached → serial-getty on ttyS0) running
  `strace -f -p <udevd>` + `udevadm monitor --kernel` + `journalctl -u
  systemd-udevd -o verbose`. The fire-and-forget `oneboot.sh` harness cannot
  drive interactive input — use `make -C ../oxide-images run-serial` or the qemu
  MCP serial. Also confirm pid 49 IS systemd-udevd (vs a udev worker) and that
  its monitor fd is the SAME socket object (port 6) the coldplug uevent reached
  (socket-activation fd-passing vs udevd creating its own late-bound monitor).
- Alternatively confirm with udevd's own journal via an INTERACTIVE serial shell
  (getty.target is reached; a serial-getty on ttyS0 may allow `journalctl -u
  systemd-udevd` + `udevadm monitor --kernel`) — the fire-and-forget oneboot.sh
  harness can't drive that; use the qemu MCP serial or a manual `make
  run-serial` session.

**Root per `udevfix.md`: the kernel's Linux device-model surface is incomplete,
so real udev can't fully process the device.** Do NOT add kernel policy/seat
hacks (udevfix.md §"Things we are doing wrong"). The roadmap:
- Phase 1 DONE (#2320): cooked-uevent multicast transport.
- **Next — Phases 3,4,6:** `device_add` ordering (sysfs+devtmpfs coherent before
  the add uevent); central char/block registries + `/sys/dev/char/<maj>:<min>`
  and `/sys/dev/block/<maj>:<min>`; complete class sysfs (DRM first: subsystem,
  /sys/dev/char/226:0, DEVTYPE, hotplug change) so udevd can build the device
  and apply 71-seat.rules.
- Then verify: udevd processes card0 → cooked event reaches logind (transport
  from #2320) → seat0 graphical → gdm opens /dev/dri/card0 → gnome-shell.
- Only after that debug virtio-gpu DRM ioctl/KMS (`crates/drivers/drm`,
  `drv-virtio-gpu`; ioctl surface exists, unexercised).

## Coordinate with driver work
Branch `codex/driver-fixes` has in-progress driver work that may touch the
device-model / sysfs / uevent paths. main now carries #2320 + this state so that
branch rebases from a current baseline (no divergence).

## Boot/diagnosis notes
- **Diagnostic cmdline**: `../oxide-images/imagectl/src/main.rs` ~line 963 GRUB
  menuentry (NOT git-tracked). Default `quiet`. systemd serial logs: swap
  `quiet` → `systemd.log_target=kmsg systemd.journald.forward_to_console=1`
  (+`systemd.log_level=debug` for unit detail, but it's slow under TCG).
- **Fast trace loop**: the card0 uevent + udevd access fire at coldplug ~6s —
  boot with a SHORT window (`bash oneboot.sh out.log 90`), don't wait for the
  full ~5min TCG boot to graphical.target. Real full boot 35k+ lines.
- **User-facing GNOME test**: `cd ~/oxide/oxide-images && make live-serial-console`
  (GTK window + serial). NOT `make live`. Default PROFILE=live-gnome ARCH=x86_64.
- **debug-epoll feature** (`make kernel FEATURES=debug-epoll`): `[epoll-lvl]`
  logs the level-ready fd spinning systemd — how the #2319 storm was pinned.
- Ledger `metadata/index.md`: B next = 307.

## First task next session
`git checkout main && git pull`. Follow `udevfix.md` Phases 3/4/6: make the
kernel device-model Linux-shaped enough that real udev processes card0 (device_add
ordering, /sys/dev/char, complete DRM class sysfs), so udevd tags it → cooked
event reaches logind (#2320 transport) → seat0 graphical → gdm greeter. Coordinate
with `codex/driver-fixes`. Active `/goal`.

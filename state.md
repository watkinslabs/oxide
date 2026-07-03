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
- **CORRECTION (supersedes "udevd never reads"): I MISIDENTIFIED the actor.**
  I latched the first tid to poll a readable KOBJECT_UEVENT socket and dumped its
  live syscall stream (`record_syscall` + a `WATCH_TID` probe). That tid is NOT
  udevd — its syscalls are `epoll_wait`, `recvmsg(ret=16)`, and a heavy
  `openat`→`fstat`→`read`→`close` loop over `/sys/fs/cgroup/**/cgroup.events`,
  `/proc/N/cgroup`, `pids.max`, `threads-max`, `/proc/self/fdinfo` — that is
  **systemd PID1's cgroup/unit manager**, and it is very much ACTIVE (not stuck).
  So the "poller sees readable but never reads" was PID1's socket-activation
  socket, which PID1 legitimately does NOT drain (it hands it to udevd). udevd's
  ACTUAL behavior is therefore UNVERIFIED — the earlier UEVREAD=0 traces need
  re-attribution.
- **REAL udevd traced (latched by exe_path in `record_syscall`): it is STUCK/
  very-slow in INITIALIZATION and never reaches device processing.** Across 1646
  captured `openat`s the real systemd-udevd opens **ZERO `/sys` paths** (no
  `/sys/devices`, no card0), writes **ZERO `/run/udev/data`**, and at the end of
  the window is STILL loading rule files (`/usr/lib/udev/rules.d/77-mm-*`,
  `78-sound-card`, `80-drivers`, `81-net-dhcp`, …) and doing heavy **userdb/NSS/
  group** lookups (`/run/userdb`, `/etc/userdb`, `/run/systemd/userdb`,
  `/run/host/userdb`, `/usr/lib/userdb`, `/etc/group` — ~30 opens each) plus
  probing `/dev/*` (fuse/kvm/loop-control/net-tun/snd/vfio/vhost). So card0 is
  never tagged because udevd never gets past init to its event loop.
- **COMPLETE ROOT PICTURE (non-confounded, confirmed via a one-shot
  `dump_tasks()` that adds NO per-syscall overhead):** systemd-udevd is
  **Runnable and busy-SPINNING** — `dump_tasks` at 50s showed it `R`, with
  `nsyscalls=251884` (a quarter-million) and last syscall `unlink`. Traced the
  spin precisely:
  1. udevd's epoll persistently reports **fd=4** ready with `POLLIN`
     (`[UDVEP] fd=4 type=6 inotag=4e4c534b(NLSK) ready=0x1` — a NETLINK socket
     whose `rx_queue` is non-empty, so `NetlinkSocket::poll` correctly = POLLIN).
  2. BUT udevd issues **NO recv syscall on fd=4** — recvmsg/recvfrom/read/
     recvmmsg traces (for udevd's tid, all netlink protocols) fire ZERO times.
     So the socket never drains → epoll stays hot every scan.
  3. Each loop udevd instead `unlink("/run/udev/queue")`=ENOENT (its
     "queue-EMPTY" marker — so from udevd's view it has NO pending events).
  4. Net: udevd spins forever on an epoll-ready-but-never-read netlink fd,
     never processes the coldplug card0 event → card0 never tagged → seat0
     never graphical → gdm idles.
- **THE crux (unresolved): epoll reports fd=4 ready to udevd, but udevd's
  sd-event never dispatches a read for it.** This SAME pattern (epoll ready, no
  recv) was also seen for systemd PID1 earlier — BOTH sd-event processes. So the
  suspect is how our epoll delivers events to sd-event: it looks up the source
  by the 8-byte `epoll_event.data` (a pointer) and only recv's if it finds+
  enables the source. If the returned `events`/`data` don't match what
  `epoll_ctl(ADD)` stored (corruption, wrong offset, an EPOLLET/oneshot
  interaction, or a level fd that sd-event has disabled), sd-event ignores the
  event but the fd stays ready → spin. VERIFY: `scan_once` writes `data` at
  `EPOLL_DATA_OFF` (x86=4) as u64 and `revents` u32 @0 into a 12-byte record —
  confirm sd-event reads the SAME data it registered, and that a persistently-
  level-ready netlink fd whose source sd-event `disabled`/`ONESHOT`'d is not
  re-reported. This is a KERNEL epoll↔sd-event dispatch bug, likely general (hits
  PID1 + udevd), and is THE thing to fix for the greeter.
- **FINAL AIRTIGHT CONFIRMATION (one-shot socket dump — non-confounding): the
  stuck messages are VALID.** Dumped udevd's stuck netlink sockets at boot via a
  1-in-20000 sample in `NetlinkSocket::poll` (no timing confound): the proto-15
  group-1 monitor has `qlen=2, frontlen=155, head="add@/devices/virtual/drm/
  card0\0ACTION=ad…"` — the REAL card0 uevent, 155 bytes, non-empty. (A proto-0
  rtnetlink socket is also stuck at qlen=3.) So:
  - The messages are NOT empty → the socket is fully drainable → the recvmsg
    empty-front idea is RULED OUT (don't chase it as the greeter fix).
  - qlen stays pinned at 2 → udevd never drains it. `sys_read`/`recvfrom`/
    `recvmsg`/`recvmmsg` ALL route netlink fds through `netlink_fd` (verified:
    000_read.rs:19 routes to netlink_fd::read), and none fired for udevd → udevd
    reads fd=4 via NO syscall path.
  - epoll `{events,data}` round-trips byte-correct (epoll.rs:226-227 read @0/@4,
    scan_once writes back @0/@4); `revents`=POLLIN clean (no spurious HUP/ERR).
- **CONCLUSION (bounded): the kernel epoll + netlink layers are VERIFIED CORRECT.
  udevd's sd-event has the uevent fd ENABLED (EPOLLIN) + epoll reports it READY
  + the queued data is a VALID uevent + delivery is byte-correct — yet sd-event
  never dispatches the read.** That is definitively inside sd-event/udevd, not a
  kernel bug reachable from here. Every kernel-side hypothesis (EPOLLET, empty
  msg, poll/recv mismatch, data-round-trip, netlink queue) has been tested and
  ruled out. The ONLY way forward is userspace introspection: interactive
  `strace -p $(pidof systemd-udevd)` (see epoll_wait's return vs its dispatch)
  and `journalctl -u systemd-udevd -o verbose` on a `make run-serial` session —
  the batch kernel-trace harness cannot see inside sd-event and its per-syscall
  klog confounds udevd's timing.
- Latent (separate, not the greeter blocker): `netlink_fd::recvmsg` line ~164
  `Some(d) if !d.is_empty() => d, _ => EAGAIN` — with `MSG_PEEK` an empty front
  datagram returns EAGAIN and is never removed → would wedge a peeking reader;
  worth a defensive drop/skip of empty front messages.
- Faster confirmation: interactive serial (`make -C ../oxide-images run-serial`;
  getty.target reached) → `strace -p $(pidof systemd-udevd)` shows the
  epoll_wait return {events,data} vs what udevd does with it. Batch klog traces
  confound udevd's timing (debug-watchdog per-syscall klog changed the loop),
  so keep any kernel probe to one-shot dumps (like `dump_tasks`), never
  per-syscall.
- Still faster with real udevd introspection: interactive serial (`make -C
  ../oxide-images run-serial`; getty.target is up) → `strace -p $(pidof
  systemd-udevd)`, `udevadm monitor --kernel --udev`, `journalctl -u
  systemd-udevd -o verbose`. The batch `oneboot.sh` can't drive stdin.
- Ruled out (verified): kernel poll machinery (POLL bits, EPOLLET et_seen init,
  ppoll scan, netlink poll all correct); the two boot storms (dbus, uevent) are
  fixed. The greeter blocker is in the udevd device-processing pipeline
  (`udevfix.md` territory), NOT the kernel poll layer.
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

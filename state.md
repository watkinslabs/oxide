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
- **Root is upstream: udevd processes no device.** Diagnose with udevd's own
  logging (`udevadm control --log-level=debug` / journal — needs runtime
  introspection, not kernel serial traces) OR the device-model completeness in
  udevfix.md. Likely a udevd worker/rule-load/db-write stall the kernel side
  must make Linux-shaped enough to satisfy (device_add ordering, complete
  sysfs). THIS is `codex/driver-fixes` territory — do not implement overlapping
  device-model changes on main in parallel (the divergence to avoid).

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

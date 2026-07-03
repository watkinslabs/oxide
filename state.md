# state.md — session handoff

## Headline (2026-07-03 update)
**The "Looping too fast" storm is FIXED & merged (#2319).** Root cause: the
kernel broadcast RAW uevents to ALL netlink listeners ignoring multicast group;
systemd PID1's cooked (group-0) monitor got a raw blob it couldn't parse, never
consumed it, and spun ~3.8M epoll scans. Fix: raw kernel uevents → netlink group
1 (udevd) only. The DRM card0 seat-master uevent now emits cleanly:
`storm 0`, boot reaches multi-user + graphical.target. **Remaining: seat0 still
not graphical** — nobody opens `/dev/dri/card0` (traced CARDOPEN=0). Next blocker
is the udevd→systemd cooked-uevent re-broadcast (see below).

## Prior headline
**GNOME reaches `graphical.target`; last blocker is the virtio-gpu DRM-master/KMS
path so logind can build a graphical seat0 for gdm's greeter.** The dbus storm
that stalled every Type=dbus service is FIXED (#2317), so multi-user + graphical
targets are reached and gdm.service Starts. gdm then idles: no greeter, because
seat0 is not graphical.

## Merged this session (8 PRs, all boot-verified)
- **#2311** mount_setattr AT_EMPTY_PATH + mount-aware bind — killed domainname 226.
- **#2312** O_PATH must not invoke device-driver open (FMODE_PATH) — killed /dev/kmsg 226.
- **#2313** socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX — brought up system D-Bus.
- **#2314** eventfd blocking read must BLOCK not EINVAL — killed EXIT_USER(217).
- **#2315** AF_UNIX accept SO_DOMAIN + epoll-wake listener on connect.
- **#2316** share a socket's poll_subs into its inode — epoll targeted wakes on
  accepted sockets (server reads binary D-Bus messages, not just AUTH text).
- **#2317** recvmsg AF_UNIX stream honours O_NONBLOCK/MSG_DONTWAIT (EAGAIN) — THE
  dbus fix. dbus-broker's edge-triggered epoll drain-until-EAGAIN never got
  EAGAIN (recvmsg spun on empty ring) → tore every connection down. conn-term
  60→0; multi-user + graphical.target reached. `047_recvmsg.rs` + `cmsg_parse.rs`.
- **#2318** /sys/class/drm class node — udev DRM seat-discovery prerequisite.
  `crates/kernel/sysfs/src/drm.rs`.

## Current blocker — graphical seat0 for gdm greeter (next session starts here)
gdm.service Starts (~75s) then idles; NO gnome-shell/greeter/wayland/Xwayland
activity. The gdm fork-child `[EXIT] code=1` is ONLY the missing `plymouth`
probe (`/usr/bin/plymouth` ENOENT — harmless), NOT the greeter.

**Chain, and exactly where it breaks:**
1. `/dev/dri/card0` (226:0) exists — `drm::node::register()` mints it. ✓
2. `/sys/class/drm/card0` now exists (#2318) — udev/logind DO open it at
   coldplug (traced: `[DRMOPEN] /sys/class/drm{,/card0,/renderD128}`). ✓
3. **BREAK:** udevd must apply the `master-of-seat` TAG (71-seat.rules,
   `SUBSYSTEM==drm KERNEL==card*`). That needs the `card0/uevent` write (from
   systemd-udev-trigger's "add") to BROADCAST a netlink uevent so udevd
   processes card0. When I made the drm `uevent` write emit that uevent,
   **logind retry-loops** trying to master the DRM device → systemd `Looping
   too fast. Throttling execution` storm (211×), boot wedges. So logind CANNOT
   master virtio-gpu card0 yet.
4. Therefore nothing opens `/dev/dri/card0`, seat0 stays non-graphical, gdm
   never launches the greeter.

**Root of the break = the seat-master uevent emission storms systemd BEFORE any
DRM ioctl.** CORRECTED finding (traced this session): with a `[DRMIOCTL]` trace
at `drm::node::handle_drm_ioctl` entry AND the drm `uevent` write re-emitting the
netlink uevent, the storm boot shows **ZERO `[DRMIOCTL]`** — logind NEVER opens
`/dev/dri/card0`. So the "Looping too fast" storm is NOT a failing
SET_MASTER/GETRESOURCES; it is a systemd/udev event-handling feedback loop
kicked off by the synthetic `drm` "add" uevent itself (likely systemd spins
creating/re-evaluating a `dev-dri-card0.device` / `sys-devices-virtual-drm-*`
unit whose sysfs backing it can't reconcile, or udevd re-triggers). The DRM
ioctl surface (`drm/src/modeset.rs`: GETRESOURCES/GETCONNECTOR/SET_MASTER) looks
complete and returns real card data — it's just never exercised yet.

**Storm facts pinned this session (all traced):**
- card0 `uevent` is written exactly ONCE (`[UEWRITE] card0 act=add`) — NOT a
  re-emit feedback loop.
- `/dev/dri/card0` is opened ZERO times during the storm — logind never masters
  it; `[DRMIOCTL]` count = 0. So the storm is NOT a DRM/KMS master failure.
- The netlink uevent socket recvmsg/read correctly returns EAGAIN on empty
  (`netlink_fd.rs:164`, `netlink/src/lib.rs:283`) and `poll()` only sets POLLIN
  when the rx_queue is non-empty — so it is NOT the #2317 edge-triggered-spin
  bug class either.
- systemd DID create a Device unit for card0 ("Registering bus object
  implementation … iface=…systemd1.Device").
- **Heisenbug:** at default log level the drm "add" tips PID1's sd-event rate
  limiter → "Looping too fast. Throttling execution" (~100+/boot), boot wedges
  ~1400 lines. At `systemd.log_level=debug` the extra logging slows PID1 below
  the threshold (storm≈1) but the boot is then too slow to reach the seat stage
  in-window. So the storm is systemd-internal event churn from the drm
  device-unit, and it needs introspection AT the loop moment (which changes the
  timing) — a genuine wall for kernel-trace/cold-boot iteration.

**Next steps (revised):**
1. Get systemd's per-event-source detail at the storm. Options: raise the
   sd-event rate-limit is not ours to change; instead instrument WHICH fd/event
   systemd polls in the loop — add a kernel trace on the specific netlink /
   D-Bus fd systemd's udev-monitor uses and count epoll_wait→recvmsg cycles, or
   compare our synthetic drm uevent env against a real Linux one field-by-field
   (MODALIAS, ID_PATH, USEC_INITIALIZED, .device SYSTEMD_ALIAS) — a missing
   field may make systemd re-queue the device job repeatedly.
2. Only after the uevent is accepted without storming does the DRM-master path
   (GETRESOURCES/SET_MASTER — surface looks complete in `drm/src/modeset.rs`)
   get exercised; fix gaps then.
3. Then gnome-shell/Xwayland launch on the graphical seat.
Repro artifacts (re-add to reproduce): the uevent emit in
`sysfs/src/drm.rs::DrmUeventFileOps::write` (currently the documented no-op),
`[DRMIOCTL]` trace at `drm/src/node.rs` handle_drm_ioctl entry, `[CARDOPEN]`
trace in `257_openat.rs` after resolve.

## Boot/diagnosis notes
- **Diagnostic cmdline**: `../oxide-images/imagectl/src/main.rs` ~line 963 GRUB
  menuentry (NOT git-tracked). Default `quiet` (restored). Systemd serial logs:
  swap `quiet` → `systemd.log_target=kmsg systemd.journald.forward_to_console=1`.
- **User-facing GNOME test command (they asked):** `cd ~/oxide/oxide-images &&
  make live-serial-console` — rebuilds kernel + serial-console ISO + boots in a
  GTK window (serial also on terminal). NOT `make live` (wrong ISO, no GPU/serial
  wiring). Default PROFILE=live-gnome ARCH=x86_64.
- **Boot loop**: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot
  PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh output/x.log <secs>`. Full
  boot 43k+ lines; a boot that runs the whole window but stays ~1900 lines +
  "Looping too fast" = systemd event storm, not a short boot.
- **execve/openat ENOENT traces**: `059_execve.rs` has a debug-boot-gated
  `[execve ENOENT] path=` at the read_exec None arm; ungate it (drop the
  `#[cfg(feature="debug-boot")]`) for one boot to see missing binaries.
- Ledger `metadata/index.md`: B next = 305.

## NEXT BLOCKER (storm fixed; seat0 still not graphical)
The drm card0 "add" uevent now reaches udevd (group 1) without storming. But
`/dev/dri/card0` is never opened (CARDOPEN=0) → seat0 not graphical → gdm idles.
The chain from here:
1. udevd (group 1) processes card0, applies 71-seat.rules, tags `master-of-seat`.
2. udevd re-broadcasts a COOKED libudev event to its monitor clients.
3. systemd PID1 / logind receive the cooked event → mark seat0 CanGraphical.
4. gdm opens /dev/dri/card0, launches gnome-shell greeter.

**Prime suspect: step 2→3 — the udevd→systemd cooked re-broadcast.** systemd's
sd-device monitors bind `nl_groups=0` (traced: 3 sockets group 0, 2 group 1
[udevd]; ZERO group 2; ZERO ADD_MEMBERSHIP). In Linux the manager monitor is on
the UDEV group (2) and udevd multicasts cooked events to group 2. Here systemd
is on group 0 — so it may receive NOTHING via multicast. Check whether oxide's
netlink implements USERSPACE→group multicast for `NETLINK_KOBJECT_UEVENT`: when
udevd sendmsg's a cooked event with a destination group, does the kernel deliver
it to the group-0/2 monitor sockets? If not (likely — `rtnl_multicast` covers
NETLINK_ROUTE only), that's the gap: implement uevent-socket send-side multicast
so udevd's cooked events reach systemd/logind.
Also verify (debug boot, `systemd.log_level=debug`, now no storm so it can reach
the seat stage if given time): does logind log seat0 CanGraphical / does udevd
log tagging card0? Re-add the `[CARDOPEN]` trace (257_openat.rs, `contains("dri/card")`)
to detect when the seat goes graphical (card0 finally opened).

## First task next session
`git checkout main && git pull`. Investigate the udevd→systemd cooked-uevent
re-broadcast (step 2→3): does oxide netlink multicast a userspace-sent uevent to
group subscribers? Trace udevd's sendmsg on its KOBJECT_UEVENT socket + whether
it reaches systemd's monitor. Fix the multicast gap, then drive the chain to a
rendered gdm greeter (active `/goal`).

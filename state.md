# state.md — session handoff

## Headline
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

**Root of the break = virtio-gpu KMS / DRM-master is not functional.** logind
opens the DRM device, does `DRM_IOCTL_SET_MASTER` + mode/resource ioctls; if
those fail/aren't implemented, logind loops. Drivers exist but the KMS path
isn't wired for logind's master handshake: `crates/drivers/drm/` (node.rs,
modeset.rs, crtc.rs, dumb.rs), `crates/drivers/drv-virtio-gpu/`.

**Next steps:**
1. Boot live-gnome with kmsg cmdline; trace `016_ioctl.rs` for the DRM ioctls
   logind issues on `/dev/dri/card0` (SET_MASTER 0x641e, MODE_GETRESOURCES
   0xc04064a0, MODE_GETCONNECTOR, etc.) — see which returns an error and why.
2. Make virtio-gpu card0 satisfy logind's master handshake (GETRESOURCES →
   ≥1 CRTC/connector/encoder, SET_MASTER ok). Then re-add the seat-master
   uevent broadcast in `sysfs/src/drm.rs` `DrmUeventFileOps::write` (currently a
   documented no-op) so udevd tags card0 → seat0 graphical → gdm greeter.
3. Then chase gnome-shell/Xwayland launch on the graphical seat.

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

## First task next session
`git checkout main && git pull`. Trace logind's DRM ioctls on /dev/dri/card0
(step 1 above), make virtio-gpu KMS satisfy the master handshake, re-enable the
seat-master uevent, drive to a rendered gdm greeter (active `/goal`).

# state.md — session handoff

## Headline
**GNOME bring-up: the dbus blocker is FIXED — `graphical.target` now REACHED.**
The root cause of the systemd↔dbus-broker "Connection terminated" storm was a
kernel bug: `recvmsg` on an AF_UNIX SOCK_STREAM socket ignored
`O_NONBLOCK`/`MSG_DONTWAIT` and busy-spun instead of returning `EAGAIN`.
dbus-broker's edge-triggered epoll drain never got its terminating `EAGAIN`, so
it tore every client connection down. Fixed in **#2317**: conn-term **60 → 0**,
**multi-user.target + graphical.target both reached**, gdm.service starts.

## Merged this session (all boot-verified)
- **#2311** mount_setattr AT_EMPTY_PATH + mount-aware bind — killed domainname 226.
- **#2312** O_PATH must not invoke device driver open (FMODE_PATH) — killed /dev/kmsg 226.
- **#2313** socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX — brought up system D-Bus.
- **#2314** eventfd blocking read must BLOCK not EINVAL — killed EXIT_USER(217).
- **#2315** AF_UNIX accept SO_DOMAIN + epoll-wake listener on connect.
- **#2316** share a socket's poll_subs into its inode — epoll targeted wakes on
  accepted sockets (server now reads binary D-Bus messages, not just AUTH text).
- **#2317** recvmsg AF_UNIX stream honours O_NONBLOCK/MSG_DONTWAIT (EAGAIN) — THE
  dbus fix. `crates/kernel/syscalls/src/047_recvmsg.rs` + `cmsg_parse.rs`.

## Current state — graphical.target reached, greeter not yet confirmed
Boot now reaches `graphical.target`. `gdm.service` **Starts**, BUT a gdm fork-child
exits code=1 (`[EXIT] name=fork-child exe=/usr/bin/gdm code=1` ~109s) and no
gnome-shell / greeter / Xwayland / /dev/dri activity appears after. So the last
gap to an actual GNOME login screen is **gdm's greeter/display launch**.

## Next session starts here — chase the gdm greeter
1. Boot with kmsg cmdline (see below), grep for `gdm`, `gnome-shell`, `Xwayland`,
   `/dev/dri`, `logind`, `seat0`, `wayland`. Find why the gdm worker exits 1.
2. Likely suspects: DRM/KMS device (`/dev/dri/card0`) missing or the virtio-gpu
   drm node not exposed; logind seat/session (`seat0`) not created; gdm's
   Xwayland/gnome-shell exec failing. Trace the gdm fork-child's `[EXIT]` via a
   4-byte errno-pipe write or `sched::diag::dump_recent_for(tid)` (see below).
3. This is Phase-17-ish (tty/login/display); GNOME shell needs the DRM path.

## Boot/diagnosis notes
- **Diagnostic cmdline**: `../oxide-images/imagectl/src/main.rs` ~line 963 GRUB
  menuentry (NOT git-tracked). Default `quiet` (restored). Enable systemd serial
  logs: swap `quiet` → `systemd.log_target=kmsg systemd.journald.forward_to_console=1`.
- **Boot loop**: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh output/x.log <secs>`. Real full boot >2000 lines (graphical boots are 36k+); ~1200/8-line = GRUB-partial, re-run.
- **AF_UNIX trace recipe (this session)**: klog `[BWRITE]/[AREAD]/[AWRITE]/[BREAD]/[UCLOSE]` in `net/src/unix_sock.rs` write/read/close_writer, filtered by `UnixEnd` — dual-direction byte-flow trace that isolated the recvmsg EAGAIN bug. Gate socket-content traces on end; `klog::write_raw`/`write_dec_u64` are in scope in the net crate.
- **safe_fork errno capture**: a failing `safe_fork` child writes its errno as a 4-byte write to an errno pipe — trace `write` where `cnt==4` and i32 ∈ -1..-255, then `sched::diag::dump_recent_for(tid)`.
- Bash sandbox can't kill qemu → `pkill -9 -f qemu-system` with `dangerouslyDisableSandbox: true` if stale qemu block a boot.
- Ledger `metadata/index.md`: B next = 304.

## First task next session
`git checkout main && git pull`. Boot live-gnome with kmsg, find why the
gdm greeter/worker exits 1 (DRM node? logind seat? Xwayland exec?). Drive the
dependency chain until the GNOME greeter renders (active `/goal`).

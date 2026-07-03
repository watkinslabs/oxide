# state.md — session handoff

## Headline
**GNOME reaches `graphical.target` + `gdm.service`; greeter/login does NOT yet
render.** The udevd "epoll-ready-but-never-reads" spin — misdiagnosed last
session as an sd-event/udevd internal fault — was a **KERNEL bug**, now fixed &
merged (#2324): `netlink_fd::recvfrom` ignored `MSG_PEEK`/`MSG_TRUNC`, so
libudev's `recvfrom(len=0, MSG_PEEK|MSG_TRUNC)` size-probe **dequeued+destroyed**
the card0 uevent and returned EAGAIN → udevd spun forever, drained nothing.
Next layer = udevd now READS the uevent but `/run/udev/data` writes still 0
(device-model tagging → graphical seat → gdm). Follow **`udevfix.md`**; driver
work on **`codex/driver-fixes`**.

## Merged this session (14 PRs, #2311–#2324, all boot-verified)
- #2311 mount_setattr AT_EMPTY_PATH + mount-aware bind — killed domainname 226.
- #2312 O_PATH must not invoke device-driver open (FMODE_PATH).
- #2313 socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX — system D-Bus up.
- #2314 eventfd blocking read must BLOCK not EINVAL — EXIT_USER(217).
- #2315 AF_UNIX accept SO_DOMAIN + epoll-wake listener on connect.
- #2316 share a socket's poll_subs into its inode (epoll targeted wakes).
- #2317 recvmsg AF_UNIX honours O_NONBLOCK/MSG_DONTWAIT — THE dbus fix.
- #2318 /sys/class/drm class node — udev DRM seat-discovery prerequisite.
- #2319 route raw kernel uevents to netlink group 1 only — PID1 uevent storm.
- #2320 NETLINK_KOBJECT_UEVENT userspace cooked-uevent multicast (udevfix Ph1).
- #2321–#2323 docs: udevfix.md plan + state hand-offs.
- **#2324 recvfrom MSG_PEEK/MSG_TRUNC — THE udevd-spin fix (root cause above).**

## Current blocker (next layer)
udevd now drains its uevent monitor (peek returns real 155 B len, spin gone).
Remaining: udevd must PROCESS card0 → write `/run/udev/data/c226:0` with the
`master-of-seat` tag → seat0 CanGraphical=yes → gdm launches greeter. Last known
state: `/run/udev/data` writes = 0. Unknown whether udevd now processes the
uevent + stalls later, or the device-model surface (`/sys` attrs, `MODALIAS`,
subsystem/devtype) is still incomplete for udev's rules. That is the udevfix.md
device-model-completeness work.

## First task next session
`git checkout main && git pull`. Boot live-gnome and check whether
`/run/udev/data/c226:0` now exists post-#2324. Interactive serial session:
`make -C ../oxide-images run-serial` (getty.target reached), then
`udevadm info /dev/dri/card0`, `udevadm monitor --udev`, `ls /run/udev/data`,
`loginctl seat-status seat0` (CanGraphical?). If the tag is missing, trace which
udev rule / device attribute is absent (device-model gap, not policy — kernel
exposes the Linux-shaped model, udevfix.md). Fix kernel-side; keep any kernel
probe to ONE-SHOT dumps (per-syscall klog confounds udevd timing).

## Boot / diagnosis notes
- Build+boot: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot
  PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh out.log <secs>`. Full boot
  35k+ lines; card0 uevent + udevd at coldplug ~6s, so a 90s window suffices.
  ~900-line boots = GRUB-partial, re-run (`pkill -9 -f qemu-system`,
  dangerouslyDisableSandbox — the Bash sandbox otherwise can't reap qemu).
- Diagnostic cmdline: `../oxide-images/imagectl/src/main.rs` GRUB menuentry (NOT
  git-tracked). Default `quiet`. systemd serial logs: swap `quiet` →
  `systemd.log_target=kmsg systemd.journald.forward_to_console=1`.
- `dump_tasks()` (one-shot, non-invasive): every task's state + last syscall +
  nsyscalls. `debug-watchdog` feature enables the syscall-name table.
- Ledger `metadata/index.md`: B next = 308, D next = 118.

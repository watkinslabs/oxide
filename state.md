# state.md — session handoff

## Headline
**GNOME reaches `graphical.target` and `gdm.service` starts; the greeter/login
screen does NOT render.** Two boot-*blocking* storms were fixed & merged this
session (dbus + uevent), taking the boot from a total EXIT_NAMESPACE(226)
cascade to a running graphical target. The remaining blocker is precisely
bounded (below) and is **inside systemd-udevd/sd-event** — the kernel epoll +
netlink layers are verified correct. Follow the udev-correctness roadmap in
**`udevfix.md`**; driver work is on branch **`codex/driver-fixes`**.

## Merged this session (13+ PRs, #2311–#2323, all boot-verified)
- #2311 mount_setattr AT_EMPTY_PATH + mount-aware bind — killed domainname 226.
- #2312 O_PATH must not invoke device-driver open (FMODE_PATH).
- #2313 socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX — system D-Bus up.
- #2314 eventfd blocking read must BLOCK not EINVAL — EXIT_USER(217).
- #2315 AF_UNIX accept SO_DOMAIN + epoll-wake listener on connect.
- #2316 share a socket's poll_subs into its inode (epoll targeted wakes).
- **#2317 recvmsg AF_UNIX honours O_NONBLOCK/MSG_DONTWAIT (EAGAIN)** — THE dbus
  fix. dbus-broker's edge-triggered epoll never got EAGAIN → tore every conn
  down. `Connection terminated` 60→0; multi-user + graphical.target reached.
- #2318 /sys/class/drm class node — udev DRM seat-discovery prerequisite.
- **#2319 route raw kernel uevents to netlink group 1 only** — THE uevent-storm
  fix. Raw blobs hit systemd PID1's cooked (group-0) monitor → PID1 spun ~3.8M
  epoll scans ("Looping too fast"). Also emit card0 seat-master uevent.
- #2320 NETLINK_KOBJECT_UEVENT userspace cooked-uevent multicast (udevfix Phase 1).
- #2321–#2323 docs: udevfix.md plan + state hand-offs.

## Current blocker (bounded, evidence in git log #0eba0698 / #68923774)
gdm idles because seat0 never goes graphical, because card0 is never tagged
`master-of-seat`, because **systemd-udevd never processes the card0 uevent.**
Traced precisely (non-confounding one-shot dumps):
- udevd is Runnable and busy-SPINNING (`dump_tasks`: nsyscalls≈250k, last=unlink).
- Its epoll persistently reports its uevent netlink socket (fd, proto 15, group
  1) READY with POLLIN. That socket holds **2 VALID card0/renderD128 uevents**
  (`head=add@/devices/virtual/drm/card0…`, 155 B each — not empty, drainable).
- BUT udevd issues NO read on it (recvmsg/recvfrom/read/recvmmsg all 0; all route
  through `netlink_fd`, verified). qlen stays pinned at 2 → never drained.
- Each loop udevd instead `unlink("/run/udev/queue")`=ENOENT (thinks queue empty).
- **KERNEL VERIFIED CORRECT:** epoll `{events,data}` round-trips byte-exact
  (epoll.rs:226-227 read @0/@4; scan_once writes back @0/@4); `NetlinkSocket::poll`
  is accurate; `revents`=POLLIN clean. Ruled out (all tested): EPOLLET et_seen,
  empty-front-message, poll/recv mismatch, data corruption, netlink queue.
- **CONCLUSION: the fault is inside sd-event/udevd** — it has the fd ENABLED
  (EPOLLIN) + epoll-READY + VALID data + byte-correct delivery, yet never
  dispatches the read. Same epoll-ready-no-read pattern also seen for PID1.

## First task next session
`git checkout main && git pull`. The ONLY tractable path is USERSPACE
introspection (the batch `oneboot.sh` harness can't see sd-event internals, and
per-syscall kernel klog *confounds* udevd's timing — keep any kernel probe to
one-shot dumps). Use an interactive serial session — `make -C ../oxide-images
run-serial` (getty.target IS reached) — then:
`strace -p $(pidof systemd-udevd)` (see `epoll_wait`'s returned {events,data}
vs whether sd-event dispatches the io callback), `udevadm monitor --kernel
--udev`, `journalctl -u systemd-udevd -o verbose`. That pins why sd-event
skips an enabled+ready source; fix it kernel-side if it turns out to be a subtle
epoll semantics mismatch, else it's a udevd/image issue. Then the udevfix.md
device-model completeness (tagging → /run/udev/data → seat graphical → gdm) is
the next layer. Coordinate with `codex/driver-fixes`.

## Boot / diagnosis notes
- Build+boot: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot
  PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh out.log <secs>`. Full boot
  35k+ lines; the card0 uevent + udevd activity happen at coldplug ~6s, so a
  SHORT window (90s) suffices for most probes. ~900-line boots = GRUB-partial,
  re-run (kill stale qemu: `pkill -9 -f qemu-system`, dangerouslyDisableSandbox).
- Diagnostic cmdline: `../oxide-images/imagectl/src/main.rs` ~line 963 GRUB
  menuentry (NOT git-tracked). Default `quiet`. systemd serial logs: swap
  `quiet` → `systemd.log_target=kmsg systemd.journald.forward_to_console=1`
  (+`udev.log_level=debug`, but udevd's worker logs stay in the journal).
- `dump_tasks()` (one-shot, non-invasive) shows every task's state + last
  syscall + nsyscalls — the tool that de-confounded this. `debug-watchdog`
  feature enables the syscall-name table; the RING recording is always-on.
- Ledger `metadata/index.md`: B next = 307, D next = 118.

# 60 udev/sd-device kernel contract

DRAFT 2026-07-03. Dep:`01`,`02`,`03`,`06`,`13`,`15`,`19`,`24`,`27`,`35`,`47`.
Provides:the complete kernel-side surface that **unmodified upstream systemd-udevd
+ libudev/sd-device + systemd-logind** require to enumerate, process, and tag
devices — so `graphical.target` → seat0 CanGraphical → gdm greeter works.

## 1 Why this exists

`19§Purpose` assumed "we don't ship udev; we fully populate `/dev` from kernel."
That is **dead** (`03`, boot-to-GNOME campaign): we run REAL `systemd-udevd` 257.
The kernel is now the *producer* of a device-model contract that udevd/libudev/
logind *consume* verbatim. `/run/udev/{data,tags,queue,control,links}` are created
by **udevd**, NOT the kernel — the kernel's job is to feed udevd correct inputs
(uevents, `/sys`, `/dev`, syscalls) so udevd's own processing completes. Every
past boot-blocker (SCM_CREDS drop, nl_groups=0, sendmsg split, missing tags) was
one line of THIS contract discovered by trial-boot. This doc enumerates the whole
contract so it is built out in one pass and verified as a unit.

## 2 The seat/greeter dependency chain (what must all be true)

```
kernel emits card0 uevent (SUBSYSTEM=drm, DEVPATH, MAJOR=226 MINOR=0, DEVNAME=dri/card0)
  → udevd monitor RECEIVES it (netlink grp1, SCM_CREDENTIALS uid=0, nl_groups=1, MSG_PEEK/TRUNC, epoll wake)
  → udevd worker PROCESSES it: reads /sys/devices/.../card0 attrs + SUBSYSTEM symlink
  → 71-seat.rules matches (SUBSYSTEM=drm, KERNEL=card[0-9]*) → TAG+="master-of-seat"
  → udevd WRITES /run/udev/data/c226:0 (G:master-of-seat) AND /run/udev/tags/master-of-seat/c226:0
  → udevd BROADCASTS cooked uevent to grp2 (libudev header + props, single datagram)
  → logind enumerates tag "master-of-seat" (sd-device reads /run/udev/tags/) AND/OR
    receives the cooked add on its grp2 monitor
  → logind attaches card0 to seat0 → writes /run/systemd/seats/seat0 (CAN_GRAPHICAL=1)
  → logind exposes seat0 CanGraphical=yes over org.freedesktop.login1
  → gdm-local-display-factory sees graphical seat → spawns greeter (gnome-shell --gdm)
```

Any broken link = no greeter. §§4–10 spec each link; §11 is the acceptance gate.

## 3 Requirements index (status as of 2026-07-03)

| # | Requirement | Spec | Status |
|---|---|---|---|
| R01 | netlink raw uevent → group 1 only | §4.1 | DONE #2319 |
| R02 | netlink cooked rebroadcast → group 2/0 | §4.1 | DONE #2320 |
| R03 | recvmsg/recvfrom honour MSG_PEEK + MSG_TRUNC | §4.2 | DONE #2324 |
| R04 | recv sets SCM_CREDENTIALS ucred{0,0,0} | §4.2 | DONE #2327 |
| R05 | recv sets source nl_groups (1 raw / 2 cooked) | §4.2 | DONE #2327 |
| R06 | enqueue wakes epoll/poll waiters (poll_subs) | §4.3 | DONE #2327 |
| R07 | sendmsg coalesces iovecs into ONE datagram | §4.4 | DONE #2329 |
| R08 | bind nl_groups + NETLINK_ADD_MEMBERSHIP | §4.5 | DONE (F88+) |
| R09 | uevent env: ACTION/DEVPATH/SUBSYSTEM/SEQNUM | §5.1 | DONE |
| R10 | uevent env: MAJOR/MINOR/DEVNAME/DEVTYPE per class | §5.2 | PARTIAL — audit §5.2 |
| R11 | uevent env: MODALIAS where Linux emits it | §5.2 | GAP — verify |
| R12 | write "add"/"change" to /sys/.../uevent re-emits | §5.3 | DONE (drm; audit others) |
| R13 | /sys/kernel/uevent_seqnum monotonic + readable | §5.4 | VERIFY |
| R14 | /sys/class/<subsys>/<dev> symlink | §6.1 | DONE drm; audit all |
| R15 | /sys/devices/.../<dev>/uevent readable+writable | §6.2 | DONE drm; audit all |
| R16 | /sys/devices/.../<dev>/subsystem → class symlink | §6.2 | DONE drm; audit all |
| R17 | /sys/devices/.../<dev>/dev = "maj:min" | §6.2 | VERIFY |
| R18 | /sys/dev/{char,block}/<maj>:<min> symlink | §6.3 | VERIFY |
| R19 | per-class required attrs (drm/input/tty/net/block) | §6.4 | AUDIT |
| R20 | /dev node per device (devtmpfs), correct maj:min+mode | §7 | DONE; audit modes |
| R21 | udevd control socket (AF_UNIX) delivers + wakes udevd | §8 | **GAP — settle times out** |
| R22 | AF_UNIX dgram/seqpacket delivery notifies poll_subs | §8.1 | VERIFY (settle bug) |
| R23 | inotify on /dev + /run/udev (IN_CREATE/DELETE/MOVE) | §9.1 | VERIFY |
| R24 | epoll/ppoll/signalfd/timerfd for sd-event loop | §9.2 | DONE |
| R25 | devtmpfs mount + MS_* + mount(2) surface udevd uses | §9.3 | DONE |
| R26 | statx/newfstatat/openat2 on /sys+/dev+/run | §9.4 | VERIFY |
| R27 | pidfd poll readable only after target exit | §9.5 | DONE #2326 |
| R28 | /proc/<pid>/fd lists target's fds | §9.6 | DONE #2328 |
| R29 | coldplug: systemd-udev-trigger writes all /sys/.../uevent | §5.3 | DONE (harness) |
| R30 | logind sd-device tag enumeration finds master-of-seat | §10.1 | **BLOCKED by R21/R12** |
| R31 | logind attaches device → /run/systemd/seats/seat0 | §10.2 | BLOCKED |

**Live blockers (2026-07-03):** R21 (udevd control socket unresponsive → udevadm
settle/info/trigger time out) and the downstream R30 (/run/udev/tags/ never
created → logind seat enumeration empty). Everything above R21 is DONE and boots
udev far enough to write /run/udev/data with the master-of-seat tag; the tag
INDEX (/run/udev/tags/) + control socket are the remaining gaps.

## 4 Netlink NETLINK_KOBJECT_UEVENT transport (proto 15)

### 4.1 Group routing
- RAW kernel uevents (`action@devpath\0…`) broadcast to **group 1 ONLY**
  (`netlink_broadcast(uevent_sock, group=1)`). udevd binds `nl_groups=1`.
  Delivering raw to a cooked (grp 0/2) monitor makes libudev peek→magic-fail→
  never consume → PID1 busy-loop ("Looping too fast"). [R01]
- COOKED libudev messages (udevd `sendmsg` with `libudev\0` magic) rebroadcast to
  grp2 (UDEV_MONITOR_UDEV) + grp0 monitors, EXCEPT the sender and grp1-only
  sockets. [R02]

### 4.2 recv semantics (recvmsg / recvfrom / read)
- `MSG_PEEK` leaves the datagram queued; `MSG_TRUNC` returns the FULL datagram
  length. libudev sizes with `recvmsg(len=0, MSG_PEEK|MSG_TRUNC)` then consumes.
  Dropping either destroys the message. [R03]
- **SCM_CREDENTIALS**: recvmsg with a control buffer MUST emit one cmsg
  `{SOL_SOCKET, SCM_CREDENTIALS, ucred{pid:0,uid:0,gid:0}}`. sd-device-monitor's
  `device_monitor_receive_device` DROPS any uevent lacking it or with uid≠0
  ("No sender credentials received, ignoring message"). [R04]
- **source nl_groups**: the returned `sockaddr_nl.nl_groups` = the multicast group
  (1 = UDEV_MONITOR_KERNEL raw, 2 = UDEV_MONITOR_UDEV cooked), NOT 0. libudev
  treats `nl_groups==0` as untrusted unicast and drops it. [R05]

### 4.3 poll/epoll wakeup
- The socket carries a shared `PollSubscribers`, wired into its inode
  (`poll_subs_arc`); `enqueue` calls `notify()` so a task in `epoll_wait`/`ppoll`
  wakes on delivery (Linux `sk_data_ready`). `poll()` reports POLL_IN iff
  `rx_queue` non-empty. [R06]

### 4.4 sendmsg iovec coalescing
- Netlink is DATAGRAM: `sendmsg` with N iovecs = ONE datagram = concatenation.
  sd-device-monitor sends cooked uevents as `[libudev header][properties]` across
  2 iovecs; sending 2 datagrams gives the monitor a header-only then props-only
  pair it can't parse. Coalesce, send once. [R07]

### 4.5 bind / membership
- `bind` nl_groups sets the subscription mask; `setsockopt(SOL_NETLINK,
  NETLINK_ADD_MEMBERSHIP, grp)` adds one group; `getsockname` returns the port_id.
  Socket-activated sockets (systemd binds, passes fd) share the same
  NetlinkSocket across fork — delivery + rx_queue survive the fd handoff. [R08]

## 5 Uevent message format + coldplug

### 5.1 Envelope (raw)
`"<action>@<devpath>\0ACTION=<action>\0DEVPATH=<devpath>\0SUBSYSTEM=<subsys>\0
<extra k=v…>\0SEQNUM=<n>\0"`. [R09]

### 5.2 Per-subsystem required keys
| subsystem | keys (Linux) |
|---|---|
| drm | MAJOR MINOR DEVNAME=dri/<n> DEVTYPE=drm_minor |
| input | (event/mouse) MAJOR MINOR DEVNAME=input/<n> |
| tty | MAJOR MINOR DEVNAME=<n> |
| block | MAJOR MINOR DEVNAME=<n> DEVTYPE=disk|partition |
| net | INTERFACE=<if> IFINDEX=<n> (no MAJOR/MINOR) |
| char misc/etc | MAJOR MINOR DEVNAME |
Devices with a `modalias` sysfs attr also emit `MODALIAS=` (drivers autoload).
[R10, R11] — **AUDIT every subsystem we emit against Linux `add_uevent_var`.**

### 5.3 Coldplug re-trigger
- Writing `add`/`change`/`remove` to `/sys/devices/.../<dev>/uevent` MUST re-emit
  the full uevent (env harvested from the device), Linux `uevent_store`. This is
  how `systemd-udev-trigger.service` coldplugs. Every device's `uevent` file needs
  a write handler that calls the emit path — not just drm. [R12, R29]

### 5.4 seqnum
- `/sys/kernel/uevent_seqnum` reads the current monotonic SEQNUM; each emit
  increments it. udevd checks ordering. [R13]

## 6 sysfs device model

### 6.1 Class tree
`/sys/class/<subsys>/<dev>` → symlink to `/sys/devices/.../<dev>`. [R14]

### 6.2 Device dir
Per `/sys/devices/.../<dev>/`: `uevent` (r: env dump, w: re-trigger §5.3),
`dev` = `"<maj>:<min>\n"`, `subsystem` → `../../../class/<subsys>` (udev reads
SUBSYSTEM from this symlink target), plus the per-class attrs 71-*.rules match on.
[R15, R16, R17]

### 6.3 dev index
`/sys/dev/char/<maj>:<min>` and `/sys/dev/block/<maj>:<min>` → device dir. libudev
`udev_device_new_from_devnum` uses these. [R18]

### 6.3a GROUNDED GAPS found 2026-07-03 (audit of the actual code)
The uevent `DEVPATH` MUST resolve to a real `/sys` dir with a `uevent` file and
a `subsystem` symlink, or udevd reads `/sys<DEVPATH>/uevent` → ENOENT → the
device is NEVER processed. Concrete defects:
- **BLOCK devpath points to a nonexistent /sys path.** `sysfs::bus::dev_root_canon`
  maps `bus=="block"` via the `_ =>` arm to `"devices/platform"`, so a disk emits
  `DEVPATH=/devices/platform/vda` — but no `/sys/devices/platform/vda` exists
  (block.rs only builds `/sys/block/<name>`). udevd can't process ANY block
  device → no `/dev/disk/by-{uuid,label,partuuid}`, no block tags. FIX: build a
  `/sys/devices/virtual/block/<name>/` tree (uevent+dev+subsystem→block) and
  point `/sys/block/<name>` + `/sys/class/block/<name>` at it; emit
  `DEVPATH=/devices/virtual/block/<name>`.
- **BLOCK uevent env missing `DEVTYPE=disk|partition`** (`dev_uevent_env` only
  emits MAJOR/MINOR/DEVNAME/MODALIAS for non-pci). udev block rules key on DEVTYPE.
- **BLOCK `/sys/block/<dev>/uevent` is RO (`RO_PERM`) with no `store`** → R12
  coldplug write (`systemd-udev-trigger`) fails EACCES. Add `SysfsOps::store` that
  re-emits + set the attr writable.
- **`/sys/class/` has only drm/net/tty.** Missing class dirs udev rules reference:
  block, input, backlight, leds, sound, hidraw, misc, graphics, pci_bus, drm_dp_aux.
  Each device's subsystem symlink must target its `/sys/class/<subsys>`.
- **`/sys/kernel/uevent_seqnum` absent** — legacy path; modern udevd tracks the
  per-message SEQNUM so likely non-blocking, but Linux exposes it.

Fix these as ONE device-model pass (not per-boot), then re-run §11 acceptance.

### 6.4 Per-class attrs (audit against the rules that gate the greeter)
- drm/card*: enough for `71-seat.rules` (SUBSYSTEM+KERNEL match only → minimal).
- input: `capabilities/*`, `name` (for `73-seat-late.rules`, libinput).
- Full audit: every attr any installed `/usr/lib/udev/rules.d/*.rules` reads on a
  device we emit. [R19]

## 7 devtmpfs /dev nodes [R20]
Each registered device gets `/dev/<name>` (char/block, correct maj:min, mode) via
`35` `device_add` → devtmpfs publish BEFORE the add uevent (so the node exists
when udevd processes the event). Modes per Linux defaults; udev `uaccess`/rules
refine ACLs.

## 8 udevd control socket (AF_UNIX) [R21] — LIVE GAP
systemd creates `/run/udev/control` (AF_UNIX SOCK_SEQPACKET, socket-activated),
passes the fd to udevd. `udevadm settle/trigger/info/control` connect + send a
`udev_ctrl_msg`; udevd MUST wake on it and reply. Currently `udevadm settle` →
"Connection timed out": udevd never services the control socket.

### 8.1 AF_UNIX delivery wakeup [R22]
A datagram/seqpacket delivered to an AF_UNIX socket MUST notify the receiver's
`PollSubscribers` (mirror of §4.3 for netlink) so a task in `epoll_wait` wakes.
**Verify** `unix_sock` enqueue calls `notify()` on the PEER's subs AND that a
socket-activated (passed-fd) control socket shares the subs its inode exposes to
epoll. This is the prime suspect for R21.

## 9 sd-device / sd-event syscall + fs surface
- 9.1 inotify: udevd watches `/dev` + `/run/udev` (IN_CREATE/DELETE/MOVED_TO); the
  watch descriptors must fire. [R23]
- 9.2 sd-event loop: epoll_pwait2, signalfd (SIGCHLD/SIGTERM), timerfd. [R24]
- 9.3 mount(2): devtmpfs mount, MS_MOVE/MS_BIND/MS_REC for sandboxes. [R25]
- 9.4 statx / newfstatat / openat2(RESOLVE_*) on /sys,/dev,/run. [R26]
- 9.5 pidfd poll: readable only after target exit (sd-event child source). [R27]
- 9.6 `/proc/<pid>/fd` lists the target pid's fds. [R28]

## 10 logind seat attach
- 10.1 startup enumeration: `sd_device_enumerator_add_match_tag("master-of-seat")`
  reads `/run/udev/tags/master-of-seat/` (created by udevd, §2). If udevd's tag
  index is absent (current bug: `/run/udev/tags/` missing), enumeration is empty →
  no seat. Root cause is udevd not completing tag write — trace to R12/R21. [R30]
- 10.2 live: logind grp2 monitor receives the cooked add (tag in props) → attach →
  `/run/systemd/seats/seat0` with `CAN_GRAPHICAL=1`. [R31]

## 11 Acceptance (Test-contract)
On a live-gnome boot, after `graphical.target`:
1. `/run/udev/data/c226:0` contains `G:master-of-seat`. (DONE)
2. `/run/udev/tags/master-of-seat/c226:0` exists. (FAIL today)
3. `udevadm settle` returns 0 within 5s (not timeout). (FAIL today)
4. `loginctl seat-status seat0` shows `card0` under Devices + `Can graphical: yes`.
5. gdm spawns a greeter session (gnome-shell `--gdm-mode`); the login screen
   renders.

Verify BOTH arches (x86_64 + aarch64) per the lockstep gate. Introspect via a
build-time-baked oxdiag oneshot dumping the above to `/dev/ttyS0` (NOT post-hoc
`debugfs -w` — corrupts the metadata_csum ext4).

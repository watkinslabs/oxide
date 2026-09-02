# oxide live-gnome — graphics/greeter campaign hard record (2026-07-06 → 2026-07-07)

Session goal: fully interactive graphical GNOME boot with a rendered greeter on the
`live-gnome` QEMU image (virtio-gpu). Took the boot from "session hangs at setgid"
to "mutter running as a live Wayland compositor, gnome-session in RUNNING state."

Main at session end: origin/main (PRs below all merged). 7 PRs.

================================================================================
## THE FIX CHAIN (in order, each boot-verified)
================================================================================

### 1. PR #2768 — SIGSETXID RT-signal siginfo delivery  [THE session-launch breakthrough]
Branch B618-futex-wake-ttwu. Commit 657a6094 (+ signal_dispatch part).
Files: crates/kernel/syscalls/src/234_tgkill.rs, signal_dispatch.rs, signal.rs

ROOT: gdm-session-worker (multithreaded) calls setgid() to drop to the session
user. glibc implements this via __nptl_setxid: it tgkills SIGSETXID(33) to every
sibling thread and futex-waits for each to run __nptl_setxid_sighandler (SA_SIGINFO)
and ack. That handler REJECTS the signal unless `si_pid == getpid() && si_code ==
SI_TKILL`. oxide delivered RT signals (33-64) with a ZEROED siginfo (si_pid=0):
  (a) tgkill only set the pending bit, never queued a SigInfo;
  (b) the arch frame builder (hal-{x86_64,aarch64}/signal.rs) wrote si_pid/si_code
      ONLY for SIGCHLD (`if let Some(c)=chld`).
So the handler returned without acking → setgid() hung FOREVER → worker never
finished EstablishCredentials → no greeter.

FIX (Linux-exact, sender recorded at send time):
  - 234_tgkill.rs: for sig 33-64, rt_push a SigInfo{pid=sender vtgid, code=SI_TKILL(-6),
    uid=euid} before setting the pending bit.
  - signal_dispatch.rs::sigchld_payload: thread the queued siginfo into the frame for
    RT signals too, not just SIGCHLD. No HAL change (both arches already had the
    Some(chld) write path).

Boot-verified: setgid completes, EstablishCredentials/OpenSession succeed, the full
greeter session launches (gdm-wayland-session + gnome-session-binary + /usr/bin/gnome-shell
all exec and run). Also on this branch: 3 SMP-correctness fixes (wake-ordering,
ttwu-bypass, AF_UNIX read-race) + the per-message SCM_CREDS fix (#2762).

Root-caused via a gated [USTACK] probe in 202_futex.rs (dumps a parked worker's
user return-address chain + find_vma base/inode → offline symbolization of the
stripped PIE).

### 2. PR #2770 — DRM subsystem-symlink depth  [correctness; NOT the greeter blocker]
Branch B619. Commit 74e921d7. File: crates/kernel/sysfs/src/drm.rs
ROOT: /sys/.../drm/cardN/subsystem hardcoded `../../../../class/drm` (4 ups). The
path_id fix nests virtio-gpu deep under PCI (devices/pci0000:00/<bdf>/virtioN/drm/
cardN, depth 6) → dangling symlink → /sys/devices/pci0000:00/class/drm.
FIX: compute the climb dynamically via bus::ups_prefix(drm_device_path). Ruled OUT
as the card0-ENODEV cause (logind reads subsystem by readlink-basename, so wrong
depth still gave "drm").

### 3/4. PRs #2772, #2774 — gated diagnostic probes
[LGD] (B620): 257_openat/267_readlinkat trace of logind's card0 classification syscalls.
[VTIO] (B621): 016_ioctl/vt.rs trace of the display stack's VT ioctl handshake.
Both gated debug-boot; kept permanently per the keep-gated rule.

### 5. PR #2776 — DRM node i_rdev  [unblocked mutter GPU open]
Branch B622-drm-node-rdev. Commit 3e913b1e.
File: crates/drivers/drm/src/node/publication.rs (make_card_inode + make_render_inode)

ROOT: the bespoke /dev/dri/cardN inode was built WITHOUT .rdev(), so stat(2)
returned st_rdev=0. mutter reads st_rdev and passes it to logind's
TakeDevice(major,minor); with 0:0, logind's sd_device_new_from_devnum(0:0) misses →
ENODEV → gnome-shell "No GPUs found" → exits. EVERYTHING ELSE WORKED (udev tracked
card0 on seat0, logind granted uid-979 ACL, session c1 had seat=seat0 vtnr=1) —
those use the sysfs uevent MAJOR/MINOR, not the inode i_rdev, which masked the bug.
This also explained the "zero card0 syscalls at TakeDevice" (logind looked up 0:0,
not 226:0).

FIX: .rdev(Devt::new(DRM_MAJOR, N).raw()) on card + (226, 128+N) on render node,
per Linux init_special_inode.
Boot-verified: "Created gbm renderer for '/dev/dri/card0'" — TakeDevice succeeds.

Root-caused by injecting SYSTEMD_LOG_LEVEL=debug into logind: loop-mount is
unprivileged-blocked, so used `debugfs -w -R "mkdir /etc/systemd/system/
systemd-logind.service.d"` + `debugfs -w -R "write <conf> .../debug.conf"` on
output/live-gnome-x86_64-root.img. logind then logged: "card0: Found udev node
/dev/dri/card0 for seat seat0", "Changing ACLs ... uid 0→979 add", "Sending reply
about created session: id=c1 ... seat=seat0 vtnr=1", and the bare
"System.Error.ENODEV" TakeDevice reply — which proved the session/seat were FINE
and the bug was elsewhere (the rdev).

### 6. PR #2779 — KMS plane enumeration  [mutter runs as Wayland compositor]
Branch B623-drm-obj-properties. Commit 3a09043f.
Files: crates/drivers/drm/src/uapi.rs, node.rs, modeset.rs (+ drm debug-boot feature)

Three linked fixes so mutter finishes modeset (was "No available primary plane
found for CRTC 1" → gnome-shell exit code=1):
  a. **DRM_IOCTL_MODE_GETPLANERESOURCES had the WRONG ioctl NUMBER**: 0xc00864b5
     (size field 0x08=8) vs the real 0xc01064b5 (size 0x10=16 — drm_mode_get_plane_res
     is 16 B padded). mutter's GETPLANERESOURCES fell through to `_ => ENOTTY`, so
     it saw ZERO planes and never found a primary plane. THE key fix.
  b. Implemented DRM_IOCTL_MODE_OBJ_GETPROPERTIES + DRM_IOCTL_MODE_GETPROPERTY
     (were defined in uapi but NOT dispatched → ENOTTY, which made mutter abort CRTC
     creation with "Inappropriate ioctl"). Planes expose the immutable "type" enum =
     PRIMARY (mutter picks the CRTC primary plane from it); CRTC/connector report
     zero props (legacy path needs none).

Boot-verified: [DRMPROP planeres count=1], getplane possible_crtcs=0x1, plane
objprops n=1, getprop id=16 (type enum). "No available primary plane" GONE.
gnome-session reaches "Entering running state" (WINDOW_MANAGER/PANEL/DESKTOP/
APPLICATION/RUNNING); gnome-shell no longer exits. mutter is a live Wayland
compositor.

LESSON: audit DRM ioctl NUMBERS (the size field), not just whether a handler exists.
All other DRM mode ioctl constants were checked against Linux and are correct; only
GETPLANERESOURCES was wrong.

### 7. PR #2780 — devfs CLONE_NEWNS inode isolation  [correctness; partial /dev/null fix]
Branch B624-devfs-ns-inode-isolation. Commit 54e32ecd.
File: crates/kernel/kernfs/src/tree.rs (deep_clone)

ROOT: deep_clone (snapshot_ns, the CLONE_NEWNS /dev clone) shared each device-node
leaf inode via Arc::clone. Device nodes carry per-namespace MUTABLE metadata
(i_uid/i_gid/i_mode a chmod/chown writes), so two mount namespaces sharing the Arc
meant one namespace's `chmod /dev/null` mutated /dev/null in EVERY other namespace.
FIX: deep_clone now COPIES CharDev/BlockDev leaves per namespace (shares immutable
i_op/i_fop/i_private/rdev + routing ino); procfs/sysfs files + symlinks stay shared.
Boot-verified no regression. Does NOT by itself fix the greeter (see below).

================================================================================
## THE REMAINING BLOCKER (fully characterized, not yet fixed)
================================================================================

Symptom: greeter wizard app (gnome-initial-setup, and ibus-daemon, X11 frames client)
fails to spawn:
  gnome-session-binary: WARNING: Failed to start app: Unable to start application:
  Failed to open file to remap file descriptor (Permission denied)

Mechanism (proven with debug-eacces [EACCES] + [NULLCHOWN] probes):
  - glib g_spawn opens /dev/null to remap unused child fds → EACCES.
  - /dev/null (the built-in devfs inode, ino 0x2000_0001, make_null_inode 0o666) has
    its owner rewritten to uid 998 (geoclue), mode 0o620 (rw-rw----) → uid 979
    (greeter) is "other" → no access → EACCES.
  - [NULLCHOWN] trace: /dev/null's uid bounced 193→114→0→979(greeter)→995→0→998(geoclue).
    Each chowning process had exe_path=/proc/self/fd/9 (systemd exec-via-fd style).
  - Mechanism: systemd resets device-node ownership per session/service via
    fchownat(fd, "", AT_EMPTY_PATH) on an open /dev/null fd (see the BUG-E comment in
    syscalls/src/perms_common.rs — it was added for /dev/console). Each service chowns
    /dev/null to ITS uid. Because oxide backs /dev/null with a SINGLE SHARED inode,
    the last chown (geoclue 998) wins globally and locks the greeter (979) out.
  - In real Linux this is harmless because each session/service's private /dev has an
    INDEPENDENT /dev/null inode (systemd PrivateDevices tmpfs + bind/mknod), so chowning
    it is isolated. The #2780 fix isolates the CLONE_NEWNS/unshare path but NOT the
    systemd-PrivateDevices tmpfs+bind path that the services actually use.

FIX DIRECTION (next session):
  - Make the systemd-PrivateDevices per-service /dev give /dev/null (and zero/full/
    random/urandom/tty) INDEPENDENT inodes, so a service's fchown stays isolated. This
    is the mount/devfs-population path (tmpfs /dev + how oxide populates/bind-mounts the
    API device nodes), NOT deep_clone.
  - Decisive next probe: add an inode-POINTER (not just ino) to a chown trace on
    ino 0x2000_0001 to confirm whether services hit the ns0 built-in or a per-ns copy,
    and to see how a service's /dev/null resolves to the shared built-in.

================================================================================
## DIAGNOSTIC METHODS THAT WORKED (reusable)
================================================================================
- Inject logind/systemd debug WITHOUT rebuilding the rootfs: loop-mount is
  unprivileged-blocked; use `debugfs -w -R "mkdir ..."` / `debugfs -w -R "write
  <localfile> <path>"` directly on output/live-gnome-x86_64-root.img. For a fast boot
  keep the KERNEL non-debug and let the userspace drop-in do the logging.
- Gated kernel probes behind cargo features (debug-boot / debug-eacces), wired through
  the crate feature graph (e.g. drm crate needed its own `debug-boot = []` added +
  `drm/debug-boot` in syscalls' debug-boot). ALWAYS verify the probe string is in the
  built kernel.elf (`strings kernel.elf | grep TAG`) — a missing crate feature silently
  cfg's the probe out (cost 2 boots here).
- Build with debug: `cargo run -p xtask -- kernel --arch x86_64 --features <feat>` then
  `xtask artifacts` — plain `xtask kernel` is DEFAULT (no debug) features.
- imagectl reads the MAIN-tree target/artifacts; from a worktree, cp kernel.elf into
  ../kernel/target/artifacts/x86_64/ before build-boot.
- Boots flaky-hang early (~t=30-60, chronic intermittent wedge) ~1/3 of the time; a
  short log that stalls before userspace is a hang, re-boot. debug builds ~2x slower
  wall-clock; the greeter/TakeDevice is ~kernel-t=230-240, so a verbose build needs
  ~400s+ wall or a non-debug kernel.

================================================================================
## KEY FILE POINTERS
================================================================================
- RT signal delivery: crates/kernel/syscalls/src/234_tgkill.rs, signal_dispatch.rs
- DRM node/inode + ioctls: crates/drivers/drm/src/{node.rs, node/publication.rs,
  modeset.rs, uapi.rs, registry.rs}; virtio-gpu DrmDriver impl in
  crates/drivers/drv-virtio-gpu/src/device.rs
- devfs /dev/null + static nodes: crates/kernel/devfs/src/misc.rs (make_null_inode,
  ino 0x2000_0001, 0o666)
- devfs namespace clone: crates/kernel/kernfs/src/tree.rs (deep_clone)
- chmod/chown convergence: crates/kernel/syscalls/src/perms_common.rs (notify_change,
  do_chown; BUG-E AT_EMPTY_PATH comment)
- DRM sysfs: crates/kernel/sysfs/src/drm.rs

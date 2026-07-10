# kernel-audit2 - GNOME desktop boot priority audit

Status: DRAFT 2026-07-09. Scope: kernel systems needed for a bootable GNOME desktop.
Goal: prioritize needs over wants. Other filesystems, full BPF, perf, NUMA, kexec, and exotic hardware are lower priority unless they block the desktop path.

## 1. Priority model

| Priority | Meaning |
|---|---|
| P0 | Blocks boot, systemd progression, rootfs integrity, or basic login/session startup. |
| P1 | Needed for a usable graphical desktop once base boot is stable. |
| P2 | Linux completeness or quality work that can wait until GNOME boots reliably. |

Rule: fix the first failing boot contract before chasing subsystem completeness. A partial Linux surface that satisfies systemd, udev, logind, D-Bus, GDM, Mutter, and GNOME Shell is more valuable than broad but shallow syscall coverage.

## 2. P0 - boot blockers

### 2.1 ext4/VFS correctness and durability

Why: if rootfs metadata corrupts, `mkdir`/`create` fails, or `sync` lies, every higher subsystem produces misleading failures.

Current focus from `ext42.md`:
- Batch journal drain: `sync_fs`, `fsync`, `syncfs`, freeze, and drop must commit the real per-mount `commit_batch()` path.
- Clean unmount ordering: commit pending metadata before setting clean, then commit the clean bit.
- htree create/split: simple `mkdir`/`create` must not return false ENOSPC/DirFull in normal Linux-scale directories.
- jbd2 crash model: batching reopens revoke/checksum questions.
- Error mapping: capacity errors should surface as ENOSPC, corruption as EIO.

Exit gate:
- Hosted ext4 stress over real image fixtures passes.
- Boot rootfs can create journald directories/files repeatedly under batching.
- Remount after stress is clean and walkable.

### 2.2 udev, devfs, sysfs, and device events

Why: GNOME desktop boot depends on udev discovering block, input, GPU, sound, tty, and miscellaneous devices. Missing or malformed uevents cause systemd/udev units to wait, skip devices, or create wrong permissions.

Audit source:
- `docs/60-udev-kernel-contract.md`

Needed surface:
- Reliable `/dev` nodes for block devices, tty/ptmx/pts, input, DRM/fb, sound, random/null/zero/full, shm, log, kmsg where expected.
- sysfs class/device hierarchy enough for udev rules.
- block uevent fields including `DEVTYPE=disk|partition`, major/minor, subsystem, driver/modalias where relevant.
- input event metadata for libinput.
- DRM/card metadata for GDM/Mutter discovery.
- sound device metadata if PipeWire/WirePlumber probes it.
- udev tags/index behavior in `/run/udev` must not silently fail.

Exit gate:
- `udevadm settle` completes.
- `/run/udev/data` and tags are populated for block/input/DRM devices.
- No long waits on missing udev devices during systemd boot.

### 2.3 systemd mount contract

Why: systemd uses mount namespaces, bind mounts, recursive propagation, tmpfs mounts, and pivot-root/switch-root idioms before the graphical stack starts.

Needed surface:
- `/run`, `/tmp`, `/dev/shm` tmpfs mounts.
- mount propagation: private/shared/slave semantics for systemd service sandboxes.
- bind mounts, recursive bind, move_mount, old `mount(2)` compatibility.
- `pivot_root`, `chroot`, `open_tree`, `fsmount`, `move_mount`, `mount_setattr` enough for systemd.
- `/proc/self/mountinfo`, `/proc/mounts`, `statmount`, `listmount` enough for probes.

Exit gate:
- systemd reaches multi-user/graphical target setup without namespace or mount-unit loops.
- Hosted mount namespace tests reproduce and pass systemd sandbox patterns.

### 2.4 cgroup v2 for systemd

Why: systemd treats cgroup v2 as core process management, not optional decoration.

Needed surface:
- Unified cgroup v2 mount.
- `cgroup.controllers`, `cgroup.subtree_control`, `cgroup.procs`, `cgroup.threads`, `cgroup.events`.
- Enough delegation semantics for user sessions.
- CPU/memory/io/pids files that systemd probes must parse and return sensible values.
- PSI files should accept triggers or cleanly behave as Linux expects.

Exit gate:
- systemd creates service scopes/slices without cgroup errors.
- User session scopes can be created for GDM/logind.

### 2.5 AF_UNIX, netlink, epoll, and D-Bus path

Why: GNOME is D-Bus heavy; systemd, logind, polkit, GDM, PipeWire, portals, and GNOME Shell all depend on AF_UNIX and epoll correctness.

Needed surface:
- AF_UNIX stream and datagram reliability.
- `SCM_RIGHTS` and `SCM_CREDENTIALS`.
- Correct peer credentials.
- Epoll level/edge behavior under socket readiness.
- Netlink enough for udev, rtnetlink probes, route/address notifications, and NetworkManager startup.
- Abstract namespace sockets.

Exit gate:
- dbus-broker starts and accepts system bus clients.
- systemd-logind, polkit, GDM, and basic user bus stay alive.

### 2.6 procfs/sysfs basics for systemd and desktop daemons

Why: many services treat malformed proc/sys files as kernel capability signals.

Needed procfs:
- `/proc/self`, `/proc/thread-self`
- `/proc/<pid>/fd`, `fdinfo`, `status`, `stat`, `cmdline`, `comm`, `mountinfo`, `maps`, `smaps` enough for probes
- `/proc/meminfo`, `stat`, `uptime`, `loadavg`, `vmstat`, `pressure/*`
- `/proc/filesystems`, `swaps`, `partitions`, `devices`, `sys/kernel/*` as used by systemd/udev

Needed sysfs:
- `/sys/devices`, `/sys/class`, `/sys/block`, `/sys/bus`, `/sys/module`
- device attributes queried by udev rules, logind, libinput, DRM, sound, and NetworkManager

Exit gate:
- systemd-analyze critical-chain shows no waits caused by malformed proc/sys answers.

## 3. P1 - usable graphical desktop

### 3.1 DRM/KMS and framebuffer path

Why: GNOME/Mutter needs real display discovery and modesetting. A booting system without graphics is not the target.

Needed surface:
- `/dev/dri/card*` and render node behavior if applicable.
- DRM ioctls for resource discovery, dumb buffer allocation/mmap, modeset, page flip or equivalent path Mutter can use.
- EDID/mode reporting.
- fbdev fallback only as a fallback; GNOME normally wants DRM/KMS.

Exit gate:
- GDM starts a graphical greeter or Mutter reaches a real display backend instead of falling back to unsupported paths.

### 3.2 Input stack

Why: login requires keyboard/mouse/touchpad through evdev/libinput.

Needed surface:
- `/dev/input/event*`
- evdev ioctls for device identity, capabilities, key/abs/rel bits.
- udev properties for seats and input classification.
- Working keyboard and pointer event delivery.

Exit gate:
- libinput lists devices and GDM accepts keyboard/mouse input.

### 3.3 TTY, PTY, VT, and logind session semantics

Why: GDM/logind need seats, sessions, VTs, controlling terminals, and PTYs.

Needed surface:
- devpts and `/dev/ptmx`.
- PTY read/write/poll/ioctl behavior.
- VT ioctls enough for logind/GDM/Mutter.
- foreground process groups and session accounting.
- signal/job-control interactions enough for shells and services.

Exit gate:
- logind creates a seat/session.
- GDM can switch to a graphical VT or equivalent active session.

### 3.4 Swap

Why: GNOME can boot without swap on a large-memory VM, but swap is likely needed for a reliable desktop target under realistic memory pressure.

Minimum useful target:
- `swapon` and `swapoff`.
- swapfile on ext4.
- anonymous page-out/page-in.
- swap slot allocator and swap cache.
- `/proc/swaps` and `/proc/meminfo` accounting.
- sane behavior under memory pressure instead of OOMing GNOME services.

Not needed first:
- swap priorities beyond simple ordering.
- discard.
- zswap/zram.
- hibernation.
- cgroup memory swap limits.
- encrypted swap.

Exit gate:
- A memory-pressure boot test can start GNOME with swap enabled and avoid killing core session services.

### 3.5 Basic networking for desktop services

Why: GNOME can boot offline, but NetworkManager and desktop services expect networking primitives to exist.

Needed surface:
- loopback is non-negotiable.
- IPv4/IPv6 sockets enough for local services.
- rtnetlink link/address/route queries and notifications.
- DHCP path if NetworkManager is in the image.
- DNS resolution path through userspace.

Can wait:
- full nftables.
- advanced qdisc.
- bridge/tun/tap unless NetworkManager blocks.
- raw socket edge cases.

Exit gate:
- NetworkManager starts without wedging boot.
- loopback and one virtio-net interface can be configured.

## 4. P2 - defer until GNOME path is stable

| System | Reason to defer |
|---|---|
| Other filesystems | ext4 rootfs is enough for GNOME boot. |
| Full BPF verifier/JIT/maps | Needed for Linux completeness; not first GNOME blocker if probes degrade cleanly. |
| Full perf/PMU | Developer tooling, not desktop boot. |
| NUMA policy | VM desktop target can run single-node. |
| kexec | Not needed for desktop boot. |
| Module loading depth | Built-in drivers are acceptable for first desktop target. |
| Advanced io_uring | Useful for performance, not first boot blocker. |
| cpufreq/power governors | Nice later; idle/reboot/poweroff enough first. |
| Exotic drivers | Virtio GPU/input/block/net/sound first. |

## 5. Recommended audit documents

Write focused follow-up reports in this order:

1. `udev2.md` - udev/sysfs/devfs/netlink device contract.
2. `systemd2.md` - mount namespaces, cgroups, procfs, tmpfs, pid/session blockers.
3. `desktop2.md` - DRM/KMS, input, VT, logind, GDM, GNOME Shell requirements.
4. `swap2.md` - minimal swapfile-on-ext4 design and VM pressure tests.

## 6. Immediate work order

1. Finish `ext42.md` P0 fixes.
2. Run the real-rootfs metadata stress reproducer and convert the useful parts into non-ignored fixture tests.
3. Audit udev with live boot logs and `docs/60-udev-kernel-contract.md`.
4. Audit systemd units that wait/fail before graphical target.
5. Only then start swap implementation, unless memory pressure is already causing OOMs before the udev/systemd path is stable.

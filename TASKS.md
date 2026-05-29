# Open tasks & deferred work

Single source of truth for things that need revisiting. Update on
every PR that opens, closes, or pivots an item. Tag closed items
with their merging PR and date.

## Vision (set 2026-05-29)

Production-grade, drop-in Linux replacement on musl. Server-class
now → workstation-capable later. RedHat/systemd-competitive: real
init+service manager (systemd), real package manager (RPM/dnf), real
multi-user (NSS+PAM), real networking (networkd/resolved), real
logging (journald). **No hacks, no stubs, no placeholders, no
example/smoke-only shortcuts** — every component is the real upstream
implementation, cross-built for x86_64 AND aarch64, validated against
real-world use. Each kernel gap that surfaces is fixed in the same PR
that surfaces it. Every PR: both-arch boot smoke + spec-lint clean.

Research cache: `research/systemd-musl.md`, `research/kernel-gaps-systemd.md`,
`research/distro-inventory.md`. Re-read before touching that area.

## Strategy note — systemd on musl

- systemd **v259** has in-tree musl support (`meson -Dlibc=musl`).
  Fallback: **v257 + OpenEmbedded/Yocto musl patch series** (postmarketOS
  ships 257 on musl as PID 1 in production). Chimera uses dinit, NOT
  systemd — the old "Chimera patchset" handoff note was wrong; ignore.
- **systemd must be DYNAMICALLY linked** (it `dlopen()`s heavily; musl
  forbids dlopen from static binaries). oxide2 is static-musl today, so
  a real shared-library system tree (`/lib`, `/usr/lib` + `ld-musl`) is
  a hard prerequisite → Track L.

## Track K — kernel prerequisites for systemd (BLOCKERS, do first)

Sequential-ish; K1+K2 are the hard gates. Implement to FROZEN specs
`26` (namespaces+cgroups), `16` (vfs), `27` (security), `19` (dev/proc/sysfs).

| Id | Work | Spec | Status |
|---|---|---|---|
| K1 | cgroup v2 unified hierarchy: real cgroupfs at `/sys/fs/cgroup`; controllers cpu/cpuset/io/memory/pids; `cgroup.procs`/`threads`/`controllers`/`subtree_control`/`events`(populated notify)/`kill`/`freeze`/`stat`; `/proc/<pid>/cgroup` real | `26` | **next** |
| K2 | real mount: MS_BIND, MS_REC, MS_MOVE, propagation (SHARED/PRIVATE/SLAVE/UNBINDABLE), pivot_root; real fs types proc/sysfs/devtmpfs/tmpfs/cgroup2 | `16` | not started |
| K3 | per-mount-namespace mount tables: CLONE_NEWNS real (copy-on-unshare, peer propagation) | `26` | not started |
| K4 | rtnetlink RTM_GETLINK dump fix (networkd link enum; also fixes iproute2 `ip link` EOF) | `25` | not started |
| K5 | verify/complete: SCM_CREDENTIALS/SO_PEERCRED real creds; NETLINK_KOBJECT_UEVENT broadcast (udev); `/proc/<pid>/ns/*` nodes; `/dev/kmsg` (journald); memfd F_ADD_SEALS | `24`,`19` | not started |
| K6 | new mount API: fsopen/fsconfig/fsmount/move_mount/open_tree + mount_setattr (systemd 254+) | `16` | not started |

## Track L — shared-library userspace (systemd needs dynamic linking)

| Id | Work | Status |
|---|---|---|
| L1 | shared musl runtime + system lib tree (`/lib`,`/usr/lib`, ldso config); dynamic-link build policy + xtask staging of `.so`s | not started |
| L2 | cross-build shared deps both arches: libcap, libxcrypt, util-linux libs (libmount/libblkid/libuuid/libsmartcols), libseccomp, kmod, pcre2, zstd, lz4, liblzma(xz), openssl, libgcrypt+libgpg-error, acl/attr, libidn2, linux-pam, dbus + dbus-broker | not started |

## Track D6 — systemd (multi-PR)

| Id | Work | Status |
|---|---|---|
| D6.0 | vendor systemd v259.6 (`-Dlibc=musl`) [fallback 257.6+OE]; meson dynamic cross-build both arches; produce systemd, systemctl, journalctl, udevadm, busctl | not started |
| D6.1 | PID-1 swap `/sbin/init`→systemd; minimal real unit set; reach `multi-user.target` with getty+login | not started |
| D6.2 | systemd-journald + `/dev/kmsg`; `journalctl` shows boot log | not started |
| D6.3 | systemd-udevd (devtmpfs + uevent netlink); device nodes + rules | not started |
| D6.4 | systemd-networkd + `.network` units (replace rcS ifconfig); eth0 up via DHCP | not started |
| D6.5 | systemd-resolved + nss/resolv integration | not started |
| D6.6 | systemd-logind (sessions/seats) + pam_systemd; closes T14 pam_unix real | not started |
| D6.7 | dbus/dbus-broker system bus; sd-bus IPC round-trip validated (`busctl`, `systemctl` over bus) | not started |
| D6.8 | timesyncd (NTP), systemd-tmpfiles, sysusers, hostnamed/localed | not started |

## Track D7 — drop busybox

| Id | Work | Status |
|---|---|---|
| D7.1 | replace busybox-only cmds with real: halt/reboot/poweroff (systemd), mount/umount (util-linux, fix non-PIE), dmesg (util-linux), stty (coreutils), fdisk/swapon (util-linux), nc/wget (real), mdev→udev | not started |
| D7.2 | remove busybox vendor entirely; `/sbin/init`=systemd; both arches boot with zero busybox | not started |

## Track P — production-distro completeness (beyond D7)

| Id | Work | Status |
|---|---|---|
| P1 | RPM toolchain (master-plan phase 16): rpm + dnf; build real `.rpm` of the vendored tree; working install/upgrade/remove | not started |
| P2 | cron (cronie or systemd timers), full journald logging, NTP | not started |
| P3 | real multi-user: NSS modules, full PAM stack (pam_unix real), useradd/passwd/login end-to-end, sudo | not started |
| P4 | filesystem robustness: ext4 RW hardening, fstab mounts, swap enable, mount of additional fs | not started |
| P5 | glibc-compat consideration for workstation apps (long-horizon; eval after server distro solid) | deferred-eval |
| P6 | graphical stack: Wayland + GNOME (explicit long-horizon; server-first per direction) | deferred-eval |

## Open follow-ups (folded into tracks above)

- iputils ping ICMP runtime path → validate under K-track socket work.
- util-linux `mount` non-PIE → fix in D7.1 / L-track.
- T14 pam_unix nested-fork/dlopen → resolved by L2 (real shared libc) + D6.6.
- T15 ARM dynamic bash `/bin/sh` wedge → resolved by L1 dynamic-exec path audit.

## Validation discipline

Every PR: `make smoke` both arches reach `oxide login:` (or systemd
`multi-user.target`). New per-feature smokes: cgroup tree mount+populate,
mount bind/move/propagate, systemd boot to multi-user.target, `journalctl`
shows logs, networkd brings up eth0, `systemctl status` works, dbus
round-trip. spec-lint clean before commit AND PR.

## Recently closed

- **D5 iputils 20240117** — closed by **#1347 F263**. ping, tracepath,
  clockdiff, arping; static-musl both arches (meson/ninja). busybox
  `ping` applet dropped; iputils owns /bin/ping. Follow-ups below.
- **D4 iproute2 6.10.0** — closed by **#1346 F262**. ip/ss/tc/bridge/
  rtmon/lnstat/nstat/ifstat, static-musl both arches.
- **D3 procps-ng 4.0.5** — closed by **#1345**. ps/top/free/vmstat/uptime/etc.
- **D2 shadow-utils 4.16.0** — closed by **#1344**. useradd/passwd/groupadd/etc.
- **D1 util-linux 2.40.2** — closed by **#1343**. login/agetty/su/etc.
- **T17 Vim cross-build + runtime smoke** — closed by **#1330 F250 (ncurses)** + **#1331 F251 (vim cross-build)** + **#1332 F252 (terminfo db)** + **#1334 F254 (less, also ncurses)** + **#1336 F256 (vim_smoke wired)**. Vim ex-mode :qa! exits 0 on both x86 and ARM.
- **T16 Growable kernel heap (vmalloc-equivalent)** — closed by **#1328 F247** (per-instance KAlloc grow hook → PMM buddy via HHDM; STATIC_HEAP back to 64 MiB; hosted test covers grow path).
- **T13 SSH-connect smoke through PAM dlopen** — closed by **#1314 F231** (real PAM dlopen via dynamic sshd + pam_permit.so).
- **T12 wait4 status decode `$?=255`** — closed by **#1320 F237** (clear SIGCHLD pending bit when wait4 drains last zombie).
- **T10 multi-conn ssh smoke** — closed earlier (boot-smoke-ssh.sh tail-tools + pty).

## Notes for the next session

- Kernel-side investigation paths are tracked in `state.md` (short-lived).
  The DURABLE work queue lives here.
- When opening a new branch, add an entry here; when closing, move it to
  "Recently closed" with the merging PR.
- If a task has a multi-step plan, add a `Plan` sub-list under it.

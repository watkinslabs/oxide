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

**Rule (user, 2026-05-29): if a Linux primitive the kernel lacks blocks
the current work, STOP and add it PROPERLY as foundational work before
continuing — never a syscall-layer hack/workaround.** e.g. cgroup mkdir
needs real VFS `mkdir`/`rmdir` inode dispatch (Linux `inode_operations`),
not path-prefix special-casing. Add the missing trait surface, then build
on it. The VFS `Inode` trait is an explicit "v1 subset" — complete it as
each subsystem needs the full Linux surface.

| Id | Work | Spec | Status |
|---|---|---|---|
| K1 | cgroup v2 unified hierarchy: real cgroupfs at `/sys/fs/cgroup`; controllers cpu/cpuset/io/memory/pids; `cgroup.procs`/`threads`/`controllers`/`subtree_control`/`events`(populated notify)/`kill`/`freeze`/`stat`; `/proc/<pid>/cgroup` real | `26` | **done** (PR #1355) — `/bin/cgroup_smoke` exercises controllers/subtree_control/mkdir/pids.max/procs-attach/`proc/self/cgroup`/rmdir, PASS both arches. Fixed: split-newline write EINVAL, vpid→tid membership translation, unified rmdir(2)+unlinkat(AT_REMOVEDIR) core |
| K1b | cgroup v2 controller ENFORCEMENT depth (interface is real+complete in K1; these deepen it): memory.max charge/OOM via per-cgroup page accounting; cpu.weight/cpu.max honored by scheduler; pids counts threads (not just process leaders); io controller wired to block layer; cpuset affinity applied; cgroup.freeze actually freezes (not just flag); /proc/self/mountinfo dynamic cgroup2 line | `26`,`13` | not started |
| K2 | real mount: MS_BIND, MS_REC, MS_MOVE, propagation (SHARED/PRIVATE/SLAVE/UNBINDABLE), pivot_root; real fs types proc/sysfs/devtmpfs/tmpfs/cgroup2 | `16` | **partial** — dynamic /proc/mounts + /proc/self/mountinfo from live table (PR #1358); MS_BIND real + propagation/MS_REMOUNT accepted (PR #1359, `/bin/mount_smoke`). REMAINING: MS_REC recursive bind, MS_MOVE (ENOSYS now), pivot_root, peer-propagation event semantics, mount-record tree |
| K3 | per-mount-namespace mount tables: CLONE_NEWNS real (copy-on-unshare, peer propagation) | `26` | not started |
| K4 | rtnetlink RTM_GETLINK dump fix (networkd link enum; also fixes iproute2 `ip link` EOF) | `25` | not started |
| K5 | verify/complete: SCM_CREDENTIALS/SO_PEERCRED real creds; NETLINK_KOBJECT_UEVENT broadcast (udev); `/proc/<pid>/ns/*` nodes; `/dev/kmsg` (journald); memfd F_ADD_SEALS | `24`,`19` | not started |
| K6 | new mount API: fsopen/fsconfig/fsmount/move_mount/open_tree + mount_setattr (systemd 254+) | `16` | not started |

## Track R — proc/dev/sys realness (make synthetic fses real, in importance order)

Audit (2026-05-30) classified every /proc, /sys, /dev entry REAL/PARTIAL/FAKE.
Build out the fakes, highest-impact first. Note: /proc/<pid>/{exe,cwd,root,fd,ns}
readlink ALREADY real via `sched::proclink`; many /proc files already dynamic.

| Id | Work | Status |
|---|---|---|
| R1 | statfs/fstatfs real per-fs `s_magic` (cgroup2/tmpfs/proc/sysfs/ext4) via `FileSystem::magic()` + mount-table classify; fix `f_namelen` offset — systemd fs-type detection | **done** (PR #1360) `/bin/statfs_smoke` |
| R2 | standard `/dev/{stdin,stdout,stderr,fd}` symlinks → `/proc/self/fd/*` (readlink/ls) + open() fd-link **dup** semantics (`/dev/std*`, `/dev/fd/<n>`, `/proc/<pid>/fd/<n>` share the target's open file description, Linux magic fd-link); fixed init stdio dentry to real `/dev/console` (was `/console`) | **done** (F269) `/bin/dev_smoke` |
| R2a | /proc/<pid>/fd path-keyed lookup + stat: stat()/readlink()/ls of `/proc/{self,<pid>}/fd[/<n>]` resolve via `proc_links::lookup_fd_path` (was: open dup'd via `dup_fd_target` but stat returned ENOENT); /proc/self/<file> readdir↔lookup parity (smaps_rollup, numa_maps, statm, sched, schedstat, autogroup, uid_map, …); `df` shows mounts (statfs now fills f_blocks); bash `child setpgid` ESRCH spam cleared (sys_setpgid/getpgid/getsid route through lookup_by_vpid; aarch64 fork stamps vtgid/pid_ns same as x86) | **done** (PR #1362) `tools/boot-smoke-fs.sh` 37-step sweep both arches |
| R2b | general open()-time symlink follow (ext4 symlinks, `/etc/localtime`, merged-usr `/bin`→`/usr/bin`): a path-walk resolver with ELOOP+O_NOFOLLOW. NOTE: a first whole-path follow loop worked on x86 but hit an undiagnosable arm-only ELOOP (arm UART drops klog mid-syscall — needs a `/proc`-based trace channel before retrying). No ext4 symlinks are opened today, so not yet blocking | not started |
| R3 | real sysfs — `/sys` is a fake-constant devfs overlay, NOT a filesystem. `/sys/class/net/<if>/*` dynamic from netdev registry; `/sys/devices/system/cpu/{online,possible,present}` from real CPU count; register a SysfsFs backend. HIGH: udev + networkd device model | not started |
| R4 | /proc system-wide realness: `/proc/cmdline` real boot cmdline; `/proc/stat` btime + procs from registry; `/proc/net/{tcp,udp,unix}` populated (systemd socket-activation); `/proc/<pid>/fd` inode-open + `fdinfo/` | not started |
| R5 | `/proc/sys` writable sysctls backed by real state (hostname already real); systemd-sysctl applies `/etc/sysctl.d` | not started |
| R6 | intermediate-directory symlink follow (merged-usr `/bin`→`/usr/bin`, `/lib`→`/usr/lib`): component-walk resolver | not started |
| R7 | `/dev/shm` tmpfs mount point (POSIX shm, systemd runtime); /dev/ptmx+pts already real | not started |

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
- **bash command substitution `$(...)` yields empty — FIXED** (B21, PR #1357). It WAS a kernel syscall bug, not bash: signal delivery at the syscall-return boundary did not preserve the interrupted syscall's return value (rax/x0); rt_sigreturn returned 0. SIGCHLD-on-comsub-child-exit was delivered right at the comsub read's return → the read's count was clobbered to 0 → shell saw EOF → empty. Affected every shell (all install SIGCHLD handlers) and every value-returning syscall interrupted by a caught signal. Fixed by saving the return value in the signal frame and restoring it in rt_sigreturn. Regression guard: `/bin/cmdsubst_probe` sigchld case.
- **alarm()/SIGALRM does not wake a task blocked in `read()`** (B20, still open). A `read()` on an empty pipe with `alarm(1)` + SIGALRM handler never returns. The pipe-read EINTR check (PR #1356) only fires once something wakes the parked task; `sys_kill` wakes via `wake_if_sleeping`, but the timer/alarm deadline path doesn't post+wake a task parked in read. Investigate `sched::live::tick_deadline` / itimer delivery to parked tasks.
- **procfs hard-coded static stubs** (`MOUNTINFO_BODY`, fixed `/proc/sys/*` sysctls, the `0::/` cgroup fallback) should become dynamic — systemd reads these expecting real state (mount tracking, sysctl apply). Folds into K-track + K1b (`/proc/self/mountinfo` dynamic). "Don't fake state with constants."

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

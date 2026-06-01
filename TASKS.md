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
| K1b | cgroup v2 controller ENFORCEMENT depth (interface is real+complete in K1; these deepen it): memory.max charge/OOM via per-cgroup page accounting; cpu.weight/cpu.max honored by scheduler; pids counts threads (not just process leaders); io controller wired to block layer; cpuset affinity applied; cgroup.freeze actually freezes (not just flag); /proc/self/mountinfo dynamic cgroup2 line | `26`,`13` | **in progress** — pids-counts-threads DONE (`charge_thread`/`remove_thread`, `subtree_proc_count`=procs+threads); cgroup.freeze REAL DONE (F319): per-task `Task::frozen` + single runqueue enqueue chokepoint + `freeze_task`/`unfreeze_task` + boot `FREEZE_HOOK`. memory.max REAL DONE (F320): per-pid charge tracking in cgroup tree (`try_charge_mem`/`uncharge_mem`/`subtree_mem`, hierarchical limit check, exit uncharges whole footprint, charge migrates on move), wired at `sys_brk` (grow charges delta → ENOMEM-as-old-brk on cap; shrink uncharges); 7 hosted unit tests prove charge/limit/hierarchy/exit-symmetry/migration. Remaining (BLOCKED on preemptive-SMP scheduler — building these now = bolt-on on cooperative-sched sand): cpu.max/weight (needs real preemptive CFS + per-tick runtime accounting), io controller (needs time-based throttle), cpuset affinity (needs SMP). Also: dynamic /proc/self/mountinfo cgroup2 line |
| K2 | real mount: MS_BIND, MS_REC, MS_MOVE, propagation (SHARED/PRIVATE/SLAVE/UNBINDABLE), pivot_root; real fs types proc/sysfs/devtmpfs/tmpfs/cgroup2 | `16` | **DONE** — completed by Track K2V (the mount-table unification, PRs #1393–#1404). MS_BIND=bind-as-clone, MS_REC, MS_MOVE (incl whole subtree), pivot_root, propagation SHARED/PRIVATE/SLAVE/UNBINDABLE + peer groups + event delivery, tmpfs unified into vfs::mount::TABLE, umount detaches table mounts. fs types proc/sysfs/devtmpfs/tmpfs/cgroup2 all real. |
| K3 | per-mount-namespace mount tables: CLONE_NEWNS real (copy-on-unshare, peer propagation) | `26` | **DONE** — completed by K2V U2-b/U4-c: per-ns mount tables (`Mount.ns` + strict `current_ns()` filtering), `sys_unshare(CLONE_NEWNS)` copy-on-unshare via `vfs::mount::snapshot_ns` + `devfs::snapshot_ns`, peer-group propagation event delivery (`propagate_mount`). |
| K4 | rtnetlink RTM_GETLINK dump fix (networkd link enum; also fixes iproute2 `ip link` EOF) | `25` | **DONE** (#1416, F317): handle_getlink dump path verified structurally correct (NLM_F_MULTI RTM_NEWLINK per iface + well-formed NLMSG_DONE); EOF note was stale. Hosted test getlink_dump_ends_with_nlmsg_done + /bin/rtlink_probe (real RTM_GETLINK NLM_F_DUMP → multipart walk + DONE). |
| K5 | verify/complete: SCM_CREDENTIALS/SO_PEERCRED real creds; NETLINK_KOBJECT_UEVENT broadcast (udev); `/proc/<pid>/ns/*` nodes; `/dev/kmsg` (journald); memfd F_ADD_SEALS | `24`,`19` | **DONE** (this session): SO_PEERCRED real peer creds (#1412 UnixPair EndCred snapshotted at socketpair/connect/accept); SO_PASSCRED→SCM_CREDENTIALS cmsg on recvmsg (#1414); `/dev/kmsg` write→klog ring (#1410, klog::kmsg_write); memfd F_ADD_SEALS/F_GET_SEALS + write/truncate enforce (#1411); `/proc/<pid>/ns/*` already real (F117); NETLINK_KOBJECT_UEVENT broadcast + writable sysfs `/sys/class/net/<if>/uevent` trigger (#1415). Probes: scm_smoke, memfd_seal_probe, uevent_probe. |
| K6 | new mount API: fsopen/fsconfig/fsmount/move_mount/open_tree + mount_setattr (systemd 254+) | `16` | **DONE** (#1408/#1409): real fd-backed fs_context (fsopen→fsconfig→fsmount→move_mount via vfs::mount primitives) + open_tree(OPEN_TREE_CLONE)/fspick/mount_setattr (propagation). /bin/fsmount_probe. |

### Track K2V — VFS dentry/mount rebuild (the "big lift", `16§3-7`)

Decided 2026-05-31: do the FULL Linux-faithful model, not a string-table
approximation. Linux keys mounts by `(parent mount, mountpoint dentry)`,
not path strings; per-component path walk crosses mounts via a
dentry→mount map, follows symlinks (depth≤40), honors dirfd + RESOLVE
flags. bind = clone (mount root = arbitrary dentry); MS_MOVE/pivot_root =
relink; propagation = peer groups. The current string mount table +
BindFs-path-rewrite + tmpfs-in-devfs-registry split are all artifacts of
having no dentry cache. docs/16§3 (`path_lookup`), §4 (dcache/icache),
§6 (mount tree), §7 (lock order MountTable<Dentry<Inode<FdTable<Superblock)
already specify this. Decisions: per-dentry children maps (global
open-addressed hash + RCU = perf follow-up, consistent with rest of
kernel); spinlock not RCU initially. Strictly staged, each stage a PR
booting BOTH arches before the next.

**REORDERED 2026-05-31 (user direction): foundation BEFORE wiring, and
verify-left.** The first attempt at V3 (wire symlink-follow into stat/
open) was a `legacy-first + walker-fallback` BOLT-ON on top of the
fragmented string-table/devfs-registry that V5 replaces — i.e. building
on sand and the "minimal" the project forbids. Reverted (branch F282,
never merged). New order: build the fast hosted resolution harness, then
the unified mount tree (the foundation), THEN migrate every path syscall
at once so `path_lookup` is THE resolver — not a fallback. See CLAUDE.md
"How to act on big/cross-subsystem changes".

| Stage | Work | Status |
|---|---|---|
| V1 | ext4 directory-inode `Inode::lookup(name)` — additive per-component child lookup | **done** (#1378 F280: `lookup_child_ino`/`wrap_any_ino` + `Ext4StatInode::lookup`, hosted test `lookup_in_dir_*`) |
| V2 | `path_lookup(start, root, path, flags) → (InodeRef, Dentry)` in vfs + per-dentry dcache; component walk, symlink+ELOOP+depth≤40, `..`, mount-cross hook, RESOLVE flags | **done** (#1379 F281: `vfs::namei`, Dentry children cache, 9 hosted synthetic-tree tests) |
| V3 | **fast hosted resolution harness** (verify-left): a rich ext4 fixture image (nested dirs, symlinks incl. abs/rel/loop, merged-usr `/bin`→`/usr/bin`) + a `cargo test` that points the ext4 global mount at it and drives `vfs::path_lookup` over the REAL ext4 Inode impls — no QEMU. Becomes the dev loop for V4–V7. Replaces the reverted bolt-on | **done** (F283): `tests/walk.img` + `tests/walk_image.rs` (7 tests, ~0.6s) via new `rootfs::set_test_mount`; un-gated the ext4 rootfs Inode layer for host (boot bits `ROOTFS`/`init`/`ImageDisk` stay kernel-only). Covers descent, abs/rel/intermediate(merged-usr R6) symlink follow, ELOOP, O_NOFOLLOW |
| V4 | `Superblock` semantics (docs/16§2) on the per-mount `FileSystem` (which already plays that role) + inode→sb linkage; per-SB inode cache | **in progress** (F284): `FileSystem::root()` added (the `Superblock::root` the walker switches to on mount-crossing, vs the whole-path `lookup(mount_point)` hack); ext4 impl returns ino-2 root dir; hosted test `fs_root_is_root_dir`. REMAINING: `root()` for tmpfs/devfs/procfs/sysfs (fill in V5 when wiring crossing), statfs/sync/umount, per-SB inode cache |
| V5 | **unified dentry-keyed mount tree** — one tree spanning ext4/tmpfs/devfs/proc/sys keyed by mounted-on dentry/inode (drops the string-table + devfs-registry split + BindFs path-rewrite). Fill procfs/sysfs dir `lookup(name)`. Now `path_lookup` is THE resolver | **in progress** (F285): the table already registers `/ /dev /proc /sys /tmp /run /dev/shm`+cgroup+binds (less fragmented than feared). Added `vfs::mount::mount_root_at(abs)` (the crossing bridge: exact-mountpoint fs's `root()` or `lookup(abs)` fallback), hosted test `mount_resolver.rs` (3), installed via `set_mount_resolver` at boot (additive — only `path_lookup` calls it). REMAINING: fill procfs/sysfs dir `lookup(name)` for per-component traversal within them, then V6 wires path_lookup as THE syscall resolver |
| V6 | migrate ALL path syscalls to `path_lookup`: stat/lstat/statx/newfstatat/open/openat/exec/access + namei mutations + real dirfd/*at + symlink-follow + RESOLVE flags. Re-add `/bin/symlink_probe`. (musl stat()/lstat() → `sys_stat` slots 4/6, NOT statx/newfstatat) | **in progress** — V6a (F286): `path_lookup` in-mount whole-path **delegation** (`set_mount_whole_path` → `vfs::mount::mount_whole_path`); when per-component `Inode::lookup` returns Enotdir (procfs whole-path), the OWNING mount resolves its own subtree (not a global legacy fallback). `vfs::mount::install_resolvers()` installs both hooks at boot. Hosted test `delegates_whole_path_for_procfs_style_fs`. V6b (F287): wired `path_lookup` into **sys_stat (slots 4/6)** as THE resolver via `pathresolve::resolve` (global ext4-root dentry); NR_STAT/NR_LSTAT split. `/bin/symlink_probe` PASS (ext4 symlink-follow + stat-crossing into /dev/null, /proc/version[whole-path delegate], /sys); both arches login PASS. FIXED latent bug: `install_resolvers` (whole-path hook) was never committed in F286 → procfs delegation ENOENT'd; lib.rs:672 now calls it. Added `boot-smoke-login KEEP_LOG=path`. V6c (F288): open/openat. V6d (F289): chmod/chown/access/utime/chdir. V6e (F290): exec via `pathresolve::read_exec`. V6f (F291): readlink (no_follow_final). V6g-a (F292): inode-level mutation FOUNDATION — vfs Inode trait gains create_child/unlink_child/symlink_child/mknod_child (default Erofs); Ext4StatInode + tmpfs TmpfsRootInode implement them (keyed parent-ino/registry). **NEXT V6g-b**: switch namei.rs sys_{mkdir,unlink,rmdir,symlink,mknod}+at to `pathresolve::resolve(parent)` → `parent_inode.<op>(name)`, dropping is_ext4_path/mount_for_write/pseudo_* gates; keep landlock; LEAVE link/linkat (O_TMPFILE) + rename (EXDEV) on ext4 path machinery; boot-login both arches (rcS mkdir/touch/rm + dhcpcd) is the only gate — see state.md for the risk list (mountpoint-mkdir, cgroupfs whole-path, B47 /var routing) |
| V6 (status) | — | **DONE** F286–F293 (#1387–#1392): every path syscall (stat/lstat/statx/newfstatat/open/openat/access/chmod/chown/utime/chdir/exec/readlink + namei mkdir/unlink/rmdir/symlink/mknod via parent-inode dispatch) resolves through `vfs::path_lookup`. Open follow-up: link/linkat (O_TMPFILE markers) + rename (EXDEV/cross-parent) still on ext4 path machinery → give them `link_child` + cross-parent inode rename later; tmpfs symlink/mknod inode methods (currently Erofs). |
| V7 | bind-as-clone (mount root = arbitrary dentry); MS_MOVE (relink); pivot_root; MS_REC; propagation peer groups (`shared:N`/`master:N`); per-ns mount tree (docs/16§6 R01) | **DONE** (PRs #1393–#1404, F294–F305): V7-a MS_MOVE, V7-b bind-as-clone (dropped BindFs path-rewrite), V7-c MS_REC, V7-d peer-group IDs; U2 ns-stamping → per-ns resolution + copy-on-unshare; U3 umount-detach + tmpfs unified into vfs::mount::TABLE; U4-a whole-subtree MS_MOVE, U4-b peer-group inheritance on bind, U4-c propagation event delivery, U4-d pivot_root. Mount tree matches docs/16§6. Open follow-ups: per-process root/cwd not yet honored in path_lookup (chroot partial); link/linkat (O_TMPFILE) + rename (EXDEV) still ext4-path not inode-dispatch; tmpfs symlink/mknod inode methods Erofs; drop /var,/tmp,/run from is_ext4_path. _(superseded plan below)_ — V7-a (F294 MS_MOVE): `vfs::mount::move_mount(from,to)` rewrites a TABLE mount's mount_point preserving mnt_id+propagation (implicit tree → parent_id auto-recomputes); sys_mount MS_MOVE wired (was ENOSYS). **The rest of V7 requires the MOUNT-TABLE UNIFICATION first** (do NOT bolt onto the fragmented table — that's the v1-subset the project forbids). Target = docs/16§6 model: `Mount { sb: Arc<dyn Superblock>, mountpoint: Arc<Dentry>, parent: Option<Arc<Mount>>, children: Vec<Arc<Mount>>, flags, propagation }`, **per mount-ns**. Current divergence: implicit string-keyed `vfs::mount::TABLE` (global) + SEPARATE devfs per-ns registry for tmpfs → mounts live in two places. STAGED PLAN (verify-left each, hosted mount-tree tests before boot): (1) introduce per-ns `MountNs` holding `Vec<Arc<Mount>>` + explicit parent/children, keyed on the mountpoint dentry, replacing the global TABLE; migrate ext4/proc/sys/dev registration into it; (2) migrate tmpfs + devfs-registry mounts into the same tree (kills the fragmentation + the B47 /var→ext4 routing hack); (3) bind-as-clone: Mount gains `root: Option<InodeRef/Dentry>` = the bound source subtree, mount_root_at returns it, DROP BindFs path-rewrite; (4) MS_REC recursive bind = clone the source subtree of Mounts; (5) propagation peer groups: `peer_group: u64` on Mount, assign on MS_SHARED, show `shared:N`/`master:N` in mountinfo, propagate mount/umount events to peers; (6) pivot_root: swap the ns root Mount + per-process root; (7) per-ns CLONE_NEWNS already partly there (mount_ns id) — make each ns own its MountNs tree. Submount-move + tmpfs-move fall out of stage 1–2. |

## Track S — preemptive-SMP scheduler (unblocks K1b cpu/io/cpuset, `13§3`)

User chose this at the K→L fork (2026-06-01): build the scheduler
foundation rather than bolt cpu/io/cpuset enforcement onto the
cooperative scheduler. NOTE: preemption already works (timer IRQ sets
need_resched every tick → `schedule_from_irq` switches on IRQ exit); the
gap was real *runtime accounting* and weighted fairness.

| # | scope | status |
|---|---|---|
| S1 | real timer-tick runtime accounting: `Task::{exec_start_ns,sum_exec_runtime_ns}`; pure `cputime` module (Linux nice→weight table, `vruntime_delta`, `clamp_delta`); `update_curr(prev,now)` charges real elapsed CPU time + advances vruntime weighted by load, re-stamps exec_start on every switch (both voluntary + IRQ paths); `/proc/<pid>/stat` utime + `/proc/<pid>/sched` now report live accounting | **DONE** (F321): 6 hosted `cputime` tests prove nice-weighting + skew clamp + no-overflow/div0; replaces the fixed `+1` vruntime bump. Foundation for S2/S3. |
| S2 | dynamic per-task weight: make `weight` a mutable atomic (not a `SchedClass::Normal` enum field); `setpriority`/`nice` reweight via `nice_to_weight`; weighted preempt decision so nice actually changes CPU shares; map cgroup `cpu.weight` → member task weights | not started |
| S3 | `cpu.max` bandwidth: per-cgroup runtime charge per period (from `update_curr`); on quota-exhaust freeze member tasks (reuse F319 freeze mechanism), unfreeze on period refill via a timer | not started |
| S4 | io controller (block-layer time accounting) + cpuset affinity (needs SMP multi-CPU runqueues) | not started |

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
| R3 | real sysfs — `/sys` is a fake-constant devfs overlay, NOT a filesystem. `/sys/class/net/<if>/*` dynamic from netdev registry; `/sys/devices/system/cpu/{online,possible,present}` from real CPU count; register a SysfsFs backend. HIGH: udev + networkd device model | **done** — SysfsFs at `/sys` (PR #1363); `/sys/class/net` dynamic from netdev registry with full attribute set; `/sys/class/<class>/<name>` symlinks → `/sys/devices/...` per docs/19§2 invariant 2; `/sys/devices/system/cpu/{online,possible,present,offline,kernel_max}`; sysfs_walk follows intermediate symlinks transparently (PR #1369). Uevent broadcast lives under K5 (separate). |
| R4 | /proc system-wide realness: `/proc/cmdline` real boot cmdline; `/proc/stat` btime + procs from registry; `/proc/net/{tcp,udp,unix}` populated (systemd socket-activation); `/proc/<pid>/fd` inode-open + `fdinfo/` | **done** — `/proc/cmdline` real via `kernel::boot_cmdline` transport seeded from Limine EXECUTABLE_FILE / KERNEL_FILE on both arches + FDT /chosen/bootargs fallback on arm (PR #1364, #1374); `/proc/stat` real btime + processes + procs_running from registry (PR #1365); `/proc/net/{tcp,udp}` populated from stack (PR #1366); `/proc/net/unix` populated from UNIX_REGISTRY (PR #1367); `/proc/<pid>/fd` inode-open (R2a) + `/proc/<pid>/fdinfo/` per-fd pos/flags/ino (PR #1371) |
| R5 | `/proc/sys` writable sysctls backed by real state (hostname already real); systemd-sysctl applies `/etc/sysctl.d` | not started |
| R6 | intermediate-directory symlink follow (merged-usr `/bin`→`/usr/bin`, `/lib`→`/usr/lib`): component-walk resolver | not started |
| R7 | `/dev/shm` tmpfs mount point (POSIX shm, systemd runtime); /dev/ptmx+pts already real | **done** (PR #1372) — TmpfsFs mounted at /dev/shm + /run via vfs::mount; end-to-end write/read/stat verified |

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

- **O_* open-flag VALUES are arch-specific and the kernel mostly uses x86
  values for both arches** (found in V6c, 2026-05-31). aarch64 Linux
  overrides: O_DIRECTORY=0o40000 (x86 0o200000), O_NOFOLLOW=0o100000
  (x86 0o400000), O_DIRECT=0o200000, O_LARGEFILE=0o400000. Fixed
  O_NOFOLLOW per-arch in open.rs (cfg). STILL x86-valued for arm:
  `O_DIRECTORY` (0o200000) — so open(O_DIRECTORY) detection is wrong on
  arm (arm sends 0o40000; kernel also wrongly treats arm's 0o200000=O_DIRECT
  as O_DIRECTORY). Audit ALL O_* consts (open.rs, vfs OpenFlags) and make
  them per-arch or normalize at the arm_abi boundary. AT_* flags
  (AT_SYMLINK_NOFOLLOW=0x100 etc.) are arch-independent — fine.
- **exec-via-walker masking risk** (V6e, F290). `execve` now reads the ELF
  via `pathresolve::read_exec` (path_lookup → inode.read) but FALLS BACK to
  raw `ext4::rootfs::read_file` when `read_exec` returns None. The fallback
  is meant only for pre-mount early boot (no root dentry yet), but it would
  ALSO silently rescue a genuine walker bug for any real binary — so a
  broken exec-walk could still boot green. Boot reaches login (proves the
  init→getty→login exec chain walks), but to truly prove no masking, add an
  exec-through-symlink case to symlink_probe (bake an executable symlink
  fixture) OR drop the fallback once confident. Revisit when touching exec.
- iputils ping ICMP runtime path → validate under K-track socket work.
- util-linux `mount` non-PIE → fix in D7.1 / L-track.
- T14 pam_unix nested-fork/dlopen → resolved by L2 (real shared libc) + D6.6.
- T15 ARM dynamic bash `/bin/sh` wedge → resolved by L1 dynamic-exec path audit.
- **bash command substitution `$(...)` yields empty — FIXED** (B21, PR #1357). It WAS a kernel syscall bug, not bash: signal delivery at the syscall-return boundary did not preserve the interrupted syscall's return value (rax/x0); rt_sigreturn returned 0. SIGCHLD-on-comsub-child-exit was delivered right at the comsub read's return → the read's count was clobbered to 0 → shell saw EOF → empty. Affected every shell (all install SIGCHLD handlers) and every value-returning syscall interrupted by a caught signal. Fixed by saving the return value in the signal frame and restoring it in rt_sigreturn. Regression guard: `/bin/cmdsubst_probe` sigchld case.
- **alarm()/SIGALRM does not wake a task blocked in `read()` — FIXED** (B20, PR pending). Three layered bugs:
  1. The alarm deadline was only checked at the syscall-return tail, which a task parked in a blocking syscall never reaches. Fixed by servicing `alarm_ns` in `sched::live::tick_wake_expired`.
  2. `tick_wake_expired` was **dead code** — F152 retired the rx kthread that called it (so SO_RCVTIMEO/SO_SNDTIMEO timeout-wakes were also dead). Wired it into the live timer tick `tick_poll_combined` (lib.rs), throttled to ~100ms.
  3. **WaitList `finish_wait` contract bug** (systemic, all park sites): a signal/deadline wake rouses a parked task via `wake_if_sleeping`, bypassing the WaitList — the stale `Arc` lingers. A later `wake_all` (e.g. pipe last-writer-close at task exit) then enqueued the now-exiting/dead task onto the runqueue → corrupt context switch → silent boot wedge. Fixed at the primitive: `wake_one`/`wake_all` only enqueue `Sleeping` tasks (drop stale entries, balancing the park bump); `park` dedups any prior entry to prevent double-enqueue on re-park. Fixes pipe + sem/msg/mq/net/epoll/evdev uniformly.
  - Also fixed `post_pgrp` — `kill(pgid=0,sig)` posted the bit but never woke parked group members.
  - Regression guard: `/bin/alarm_probe` (alarm(1)+SIGALRM, no SA_RESTART, blocking read on empty pipe → must return EINTR). It was the first code to park a pipe reader woken *purely* by a signal with the writer end held open — exactly the case that exposed bug 3.
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

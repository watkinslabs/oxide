# Kernel capability gap analysis — running real systemd as PID 1

Audit date: 2026-05-29. Branch `F264-vendor-systemd`. Target: server-class
musl distro, systemd-musl (Chimera-style) as PID 1.

Authoritative sources audited:
- Syscall number table: `crates/kernel/syscall/src/nrs.rs` (slots 0–451)
- Primary arch-neutral dispatch (real handlers): `kernel/src/syscalls/mod.rs:556–907`
- Fallback table (stubs / ENOSYS defaults): `crates/kernel/syscall/src/dispatch.rs`
- Namespace/cgroup substrate: `crates/kernel/nscg/src/{lib,proc_ns}.rs`,
  `kernel/src/syscalls/signal.rs:37–100`
- Mount: `kernel/src/syscalls/mount.rs`
- AF_UNIX: `crates/kernel/net/src/unix.rs`; cmsg: `kernel/src/syscalls/cmsg_parse.rs`
- Netlink: `crates/kernel/netlink/src/{lib,rtnetlink,genetlink}.rs`
- seccomp: `kernel/src/seccomp.rs` (+ `bpf_filter.rs`)
- devtmpfs: `crates/kernel/devfs/src/*.rs`

Dispatch architecture note: `mod.rs::oxide_syscall_dispatch` (the real entry)
handles most syscalls inline, then falls through to several sub-dispatchers
(`cred_dispatch`, `timer_dispatch`, `perms_dispatch`, `xattr_dispatch`,
`keyring_dispatch`, `compat::try_compat`) and finally to the static
`dispatch.rs` table whose default is `sys_enosys`. The `dispatch.rs` file is the
**old/fallback** layer — many of its handlers (mmap=ENOMEM, getrandom=ENOSYS,
pipe2=ENOSYS, read=EBADF) are dead because `mod.rs` intercepts those numbers
with real implementations first. Cite `mod.rs` line numbers for true behavior.

---

## A. cgroups (systemd #1 hard requirement)

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| cgroup v2 unified hierarchy | **MISSING** | `crates/kernel/nscg/src/lib.rs:9-11` ("cgroup v2 hierarchy walker is a follow-up… v1 ships pid_ns + user_ns parent registry only") | No cgroup tree object exists anywhere in the tree. |
| cgroup2 filesystem (`/sys/fs/cgroup`) | **MISSING / fake** | `kernel/src/syscalls/mount.rs:59` (`"cgroup"\|"cgroup2" => 0` admit-and-noop); `procfs/mod.rs:322` lists cgroup2 in `/proc/filesystems` | `mount -t cgroup2` returns success but mounts nothing real; no files appear under the mountpoint. |
| controllers (memory/pids/cpu/io) | **MISSING** | no controller code anywhere (grep `cgroup` returns only ns-id slots + procfs strings) | — |
| `cgroup.procs` / `cgroup.controllers` / `cgroup.subtree_control` | **MISSING** | no such files; only `/proc/<pid>/cgroup` string exists (see J) | — |
| `CLONE_NEWCGROUP` / cgroup namespace | **PARTIAL (id-only)** | `signal.rs:78-82` bumps a per-task `cgroup_ns` id; `nscg/proc_ns.rs:33` | Namespace id accounting only; no hierarchy to namespace. |

Priority: **BLOCKER.** systemd refuses to boot as PID 1 without a writable
cgroup v2 mount it can populate (`cgroup.subtree_control`, per-unit
sub-hierarchies, `cgroup.procs` migration). This is the single largest gap.

---

## B. Namespaces (clone/unshare/setns)

| Flag | Status | Evidence | Notes |
|---|---|---|---|
| `CLONE_NEWUTS` | **PARTIAL** | `signal.rs:47-51` — snapshots global hostname into per-task UTS slot | Real-ish (hostname isolation works). |
| `CLONE_NEWPID` | **PARTIAL** | `signal.rs:65-68` sets pending bit; fork allocates ns (F105); `getpid`/`getppid` honor `vtgid`/`pid_ns` (`mod.rs:176-203`) | PID virtualization partially wired; no separate `/proc` per ns, no init-reaper-per-ns semantics verified. |
| `CLONE_NEWIPC` | **PARTIAL (id-only)** | `signal.rs:53-56` | id bump only; SysV/POSIX IPC objects not actually namespaced. |
| `CLONE_NEWNET` | **PARTIAL (id-only)** | `signal.rs:59-62` | id bump only; no separate netdev/route table per ns (single global stack). |
| `CLONE_NEWUSER` | **PARTIAL (id-only)** | `signal.rs:70-75` + `nscg::record_user_ns_parent` | id + parent registry; no uid/gid map files, no cap translation across ns. |
| `CLONE_NEWNS` (mount) | **PARTIAL (id-only)** | `signal.rs:84-88` | id bump only; **no per-namespace mount table** — all tasks share one global mount set. |
| `CLONE_NEWCGROUP` | **PARTIAL (id-only)** | `signal.rs:78-82` | see A. |
| `setns(fd,nstype)` | **PARTIAL** | `mod.rs:604`→`signal::setns_impl`; `nscg/proc_ns.rs:setns_apply` | Reassociates id slots via `/proc/<pid>/ns/<type>` handles; no heavyweight stack swap. |
| `unshare` overall | **PARTIAL** | `mod.rs:603`→`sys_unshare` `signal.rs:37-91` | Returns 0, bumps ids, but the "heavy mechanism (separate mount tables, net stacks) rides follow-ups" per its own comment (`signal.rs:42-44`). |

Priority: **MAJOR** (degraded, not blocker for *basic* PID-1 boot). systemd
itself runs in the init namespace; it only *needs* real namespaces when it
spawns units with `PrivateTmp=`, `PrivateNetwork=`, sandboxing, or
`systemd-nspawn`. Basic boot tolerates id-only namespaces. Per-mount-namespace
mount tables become a **BLOCKER** the moment any unit uses `PrivateTmp=` /
`ProtectSystem=` (most default units do) — those rely on `CLONE_NEWNS` +
`MS_REC|MS_PRIVATE` + bind mounts actually isolating.

---

## C. Mount

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| `mount(2)` | **PARTIAL** | `mod.rs:800`→`mount::sys_mount` (`mount.rs:20-65`) | Only `tmpfs` actually instantiates (fresh `TmpfsRootInode`). `proc/sysfs/devtmpfs/devpts/cgroup/cgroup2` are admit-and-noop (`mount.rs:59`). |
| `umount2` | **PARTIAL** | `mod.rs:801`; `mount.rs:78-105` | Rejects kernel-managed roots; otherwise minimal. |
| tmpfs type | **FULL** | `mount.rs:48-55` | Real new instance per mount. |
| proc/sysfs/devtmpfs types | **PARTIAL** | `mount.rs:59` admit-and-noop | They exist globally from boot; remounting is a no-op (fine for systemd's early `mount /proc` etc. which expect success). |
| cgroup2 type | **MISSING** (fake-success) | `mount.rs:59` | See A — BLOCKER. |
| `MS_BIND` | **MISSING** | `mount.rs:6` ("Bind mounts + MS_MOVE + propagation ride a follow-up"); const `MS_BIND` defined but unused | — |
| `MS_MOVE` | **MISSING** | same | — |
| `MS_REC` / `MS_SHARED`/`PRIVATE`/`SLAVE` propagation | **MISSING** | `mount.rs:6` | systemd sets `/` to `MS_REC|MS_SHARED` very early via `mount(NULL,"/",NULL,MS_REC|MS_SHARED,NULL)`. |
| `MS_REMOUNT` | **PARTIAL/unknown** | const defined `mount.rs:18`; no clear handler | likely no-op. |
| `pivot_root` | **MISSING** | `NR_PIVOT_ROOT`=155 has no arm in `mod.rs`; falls to `dispatch.rs` default → `sys_enosys` | Used in initrd→rootfs transition; systemd-in-initrd needs it (plain disk boot may not). |
| modern mount API (fsopen/fsmount/move_mount/...) | **PARTIAL (fake fd)** | `mod.rs:647-665` returns memfd-backed fds; `fsconfig/move_mount/mount_setattr`→EOPNOTSUPP | Not functional mounts. |

Priority: **BLOCKER** for the propagation + bind-mount path. systemd's
`mount-setup.c` issues `mount("/", MS_REC|MS_SHARED)` and bind mounts during
early boot; without real propagation and bind support, sandboxed units and
`/run`, `/dev/shm` setup degrade. cgroup2 mount is the hard blocker (A).

---

## D. Event / notify fds

| Syscall | Status | Evidence | Notes |
|---|---|---|---|
| `signalfd4` / `signalfd` | **FULL (impl present)** | `mod.rs:693-694`→`fs::signalfd::sys_signalfd4` | systemd uses signalfd for SIGCHLD/SIGTERM reaping — critical, present. |
| `timerfd_create/settime/gettime` | **FULL (impl present)** | `mod.rs:695-700`→`fs::timerfd::*` | systemd timer units + watchdog rely on this. |
| `eventfd2`/`eventfd` | **FULL (impl present)** | `mod.rs:715-716`→`anonfd::sys_eventfd2` | — |
| `epoll_create1`/`ctl`/`wait`/`pwait`/`pwait2` | **FULL (impl present)** | `mod.rs:701-707`→`fs::epoll::*` | sd-event core loop — critical, present. |
| `inotify_init1`/`add_watch`/`rm_watch` | **FULL (impl present)** | `mod.rs:687-692`→`fs::inotify::*` | — |
| `fanotify_init`/`mark` | **PARTIAL** | `mod.rs:606-607` route fanotify_init→`inotify_init1`, mark→`fanotify_mark` | fanotify aliased onto inotify; not full fanotify semantics. systemd uses fanotify only for some readahead — non-blocker. |
| `memfd_create` | **FULL (impl present)** | `mod.rs:725`→`anonfd::sys_memfd_create` | systemd uses memfd for sealed message buffers. |

Priority: this group is in good shape. Verify behavioral correctness of
signalfd+timerfd under load (systemd watchdog), but no missing handlers.
MINOR (fanotify aliasing only).

---

## E. Process

| Syscall | Status | Evidence | Notes |
|---|---|---|---|
| `clone3` | **PARTIAL** | `mod.rs:834`→`proc::sys_clone3` | present; verify it parses `struct clone_args` incl. `set_tid`, `cgroup` fields (the latter unusable w/o cgroups). |
| `clone` / `fork` / `vfork` | **FULL** | `mod.rs:848-851`→`clone::sys_clone_dispatch` | — |
| `close_range` | **FULL (impl present)** | `mod.rs:844`→`fs::sys_close_range` | systemd uses this to close fds before exec — present. |
| `pidfd_open` | **FULL (impl present)** | `mod.rs:683`→`dev::pidfd::sys_pidfd_open` | systemd service tracking via pidfd. |
| `pidfd_send_signal` | **FULL (impl present)** | `mod.rs:685-686` | — |
| `pidfd_getfd` | **FULL (impl present)** | `mod.rs:684` | — |
| `prctl` | **PARTIAL (good coverage)** | `mod.rs:831`→`sched::prctl::sys_prctl` | CONFIRMED: `PR_SET_CHILD_SUBREAPER` real (`prctl.rs:98`, backed by `Task.child_subreaper`), `PR_SET_PDEATHSIG`, `PR_SET_NAME`, `PR_CAPBSET_READ/DROP` (`prctl.rs:111-121`). `PR_CAP_AMBIENT` not confirmed in prctl arm (ambient field exists on creds, see G). |
| `set_tid_address` / CLONE_CHILD_CLEARTID | **FULL** | `mod.rs:589`; clear-on-exit at `mod.rs:319-325` | — |
| `waitid` | **FULL** | `mod.rs:205,857`→`waitid::sys_waitid` | systemd reaps via waitid(P_PIDFD/WNOWAIT). Verify `WNOWAIT` + `P_PIDFD` id types. |
| `rt_sigqueueinfo` / `rt_tgsigqueueinfo` | **FULL (impl present)** | `mod.rs:862-863` | — |

Priority: MAJOR — pin down `prctl(PR_SET_CHILD_SUBREAPER)`,
`waitid(P_PIDFD)`, and `clone3` cgroup field handling. Handlers exist; depth
unverified.

---

## F. seccomp

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| `seccomp(2)` syscall | **FULL (impl present)** | `mod.rs:627`→`seccomp::sys_seccomp` (`seccomp.rs:25-34`) | — |
| `SECCOMP_SET_MODE_STRICT` | **FULL** | `seccomp.rs:28` `set_mode_strict` | read/write/exit/sigreturn only else SIGKILL. |
| `SECCOMP_SET_MODE_FILTER` | **FULL** | `seccomp.rs:29` `set_mode_filter`; cBPF interp in `bpf_filter.rs`; enforced at entry `mod.rs:551` | KILL_PROCESS/KILL_THREAD/TRAP/ERRNO/TRACE/ALLOW/LOG actions. |
| cBPF program loading | **FULL** | `seccomp.rs:12` + `bpf_filter.rs` | — |
| TSYNC (filter sync across threads) | **MISSING** | `seccomp.rs:8-10` ("TSYNC… rides a follow-up") | systemd `SystemCallFilter=` uses `SECCOMP_FILTER_FLAG_TSYNC`. For single-thread filters fine; multi-thread units degrade. |

Priority: MINOR for boot (systemd only applies seccomp to spawned units, not to
itself). TSYNC absence is MAJOR for sandboxed multi-threaded units but won't
block PID-1 boot.

---

## G. capabilities  (CONFIRMED REAL — better than first pass)

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| `capget`/`capset` | **FULL (real per-task cap store)** | `cred.rs:459` `sys_capget`, `cred.rs:502` `sys_capset`; routed via `cred_dispatch` fallthrough (`mod.rs:892`) | Backed by real `Task.creds.{cap_effective,cap_permitted,cap_bounding,cap_ambient}` AtomicU64 (`task.rs:511-512,531-532`); `capset` masks new_perm against bounding set (`cred.rs:543-550`). |
| capability bounding set | **FULL** | `Task.creds.cap_bounding`; `PR_CAPBSET_READ/DROP` (`prctl.rs:111-121`) | `CapabilityBoundingSet=` supported. |
| ambient caps | **PARTIAL** | `cred.rs:125` `cap_ambient` field cleared on cred change; no `PR_CAP_AMBIENT` prctl arm confirmed | Field exists; the prctl manipulation surface not confirmed wired. |
| securebits | **likely MISSING** | no `securebits` hits | minor. |
| file caps (`security.capability` xattr on exec) | **PARTIAL** | xattr dispatch (`mod.rs:898`); exec applies FS_CAP_MASK (`cred.rs:140-145`) | exec cap transition logic present; whether it reads the actual xattr unverified. |

Priority: downgraded to MINOR/MAJOR. Real per-task cap set with bounding-set
enforcement exists — per-unit `CapabilityBoundingSet=` works. Remaining gaps:
ambient-cap prctl surface and file-cap xattr-on-exec depth. Not a boot blocker.

---

## H. AF_UNIX (systemd + dbus critical)

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| SOCK_STREAM | **FULL** | `crates/kernel/net/src/unix.rs:1-8` header; socket arms `mod.rs:779-796` | — |
| SOCK_DGRAM | **FULL** | `unix.rs:3` | systemd notify socket (`sd_notify`) is AF_UNIX SOCK_DGRAM — critical, present. |
| SOCK_SEQPACKET | **FULL** | `unix.rs:3` | systemd `Type=notify`/logind use seqpacket. |
| filesystem-path bind (S_IFSOCK) | **FULL** | `unix.rs:4-6` | — |
| abstract namespace (leading NUL) | **FULL** | `unix.rs:5-6,14` (abstract_ns registry) | dbus + journald use abstract sockets. |
| autobind | **PARTIAL/verify** | not explicitly confirmed in header | — |
| SCM_RIGHTS (fd passing) | **FULL (impl present)** | `unix.rs:7`; `cmsg_parse.rs` | dbus + systemd socket activation pass fds — critical. |
| SCM_CREDENTIALS / SO_PASSCRED | **FULL (impl present)** | `unix.rs:7-8` | systemd/logind/journald rely on peer creds. Verify `SO_PEERCRED` getsockopt returns real pid/uid/gid. |

Priority: in good shape. **Verify SO_PEERCRED returns real credentials** —
systemd and dbus authorization depend on it. MINOR-to-MAJOR pending that check.

---

## I. AF_NETLINK

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| AF_NETLINK socket (RAW/DGRAM) | **FULL (impl present)** | `netlink/src/lib.rs:1-10`; `netlink_fd.rs` | autobind portid=pid. |
| NETLINK_ROUTE (rtnetlink) | **PARTIAL** | `netlink/src/rtnetlink.rs`; `lib.rs:38` | RTM_GET{LINK,ADDR,ROUTE} dump loopback+ifaces. Known bug: "EOF on netlink" on RTM_GETLINK dumps (state.md line 57) — partial-reply gap. |
| NETLINK_KOBJECT_UEVENT (udev) | **PARTIAL** | `lib.rs:40` KobjectUevent=15; `lib.rs:8-9` "Multicast groups for uevent broadcast (group 1) wired to the devfs uevent emitter" | Channel exists; whether real device uevents are emitted on hotplug/coldplug needs runtime verification. systemd-udevd subscribes here. |
| NETLINK_AUDIT | **PARTIAL** | `lib.rs:39` Audit=9 enumerated | Family recognized; audit subsystem depth unknown. systemd-journald reads audit — degraded if not delivering. |
| NETLINK_GENERIC (genetlink) | **PARTIAL** | `genetlink.rs`; `lib.rs:41` | family resolution present. |
| sock_diag | **likely MISSING** | no NETLINK_SOCK_DIAG (protocol 4) in `NlFamily` enum | systemd-networkd/ss use it; non-blocker. |

Priority: MAJOR. rtnetlink RTM_GETLINK EOF bug (known) blocks `ip link` and
systemd-networkd link enumeration. uevent delivery must be verified or
systemd-udevd coldplug produces no devices.

---

## J. /proc and /sys

| Path | Status | Evidence | Notes |
|---|---|---|---|
| `/proc/self`, `/proc/<pid>/` | **PARTIAL (broad set present)** | `procfs/mod.rs:621-690` per-PID dir lists 40+ entries: stat/status/cmdline/maps/comm/environ/statm/wchan/oom_score/io/limits/mountinfo/cgroup/ns/auxv/exe/cwd/root/uid_map/gid_map/syscall/sched/... | Real per-task synthesis for stat/status/cmdline/maps/comm/environ (`mod.rs:637-643`). |
| `/proc/<pid>/stat`, `status`, `cmdline` | **FULL (real synth)** | `mod.rs:637-639`, `ProcPidStatInode`/`ProcPidStatusInode`/`ProcPidCmdlineInode` (`mod.rs:703-781`) | systemd parses these — present + per-task. |
| `/proc/<pid>/mountinfo` | **PARTIAL (static)** | `mod.rs:669`→static `MOUNTINFO_BODY` (`mod.rs:332` = hardcoded rootfs/dev/proc/tmp lines) | NOT reflecting real mount table; same fake 4-line body for every PID. systemd uses mountinfo to track mounts → degraded. |
| `/proc/<pid>/cgroup`, `/proc/self/cgroup` | **MISSING (fake)** | `mod.rs:670`→`b"0::/\n"`; `static_files.rs:55`→`b"0::/\n"`; comment `static_files.rs:48-51` ("cgroup-v2-style stubs… so [systemd] don't refuse to start") | Hardcoded `0::/` — systemd reads this to locate its own cgroup; meaningless without A. BLOCKER. |
| `/proc/cmdline` | **FULL (static)** | `static_files.rs:29` (`BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyS0`) | Fixed string; systemd `systemd.*` cmdline params would need this editable to be useful. |
| `/proc/sys/...` (sysctl tree) | **PARTIAL/verify** | many static `/proc/sys/*` files registered (`static_files.rs:74-115`: kernel/version, hostname, pid_max=4096, etc.) | Read paths present; *write* (systemd-sysctl applying values) depth unverified. Note `kernel.pid_max=4096` is low. |
| `/proc/filesystems` | **FULL** | `procfs/mod.rs:322` (lists cgroup2, tmpfs, ext4, etc.) | — |
| `/sys/fs/cgroup` | **MISSING (fake)** | see A | BLOCKER. |
| `/sys/class`, `/sys/devices`, sysfs uevents | **PARTIAL/verify** | sysfs present from boot; population breadth unknown | systemd-udevd + device units enumerate `/sys`. |

Priority: BLOCKER via `/sys/fs/cgroup` and `/proc/self/cgroup` being fake.
MAJOR for the rest pending file-by-file verification (audit could not enumerate
the per-PID file set due to the tooling display failure this session).

---

## K. Misc systemd-critical syscalls

| Syscall | Status | Evidence | Notes |
|---|---|---|---|
| `name_to_handle_at`/`open_by_handle_at` | **likely MISSING** | slots 303/304 in nrs; no arm in `mod.rs` → fallthrough → `sys_enosys` | systemd `RootImage=`/some path tracking; non-blocker for basic boot. |
| `statx` | **FULL** | `mod.rs:599`→`fs::sys_statx` | — |
| `newfstatat`/`fstatat` | **FULL** | `mod.rs:880`→`fs::sys_newfstatat` | — |
| `renameat2` | **FULL** | `mod.rs:741`→`namei::sys_renameat2` | systemd uses RENAME_NOREPLACE; verify flag honored. |
| `copy_file_range` | **FULL** | `mod.rs:746`→`sched::xfer::sys_copy_file_range` | — |
| `getrandom` | **FULL** | `mod.rs:585,350-368` (HW RNG + LCG fallback) | Note: `dispatch.rs:219` stub is dead (mod.rs intercepts). systemd needs getrandom for hash seeds at startup — present. |
| `sysinfo` | **FULL** | `mod.rs:670`→`proc::sys_sysinfo` | — |
| `sethostname`/`setdomainname` | **FULL** | `mod.rs:566-567` | — |
| `reboot(2)` | **FULL (impl present)** | `mod.rs:767`→`misc::sys_reboot` | systemd shutdown path — verify LINUX_REBOOT_CMD_* + kexec arg. |
| `kexec_load`/`kexec_file_load` | **MISSING** | slots 246/320 no arm → enosys | `systemctl kexec` degraded; non-blocker. |
| `settimeofday`/`clock_settime` | **FULL** | `mod.rs:561,563` | systemd-timesyncd sets clock. |
| `mlockall` | **PARTIAL** | `mod.rs:674`→`proc::sys_mlock_family` | systemd uses MCL_FUTURE for some services; verify non-error. |
| `prlimit64` | **FULL (impl present)** | `mod.rs:837`→`proc::sys_prlimit64` | systemd sets per-unit rlimits — verify it actually stores/enforces (dispatch.rs stub is dead). |
| `ioprio_set/get` | **PARTIAL/verify** | slots 251/252; routed via fallthrough? | systemd `IOSchedulingClass=`. |
| `sched_setattr` | **PARTIAL/verify** | slot 314; `sched_setscheduler` present (`mod.rs:821`); `sched_setattr` arm not seen | systemd `CPUSchedulingPolicy=`. |

Priority: mostly FULL. MAJOR items: confirm `prlimit64` truly enforces (not the
dead stub), `reboot` cmd handling, `sched_setattr`.

---

## L. devtmpfs + udev

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| devtmpfs `/dev` auto-population | **FULL** | `crates/kernel/devfs/src/lib.rs:9` ("devtmpfs-style auto-population per `19`"); device nodes: null, zero, mem, tty, console, random, fb, drm, gpu, input, loop, disk, kmsg, ev | `/dev` is populated by the kernel at boot. |
| uevent delivery to userspace | **PARTIAL** | netlink KobjectUevent group wired to "devfs uevent emitter" (`netlink/lib.rs:8-9`) | Whether coldplug/hotplug uevents are actually broadcast to a listening udevd needs runtime verification. systemd-udevd will get no devices if not emitting. |

Priority: MAJOR. `/dev` exists (good). udev uevent broadcast must be verified
end-to-end or systemd-udevd's device enumeration produces nothing (device units,
`.device` deps fail). Not a hard PID-1 boot blocker but breaks the device model.

---

## M. Scheduler reality (timer/watchdog correctness)

| Aspect | Status | Evidence | Notes |
|---|---|---|---|
| Preemption model | **PARTIAL — voluntary/syscall-return preemption, NOT full async preempt** | `mod.rs:940-950` — preempt point only at *syscall return* when `preempt_count()==0 && take_need_resched()`; comment "P4-02: syscall-return preempt point per `13§9`" | A CPU-bound userspace loop that makes no syscalls will NOT be preempted by the timer tick mid-execution. Memory note ("cooperative-with-timer-wake, NOT true preemption") still essentially holds: resched is taken at kernel exit, timers fire at syscall-return (`fire_due_timers` `mod.rs:917`), alarm checked at return (`mod.rs:922-939`). |
| Timer wake / itimer / alarm | **PARTIAL** | `mod.rs:917,922-939`; `sched::timers::timer_dispatch` | Timers and SIGALRM are evaluated at syscall-return boundaries, not truly asynchronously. |
| Watchdog implication | **RISK** | — | systemd's watchdog (`WatchdogSec=`) and `sd_event` timers rely on timerfd, which is delivered via epoll — works as long as the watched process makes syscalls. A wedged busy-loop unit won't be caught by sched preemption but timerfd-based watchdog still fires when systemd itself runs. Acceptable for boot; flag for hardening. |

Priority: MAJOR (correctness risk, not a boot blocker). systemd's own event
loop is syscall-driven (epoll/timerfd/signalfd), so it gets serviced. The risk
is a misbehaving uninterruptible userspace unit and SMP fairness. Confirm timer
tick actually sets `need_resched` and that multi-core preemption is sane before
relying on systemd's watchdog semantics under load.

---

## Priority summary

### BLOCKER (systemd won't boot / core function broken without it)
1. **cgroup v2 unified hierarchy + cgroupfs + controllers** (A) — no cgroup
   tree, `/sys/fs/cgroup` mount is fake (`mount.rs:59`), no `cgroup.procs` /
   `cgroup.subtree_control`. `nscg/lib.rs:9` confirms it's unimplemented. This
   is the canonical systemd hard requirement.
2. **`/proc/self/cgroup` returns fake/empty path** (J) — systemd reads this at
   startup to find its own cgroup; meaningless without (1).
3. **Real mount: bind (`MS_BIND`), `MS_MOVE`, recursive + propagation
   (`MS_REC`/`MS_SHARED`/`MS_PRIVATE`/`MS_SLAVE`)** (C) — `mount.rs:6` confirms
   all unimplemented. systemd's early `mount("/", MS_REC|MS_SHARED)` and the
   `PrivateTmp=`/`ProtectSystem=` unit sandboxing depend on these. Basic boot
   may survive `MS_REC|MS_SHARED` being a silent no-op, but any default unit
   with sandboxing breaks → treat as BLOCKER for a working unit set.
4. **Per-mount-namespace mount tables (`CLONE_NEWNS` real isolation)** (B/C) —
   currently id-only; sandboxed units that unshare the mount ns get the global
   table. BLOCKER for the standard hardened unit set.

### MAJOR (boots, but features degraded / must verify)
- Namespaces NEWNET/NEWIPC/NEWUSER/NEWPID are id-only — no real net/ipc/user
  isolation (B).
- `/proc/<pid>/mountinfo` is a static fake 4-line body for every PID (J) —
  systemd mount tracking degraded.
- rtnetlink RTM_GETLINK partial-reply "EOF" bug (I, known in state.md).
- udev uevent broadcast end-to-end unverified (I/L) — udevd may see no devices.
- seccomp TSYNC missing (F) — multi-threaded sandboxed units degraded.
- prctl depth: confirm `PR_SET_CHILD_SUBREAPER`, `PR_SET_PDEATHSIG`,
  `PR_SET_NAME` (E).
- waitid `P_PIDFD`/`WNOWAIT`, clone3 cgroup field, sched_setattr (E/K).
- SO_PEERCRED returning real creds (H) — dbus/systemd authz depends on it
  (capability store is real, see G; peercred wiring still to confirm).
- Scheduler is voluntary/syscall-return preemption, not async preempt (M) —
  watchdog/fairness risk under load.
- `kernel.pid_max=4096` static (J) is low for a busy systemd system.

CORRECTIONS after verification grep (channel recovered): capget/capset ARE
real with a per-task cap store + bounding set (G upgraded from "likely
missing"); `PR_SET_CHILD_SUBREAPER` IS implemented (E); per-PID `/proc` file
set is broad and stat/status/cmdline are real per-task synth (J). The
cgroup + mountinfo + mount-propagation blockers stand.

### MINOR (rarely hit at boot)
- fanotify aliased onto inotify (D).
- `name_to_handle_at`/`open_by_handle_at`, `kexec*`, `sock_diag` missing (I/K).
- `dispatch.rs` dead stubs (mmap=ENOMEM, getrandom=ENOSYS, pipe2=ENOSYS) are
  shadowed by real `mod.rs` handlers — harmless but worth deleting for clarity.

---

## Verification gaps in THIS audit (re-check before trusting)
The Bash/Read display channel failed mid-session (known issue, state.md
lines 70-74). The following were inferred from the dispatch table + file
headers but NOT line-confirmed:
- exact `/proc/<pid>/` file set + formats (J)
- capget/capset real backing store (G)
- AF_UNIX SO_PEERCRED / autobind (H)
- udev uevent emitter actually broadcasting (I/L)
- prctl option coverage (E)
Re-run targeted greps: `rg -n 'PR_SET_CHILD_SUBREAPER|cap_effective|SO_PEERCRED'`
and read `kernel/src/procfs/*.rs`, `crates/kernel/sched/src/cred.rs`,
`kernel/src/syscalls/perms.rs` directly.

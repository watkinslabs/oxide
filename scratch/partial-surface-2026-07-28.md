# PARTIAL surface — re-derived against current main

DRAFT 2026-07-28. Dep: `scratch/syscall-compliance-matrix.md` (base `5a5fe627f`), `scratch/audit-{mm,sched,vfs,net-sec}.md`, `scratch/linux-compliance-findings.md`. Supersedes `scratch/partial-gap-triage.md`.

Every `PARTIAL` row re-verified against current source and `/home/nd/oxide/linux-master` (v7.2.0-rc4). Row Evidence strings were treated as claims to disprove, not as input.

## 1 Counts

| Bucket | Rows | Meaning |
|---|---|---|
| A — real functional gap | **162** | named Linux behaviour we do not implement |
| B — coverage debt only | **26** | behaviour verified correct; the audit/harness is unfinished |
| C — already fixed, row stale | **3** | gap named in Evidence closed by a merged lane; flip to `IMPL` |
| D — ABSENT-OK | **3** | Linux omits it under a named `CONFIG`; not a gap |
| Total | **194** | |

| Status | Matrix today | After bucket C |
|---|---|---|
| `IMPL` | 166 | **169** |
| `PARTIAL` | 194 | **191** |
| `LINUX-ENOSYS` | 22 | 22 |
| `DONE` | 3 | 3 |

**The brief's expectation of "a lot" of bucket C was wrong — 3 rows, not ~30.** The ~30 merged lanes closed *sub-claims inside* rows, not whole rows. The pattern is uniform: a fix lane closed the syscall-shim half (errno order, ABI layout, permission ladder) and left the subsystem half (RT tick, `shared_pending`, `i_writecount`, the aio ring, uid translation) untouched — which is precisely why those rows still read `PARTIAL`. 21 rows carry a verified-stale *clause* whose row is still A; those are listed in §6, and a follow-up lane should strike the clause without flipping the status.

Bucket A is 162 rows but far fewer lanes: **~40 root causes** produce them (§4). The largest single one — user-namespace id translation — accounts for 16 rows by itself.

## 2 Bucket A — real functional gaps

| Nr | Syscall | Missing behaviour | Owner crate | Linux ref | Oxide ref | Size |
|---|---|---|---|---|---|---|
| 16 | `ioctl` | `kill_fasync` has zero production callers: `FIOASYNC`/`O_ASYNC` registers but no socket/pipe/tty ever delivers SIGIO/SIGURG | vfs | `net/socket.c:1555-1558`; `fs/pipe.c:667,694,837` | `vfs/src/file/async_notify.rs:80,140` | M |
| 42 | `connect` | AF_UNIX pathname connect never checks filesystem permission — a 0600 root socket is connectable by any uid that can traverse to it | syscalls+net | `net/unix/af_unix.c:1217 path_permission(MAY_WRITE)` | `syscalls/src/namei_common.rs:388-399` | M |
| 43 | `accept` | accepted child inherits only sndbuf/rcvbuf/bpf/mtu_discover; every `SO_*`/`TCP_*` set on the listener is dropped | net | `net/core/sock.c sk_clone_lock` | `net/src/sock/construct.rs:151-186` | M |
| 44 | `sendto` | `MSG_OOB` on an AF_UNIX stream/seqpacket socket delivered as ordinary in-band data — no OOB mark, no `sk_send_sigurg` | socket | `net/unix/af_unix.c:2363`; `net/unix/Kconfig AF_UNIX_OOB=y` | `socket/src/send.rs:157-165,373-388` | S |
| 46 | `sendmsg` | same AF_UNIX `MSG_OOB` gap (shared `socket::send::prepare`); no SIGURG raise anywhere in `net` | socket | `net/core/sock.c:3714 sk_send_sigurg` | `socket/src/send.rs:157-165,373-388` | S |
| 47 | `recvmsg` | AF_UNIX OOB receive absent (send side never marks it); no SIGURG/SIGIO notification. TCP OOB is complete | net | `net/unix/af_unix.c unix_stream_recvmsg` | `syscalls/src/recvmsg/entry.rs:12` | M |
| 49 | `bind` | every bound pathname AF_UNIX socket lands mode `s---------` (`CreateCtx{umask:0}`, perm bits 0) | syscalls | `net/unix/af_unix.c:1351-1352` | `syscalls/src/049_bind.rs:25,29` | S |
| 50 | `listen` | SYN cookies absent (Fedora default `tcp_syncookies=1`); backlog machinery itself is real | net | `net/ipv4/syncookies.c`; `tcp_syn_flood_action` | `net/src/stack/tcp_listener.rs:103-135` | M |
| 54 | `setsockopt` | SOL_TCP implements 5 of ~30 optnames; `SO_SNDBUF` floored at 16 KiB by every send path while `getsockopt` reports the requested value | syscalls+net | `net/ipv4/tcp.c do_tcp_setsockopt`; `net/core/sock.c` | `054_setsockopt/main.rs:308-345`; `socket/src/send.rs:281` | M |
| 55 | `getsockopt` | `TCP_INFO.tcpi_rtt`/`rttvar` always 0 and `tcpi_rto` a fixed 1 s — `update_rtt` has no production caller | net | `net/ipv4/tcp_input.c:3459,3732` | `net/src/tcp_conn/timers.rs:9` | M |
| 56 | `clone` | **the `CLONE_NEW*` capability gate is missing at clone** — `may_unshare_namespaces` is called only from `unshare`, so unprivileged `clone(CLONE_NEWNS)` succeeds; `CLONE_SYSVSEM`/`CLONE_IO`/`CLONE_PTRACE` unknown; no `PTRACE_EVENT_FORK/VFORK/CLONE` | syscalls+sched | `kernel/nsproxy.c:177-182`; `kernel/fork.c:2295,2440` | `056_clone.rs:19-38,317` | M |
| 58 | `vfork` | parent's park loop breaks only on `!vfork_pending`, no fatal-signal check — a vfork parent whose child blocks is unkillable; no `PTRACE_EVENT_VFORK_DONE` | syscalls | `kernel/fork.c:1439-1454 wait_for_vfork_done` | `056_clone.rs:436-460` | S |
| 59 | `execve` | argv/envp caps (1024 entries / 4096 bytes) truncate silently instead of `E2BIG`; `de_thread` is only its SIGKILL half (no `notify_count` wait, no `exchange_tids`); no `i_writecount` → no `ETXTBSY`; shebang depth 4 vs 5 | syscalls+exec | `fs/exec.c:364,470-476,919,1002-1018,1134`; `binfmts.h:15-16` | `059_execve/x86_64.rs:121-150`; `execve_common.rs:172,211` | L |
| 60 | `exit` | session-leader exit runs no `disassociate_ctty(1)`: no session vhangup, no SIGHUP/SIGCONT to the tty's foreground pgrp | sched+tty | `drivers/tty/tty_jobctrl.c disassociate_ctty` | `060_exit.rs:56` | M |
| 61 | `wait4` | `traced_by` is never consulted by any wait path — a tracer that is not the parent can never `wait4` its tracee | syscalls+sched | `kernel/ptrace.c __ptrace_link`; `kernel/exit.c do_wait` | `061_wait4.rs:40` | M |
| 62 | `kill` | `kill(2)` sets only the pending bit — no `sigq_push` — so every `SA_SIGINFO` handler sees `si_code=0/si_pid=0/si_uid=0`; no SIGCONT↔stop mutual flush | syscalls | `kernel/signal.c prepare_kill_siginfo, prepare_signal` | `062_kill.rs:45,85,106` | S |
| 72 | `fcntl` | `F_SEAL_EXEC` absent from the `F_ADD_SEALS` valid mask; `F_CREATED_QUERY`/`F_DUPFD_QUERY`/`F_GETOWNER_UIDS`/`F_GETDELEG`/`F_SETDELEG` all fall through to `EINVAL` | syscalls | `fs/fcntl.c do_fcntl`; `mm/memfd.c:223 F_ALL_SEALS` | `072_fcntl.rs:116,264` | M |
| 75 | `fdatasync` | ext4's two `FileOps::fsync` impls take `_datasync` and ignore it — the timestamp-only elision that is `fdatasync`'s purpose is absent | ext4 | `fs/ext4/fsync.c ext4_sync_file` | `ext4/src/rootfs/inode/regular.rs:212` | S |
| 76 | `truncate` | no `i_writecount`/`get_write_access` anywhere → no `ETXTBSY` on truncating a running executable; `break_lease(O_WRONLY)` never called | vfs+fs | `fs/open.c:104-112 vfs_truncate` | `fs/src/truncate.rs` | M |
| 77 | `ftruncate` | same missing `i_writecount` infrastructure (one lane with 76) | vfs | `include/linux/fs.h:2817 deny_write_access` | absent; `vfs/src/inode/model.rs` | M |
| 78 | `getdents` | synthetic filesystems iterate with ORDINAL cursors, so an insert/unlink between calls shifts every later `d_off` | fs+procfs | `fs/libfs.c dcache_readdir / d_alloc_cursor` | `fs/src/tmpfs/dir.rs:67-78` | M |
| 82 | `rename` | `d_move` mints a NEW dentry instead of re-parenting, so an fd/cwd across a rename renders the old path + ` (deleted)`; no `__d_exchange`; no `IS_DEADDIR`→ENOENT | vfs | `fs/dcache.c:3050 __d_move` | `vfs/src/dcache/rename.rs:55-77` | M |
| 83 | `mkdir` | no directory-link-count ceiling — ext4 `mkdir` has no `EMLINK` gate | ext4 | `fs/ext4/namei.c ext4_mkdir` | `ext4/src/rootfs/inode/special.rs:78-94` | S |
| 84 | `rmdir` | no `is_local_mountpoint`→`EBUSY`; the predicate exists and its only caller is `rename` | syscalls | `fs/namei.c:5368-5369 vfs_rmdir` | `084_rmdir.rs:39-52` | S |
| 85 | `creat` | inherits `openat`'s `may_open` hole: append-only `EPERM`, `O_NOATIME`-non-owner `EPERM`, `MAY_EXEC` `EACCES` all absent | vfs | `fs/namei.c:4281-4290 may_open` | `vfs/src/namei/permission.rs:172-182` | S |
| 87 | `unlink` | no `is_local_mountpoint`→`EBUSY`; and ext4 frees data blocks + inode INLINE at `links_count==0` ignoring open fds — unlink-while-open frees live blocks under a reader | ext4 | `fs/ext4/namei.c:3299 ext4_orphan_add`; `fs/inode.c:1975` | `ext4/src/ialloc.rs:389-424` | L |
| 89 | `readlink` | `bufsiz` read as u64, only `==0` rejected; Linux's parameter is `int` and `bufsiz<=0` is `EINVAL` | syscalls | `fs/stat.c do_readlinkat` | `089_readlink.rs:16` | S |
| 92 | `chown` | `setattr_should_drop_sgid` is complete, tested, and has zero production callers — `do_chown` sets `ATTR_KILL_SGID` unconditionally so Linux's non-executable-setgid arm never fires; `ATTR_KILL_PRIV` absent | syscalls+vfs | `fs/open.c chown_common` | `perms_common.rs:152-162`; `vfs/src/setattr.rs:254-262` | S |
| 93 | `fchown` | same shared `do_chown` gap | syscalls | `fs/open.c chown_common` | `perms_common.rs:152-162` | S |
| 97 | `getrlimit` | `RLIMIT_CPU/CORE/NPROC/AS/SIGPENDING/RTTIME` stored, rendered in `/proc/*/limits`, read by nothing | sched | `posix-cpu-timers.c check_process_timers`; `fork.c copy_process`; `signal.c:418` | `sched/src/rlimit.rs` | L |
| 98 | `getrusage` | only `ru_utime`/`ru_stime` filled; 14 fields hard-zeroed although `min_flt`/`maj_flt`/`nvcsw`/`nivcsw` now exist on `Task`; `RUSAGE_SELF` reports the thread, not the group | syscalls | `kernel/sys.c k_getrusage` | `098_getrusage.rs:25-42` | S |
| 100 | `times` | `tms_utime`/`tms_stime` are the calling task's counters, not `thread_group_cputime_adjusted` | syscalls | `kernel/sys.c do_sys_times` | `100_times.rs:23-31` | S |
| 101 | `ptrace` | no signal-delivery-stop, no `PTRACE_EVENT_*` generation, `traced_by` never reaches `wait4`/notify — `gdb -p` and `strace -p` non-functional | syscalls+sched | `kernel/signal.c ptrace_signal`; `kernel/ptrace.c ptrace_event` | `syscalls/src/signal.rs:67`; `101_ptrace/sig.rs:28` | L |
| 102 | `getuid` | returns the raw ruid; Linux munges through the caller's user namespace (`from_kuid_munged`) | sched | `kernel/sys.c:1030` | `sched/src/cred/uid.rs:45` | L |
| 104 | `getgid` | raw rgid, no `from_kgid_munged` | sched | `kernel/sys.c:1039` | `sched/src/cred/gid.rs:46` | L |
| 105 | `setuid` | arg used as a raw uid, no `make_kuid`; also no `flag_nproc_exceeded` deferred-`EAGAIN` at execve | sched | `kernel/sys.c:659,:536` | `sched/src/cred/uid.rs:66-79` | L |
| 106 | `setgid` | arg used as a raw gid, no `make_kgid` | sched | `kernel/sys.c __sys_setgid` | `sched/src/cred/gid.rs:79` | L |
| 107 | `geteuid` | raw euid, no `from_kuid_munged` | sched | `kernel/sys.c:1033` | `sched/src/cred/uid.rs:53` | L |
| 108 | `getegid` | raw egid, no `from_kgid_munged` | sched | `kernel/sys.c getegid` | `sched/src/cred/gid.rs:54` | L |
| 112 | `setsid` | `ctty` is a per-`Task` cell, so `setsid` clears only the calling thread's controlling terminal; Linux holds it in `signal_struct` | sched | `drivers/tty/tty_jobctrl.c proc_clear_tty` | `sched/src/task.rs:389`; `session.rs:167` | M |
| 113 | `setreuid` | both args treated as raw uids | sched | `kernel/sys.c __sys_setreuid` | `sched/src/cred/uid.rs:88-105` | L |
| 114 | `setregid` | both args treated as raw gids | sched | `kernel/sys.c __sys_setregid` | `sched/src/cred/gid.rs:104` | L |
| 115 | `getgroups` | writes raw gids; Linux writes `from_kgid_munged` per element | sched | `kernel/groups.c getgroups` | `sched/src/cred/groups.rs:62-69` | L |
| 116 | `setgroups` | stores supplied gids verbatim; Linux `make_kgid`s each and `EINVAL`s an unmapped one | sched | `kernel/groups.c groups_from_user` | `sched/src/cred/groups.rs:93-105` | L |
| 117 | `setresuid` | three raw uids, no `make_kuid` | sched | `kernel/sys.c __sys_setresuid` | `sched/src/cred/uid.rs:126-148` | L |
| 118 | `getresuid` | writes raw uids, no `from_kuid_munged` | sched | `kernel/sys.c getresuid` | `sched/src/cred/resid.rs:41` | L |
| 119 | `setresgid` | three raw gids, no `make_kgid` | sched | `kernel/sys.c __sys_setresgid` | `sched/src/cred/gid.rs:140` | L |
| 120 | `getresgid` | writes raw gids | sched | `kernel/sys.c getresgid` | `sched/src/cred/resid.rs:53` | L |
| 122 | `setfsuid` | raw id in/out; and `cap_emulate_setxuid`'s root test hardcodes `ROOT_UID=0` where Linux uses `make_kuid(ns,0)`, so `CAP_FS_MASK` juggling misfires for a userns-mapped root | sched | `kernel/sys.c __sys_setfsuid`; `security/commoncap.c` | `sched/src/cred/fsid.rs:39`; `capfix.rs:38` | L |
| 123 | `setfsgid` | raw id in/out, no `make_kgid` | sched | `kernel/sys.c __sys_setfsgid` | `sched/src/cred/fsid.rs:63` | L |
| 128 | `rt_sigtimedwait` | the out-of-set interrupt test reads `deliverable_signals_self()` only, so a process-directed out-of-set signal does not interrupt a non-leader waiter | syscalls+sched | `kernel/signal.c:3755,:946 wants_signal` | `128_rt_sigtimedwait.rs:105,127` | L |
| 130 | `rt_sigsuspend` | same `shared_pending` root cause: a non-leader thread suspended for a PROCESS-directed signal never wakes | syscalls+sched | `kernel/signal.c:4843,:963` | `130_rt_sigsuspend.rs:53,67` | L |
| 135 | `personality` | `MMAP_PAGE_ZERO`/`ADDR_COMPAT_LAYOUT`/`ADDR_LIMIT_3GB` have zero consumers; no arch `SET_PERSONALITY` at exec | sched | `fs/binfmt_elf.c`; `arch/x86/kernel/process_64.c` | `sched/src/personality.rs:21,23,35` | S |
| 140 | `getpriority` | `PRIO_USER`/`PRIO_PGRP` walk the global registry with no `task_pid_vnr(p)` visibility test — a caller in a child pid ns observes tasks outside it | syscalls | `kernel/sys.c getpriority` | `priority_common.rs:26,32-35` | S |
| 141 | `setpriority` | same namespace gap on the write side; no `security_task_setnice` analogue | syscalls | `kernel/sys.c setpriority` | `priority_common.rs:26,32-35` | S |
| 144 | `sched_setscheduler` | no RR quantum anywhere (`task_tick_rt` 0 hits) so `SCHED_RR == SCHED_FIFO`; the unconditional tick resched + tail requeue *also* round-robins `SCHED_FIFO`; `SCHED_BATCH == SCHED_NORMAL`; no deadline class | sched | `kernel/sched/rt.c:2540`; `deadline.c:3644` | `sched/src/rt.rs:1-6`; `task/types.rs:36` | L |
| 148 | `sched_rr_get_interval` | reports a Linux-correct quantum that nothing enforces | syscalls | `kernel/sched/rt.c:2623` | `sched_policy.rs:181` | S |
| 149 | `mlock` | errno ORDER inverted (range→`ENOMEM` before `can_do_mlock`→`EPERM`); `len==0` with an unaligned addr returns 0 where Linux locks one page | syscalls | `mm/mlock.c:618-665` | `149_mlock_family.rs:23-33,121-122` | S |
| 150 | `munlock` | same rounding divergence; validates the whole range up front where Linux applies VMA-by-VMA and leaves earlier VMAs unlocked on a hole | syscalls | `mm/mlock.c:683-697,:520-560` | `149_mlock_family.rs:23-33,136-150` | S |
| 151 | `mlockall` | no `can_do_mlock()`→`EPERM` and no `total_vm > RLIMIT_MEMLOCK`→`ENOMEM`: any unprivileged process pins its whole AS. `MCL_FUTURE` state never clears | syscalls | `mm/mlock.c:751-778,:710-716` | `149_mlock_family.rs:175-186` | S |
| 155 | `pivot_root` | commit re-roots the whole namespace and re-seats mounts by rendered path STRING; Linux detaches `root_mnt` and never touches `mnt_ns->root`. `MNT_LOCKED` rung dead | vfs | `fs/namespace.c:4701-4738` | `vfs/src/mount/namespace.rs:171-203` | M |
| 157 | `prctl` | still `EINVAL` for Linux-implemented options: `PR_SET_SECCOMP(FILTER)`, `PR_SET_TSC`, `PR_SET/GET_IO_FLUSHER`, `PR_SET_SYSCALL_USER_DISPATCH`, `PR_SET/GET_MDWE`, `PR_GET_AUXV`, `PR_FUTEX_HASH`, arm64 `PR_SET/GET_TAGGED_ADDR_CTRL` | sched | `kernel/sys.c prctl` | `sched/src/prctl.rs:32-34` | M |
| 158 | `arch_prctl` | `ARCH_SET_GS`/`ARCH_GET_GS` answer `EINVAL`; blocked on the no-swapgs entry model (`docs/54`). `ARCH_*_XCOMP_*` likewise | syscalls | `arch/x86/kernel/process_64.c do_arch_prctl_64` | `158_arch_prctl.rs:76` | M |
| 160 | `setrlimit` | ladder complete; the same six limits as row 97 are enforced nowhere | sched | as row 97 | `sched/src/task/rlimits.rs:36` | L |
| 163 | `acct` | `f.majflt = 0` behind a stale comment (F766 added live `Task::maj_flt`); `minflt` reads the mm-wide counter, not the task's | syscalls | `kernel/acct.c acct_collect` | `syscalls/src/acct_exit.rs:74,89` | S |
| 165 | `mount` | **FIXED B1478** (flags half). `graft_mount` passed a hardcoded `0` as `mnt_flags`, so every fresh mount had an EMPTY flags word — the consumers (exec `may_suid`, `may_open` EROFS/EACCES, mmap) already existed and were reading "unrestricted" from a word nothing wrote. Also: `MS_STRICTATIME` precedence was inverted, `MS_NOSYMFOLLOW` undefined, remount atime not preserved, `mnt_want_write` ignored `sb_rdonly`. **Audit correction: binds are NOT a gap** — `path_mount` DISCARDS `mnt_flags` for `MS_BIND` (`do_loopback(path, dev_name, flags & MS_REC)`) and the clone inherits from its source, which this tree already did. **Remaining:** `sb_flags` still never reach `fill_super` (a `construct()` signature change across every fstype); options string still dropped by most fs ctors | syscalls | `fs/namespace.c path_mount`, `:2983`, `:2862-2909` | `165_mount.rs:42,237,288-293,341` | L |
| 166 | `umount2` | `MNT_FORCE` validated then never referenced (no `umount_begin` in tree); `MNT_EXPIRE` no two-pass mark; busy detection is only `has_child_mounts` — no `mnt_count`/open-fd/cwd `EBUSY` | syscalls | `fs/namespace.c:1870,1915,1953-1960` | `166_umount2.rs:40-50,151-185` | L |
| 202 | `futex` | all six PI ops return `ENOSYS` (no rt-mutex/`pi_state`/prio boost) so `PTHREAD_PRIO_INHERIT` fails; user-word access is raw `read_volatile` with no exception table, so `FUTEX_WAKE_OP` on an unmapped word faults the kernel | ipc | `kernel/futex/pi.c`; `futex.h futex_get_value_locked` | `ipc/src/live/futex/wait.rs:98-100`; `core.rs:168-182` | L |
| 203 | `sched_setaffinity` | a task currently RUNNING on a now-disallowed CPU is only nudged and keeps running there until it next schedules | sched | `kernel/sched/core.c → stop_one_cpu(migration_cpu_stop)` | `sched/src/live/ttwu.rs relocate_for_affinity` | M |
| 206 | `io_setup` | no aio ring is mmap'd: `aio_context_t` is a small monotonic integer in a process-GLOBAL registry, not the ring's user address, so libaio dereferences it; no `aio-max-nr` | syscalls | `fs/aio.c lookup_ioctx, ioctx_alloc` | `syscalls/src/aio.rs:117-142` | L |
| 207 | `io_destroy` | global registry only: a foreign ctx id is destroyable, no wait for outstanding requests, no ring unmap, never reaped at exit | syscalls | `fs/aio.c io_destroy` | `syscalls/src/aio.rs:146-149` | L |
| 208 | `io_getevents` | `min_nr` and `timeout` both discarded — the call never blocks | syscalls | `fs/aio.c read_events` | `syscalls/src/aio.rs:290-292` | L |
| 209 | `io_submit` | every iocb executes synchronously inline; `IOCB_CMD_POLL`/`NOOP` `EINVAL`; `aio_rw_flags` never read; `aio_flags`/`aio_reserved2` unvalidated | syscalls | `fs/aio.c __io_submit_one` | `syscalls/src/aio.rs:178-188,229-240` | L |
| 210 | `io_cancel` | unconditional `EINVAL` with no iocb lookup; the `result` out-param is never written | syscalls | `fs/aio.c io_cancel` | `syscalls/src/aio.rs:305-308` | L |
| 217 | `getdents64` | identical to row 78 — same ordinal synthetic-fs cursors | fs | `fs/libfs.c dcache_readdir` | `fs/src/tmpfs/dir.rs:67-78` | M |
| 221 | `fadvise64` | `WILLNEED` populates SYNCHRONOUSLY where Linux submits async readahead and returns | syscalls | `mm/fadvise.c generic_fadvise` | `221_fadvise64.rs` | S |
| 222 | `timer_create` | expiry queues NO siginfo for a STANDARD signal, so the NULL-sigevent SIGALRM default delivers `SI_USER` not `SI_TIMER`; `SigInfo` has no `si_tid`/`si_overrun` fields so both are always 0 | sched | `kernel/time/posix-timers.c:530-531,:322` | `sched/src/timers/runtime.rs:55-60`; `task/types.rs:7-13` | M |
| 230 | `clock_nanosleep` | a DYNAMIC per-thread CPU clock naming pid 0 returns `EOPNOTSUPP` where Linux returns `EINVAL`; `CpuMeasure::Sched` samples `utime+stime` where Linux uses `task_sched_runtime()`, while `getres` advertises `HRTIMER_RES_NS` | sched | `posix-cpu-timers.c:198-199,:1639-1642` | `sched/src/timers/clockid.rs:103-105`; `clock.rs:77-86` | S |
| 231 | `exit_group` | same `disassociate_ctty(1)` gap as row 60 | syscalls+tty | `drivers/tty/tty_jobctrl.c` | `060_exit.rs:39` | M |
| 233 | `epoll_ctl` | no `file_can_poll` `EPERM` for a non-pollable target; the self-add `EINVAL` is gated on `op != EPOLL_CTL_DEL` where Linux's check is unconditional | fs | `fs/eventpoll.c:2632-2643` | `fs/src/epoll/syscalls.rs:112-114` | S |
| 247 | `waitid` | same tracer↔wait gap as row 61 | syscalls | `kernel/exit.c wait_task_stopped` | `247_waitid.rs:123` | M |
| 249 | `request_key` | the kernel has NO usermode-helper primitive at all, so a key can never be CONSTRUCTED — a miss is always `ENOKEY` and `callout_info`/`dest_keyring` are unusable | fs | `security/keys/request_key.c call_sbin_request_key` | `fs/src/keyring/ops/links.rs:150` | M |
| 251 | `ioprio_set` | the stored value is consumed by nothing (0 `ioprio` hits in `block`/`drivers`); `CLONE_IO` is not parsed anywhere, so threads never share an io_context | syscalls+block | `block/mq-deadline.c`; `kernel/fork.c copy_io` | `syscalls/src/ioprio.rs` | M |
| 252 | `ioprio_get` | reports a value nothing acts on; same missing `CLONE_IO` | syscalls | `block/ioprio.c:180` | `syscalls/src/ioprio.rs` | S |
| 253 | `inotify_init` | blocking `read()` returns `EAGAIN` on an empty queue regardless of `O_NONBLOCK`; Linux blocks in `wait_woken` | fs | `fs/notify/inotify/inotify_user.c inotify_read` | `fs/src/inotify/group.rs:136-163` | S |
| 254 | `inotify_add_watch` | `IN_EXCL_UNLINK` stored and never consulted; no `max_user_watches` `ENOSPC` gate; the fd decoder accepts a FANOTIFY group where Linux `EINVAL`s on `f_op` | fs+procfs | `inotify_user.c inotify_new_watch` | `fs/src/inotify/syscalls.rs:39-45,165-191` | M |
| 255 | `inotify_rm_watch` | same type confusion — `inotify_rm_watch(fanotify_fd, wd)` destroys a fanotify mark instead of `EINVAL` | fs | `inotify_user.c inotify_rm_watch f_op check` | `fs/src/inotify/syscalls.rs:39-45,209-218` | S |
| 257 | `openat` | `may_open` missing append-only `EPERM`, `O_NOATIME`-non-owner `EPERM`, `MAY_EXEC` `EACCES`; and `/proc/sys/fs/protected_symlinks` reports `1` while no `may_follow_link` exists — the restriction is fabricated | vfs+procfs | `fs/namei.c:4281-4290`; `may_follow_link` | `vfs/src/namei/permission.rs:172-182`; `procfs/src/ctl.rs:224` | M |
| 258 | `mkdirat` | shares row 83's core — no `EMLINK` ceiling | ext4 | `fs/ext4/namei.c ext4_mkdir` | `ext4/src/rootfs/inode/special.rs:78-94` | S |
| 260 | `fchownat` | same shared `do_chown` gap as 92/93 | syscalls | `fs/open.c chown_common` | `perms_common.rs:152-162` | S |
| 263 | `unlinkat` | inherits row 87's mountpoint-`EBUSY` and ext4 unlink-while-open block free | ext4 | `fs/namei.c:5504`; `fs/ext4/namei.c` | `ext4/src/ialloc.rs:389-424` | L |
| 264 | `renameat` | same `d_move`/`__d_exchange` identity defect as row 82 | vfs | `fs/dcache.c:3050` | `vfs/src/dcache/rename.rs:55-77` | M |
| 267 | `readlinkat` | same unsigned-`bufsiz` defect as row 89 | syscalls | `fs/stat.c do_readlinkat` | `267_readlinkat.rs:17` | S |
| 272 | `unshare` | `copy_mnt_ns_map` clones every SHARED mount as `Slave` UNCONDITIONALLY; Linux adds `CL_SLAVE` only across user namespaces, so same-userns `unshare(CLONE_NEWNS)` loses two-way peer propagation. No `create_user_ns` capability grant | vfs+syscalls | `fs/namespace.c:4262-4264`; `kernel/user_namespace.c` | `vfs/src/mount/namespace_lifecycle.rs:43-50` | M |
| 275 | `splice` | `SPLICE_F_MORE` exists only as a constant — never translated to `MSG_MORE` on a socket output | fs | `fs/splice.c splice_to_socket` | `fs/src/splice/flags.rs:13-14` | S |
| 278 | `vmsplice` | pipe buffers are a plain byte ring with no page identity, so `PIPE_BUF_FLAG_GIFT` page stealing cannot exist | fs | `fs/splice.c user_page_pipe_buf_try_steal` | `fs/src/pipe/ring.rs:52-71` | L |
| 281 | `epoll_pwait` | `set_user_sigmask` deferred restore absent: the temporary mask is swapped back before any signal is dispatched, so an interrupting handler runs under the ORIGINAL mask | fs+sched | `fs/eventpoll.c do_epoll_pwait`; `kernel/signal.c set_user_sigmask` | `fs/src/epoll/syscalls.rs:281-284` | M |
| 282 | `signalfd` | a BLOCKING signalfd read never blocks (no waitqueue park, no `ERESTARTSYS`); read/poll consult only `cur.sigpending`; 9 `signalfd_siginfo` fields always zero | fs | `fs/signalfd.c signalfd_read, signalfd_copyinfo` | `fs/src/signalfd.rs:54-93` | M |
| 283 | `timerfd_create` | no release path — the global table holds an `Arc` for every timerfd ever created, and the fd→state lookup keys 24 inode bits against a u32 id so id 2^24 aliases id 0; blocking `read` never tests for a deliverable signal (spins at 100% CPU while one is pending); no `show_fdinfo` | fs | `fs/timerfd.c:270-281,:314,:352-374` | `fs/src/timerfd.rs:55-57,127-131,163-186` | M |
| 284 | `eventfd` | a blocking `write()` on overflow returns `EAGAIN` instead of parking; `EPOLLERR` for the `ULLONG_MAX` state not reported | fs | `fs/eventfd.c eventfd_write, eventfd_poll` | `fs/src/pipe/eventfd.rs:142-161` | S |
| 285 | `fallocate` | ext4 `COLLAPSE_RANGE` and `INSERT_RANGE` fall to `EOPNOTSUPP`; Linux ext4 implements both, so the in-tree comment defending the errno is false. `S_SWAPFILE` set by no production code, so the `ETXTBSY` gate is unreachable | ext4 | `fs/ext4/extents.c:5525,:4708` | `ext4/src/rootfs/inode/fallocate.rs:26-60` | M |
| 286 | `timerfd_settime` | no `CAP_WAKE_ALARM` re-check; `old` copied out BEFORE `new` is validated, so an `EINVAL` settime still clobbers `*old`; a realtime clock step wakes nothing; never returns `ECANCELED`; expired-periodic `old->it_value` reports 0 | fs | `fs/timerfd.c:479-481,:493,:99-113,:526-529` | `fs/src/timerfd.rs:282-346,364-382` | M |
| 287 | `timerfd_gettime` | never advances an expired periodic timer, so a periodic timerfd inspected only with `gettime` reads `{0,0}` forever; output pointer validated before the fd (`EFAULT` where Linux is `EBADF`) | fs | `fs/timerfd.c:545-560` | `fs/src/timerfd.rs:469-500` | S |
| 288 | `accept4` | same listener-option-inheritance gap as row 43 | net | `net/core/sock.c sk_clone_lock` | `net/src/sock/construct.rs:151-186` | M |
| 289 | `signalfd4` | identical body to row 282 (one `SignalfdFileOps` serves both slots) | fs | `fs/signalfd.c do_signalfd4` | `fs/src/signalfd.rs:54-93` | M |
| 290 | `eventfd2` | same blocking-write defect as row 284 | fs | `fs/eventfd.c eventfd_write` | `fs/src/pipe/eventfd.rs:142-161` | S |
| 294 | `inotify_init1` | same blocking-read `EAGAIN` as row 253 | fs | `inotify_user.c inotify_read` | `fs/src/inotify/group.rs:161` | S |
| 296 | `pwritev` | `MAX_RW_COUNT` is defined and never applied — the loop has no running-total cap where Linux truncates at `INT_MAX & PAGE_MASK` | syscalls | `lib/iov_iter.c:1389-1404` | `296_pwritev.rs:95-160` | S |
| 298 | `perf_event_open` | the fabrication is FIXED (F766) but there is still no sampling ring buffer (0 `perf_mmap`/`PERF_RECORD` hits), so `perf record` collects nothing; no `attr.inherit`; no tracepoint/kprobe/hardware PMUs | fs | `kernel/events/core.c perf_mmap, perf_output_begin` | `fs/src/perf/{open,file,ioctl}.rs` | L |
| 300 | `fanotify_init` | `FAN_REPORT_FID`/`DIR_FID`/`NAME` accepted at init but the read path emits only the 24-byte legacy metadata — no `fanotify_event_info_fid` record exists in tree; the blocking read is a `tick_yield` spin with no signal check | fs | `fanotify_user.c copy_info_records_to_user` | `fs/src/inotify/group.rs:59-88,136-150` | L |
| 301 | `fanotify_mark` | `dirfd` is bound to `_dirfd` and discarded: a relative pathname resolves against CWD, and the `pathname == NULL` form is unreachable | fs | `fanotify_user.c fanotify_find_path` | `fs/src/inotify/syscalls.rs:258` | M |
| 303 | `name_to_handle_at` | the encoder emits an inode-only FID with no parent, so `AT_HANDLE_CONNECTABLE` can never be satisfied and always takes the `FILEID_INVALID` → `EOVERFLOW` path | syscalls | `fs/fhandle.c do_sys_name_to_handle` | `303_name_to_handle_at.rs:96-108` | M |
| 304 | `open_by_handle_at` | decode is `sb.ilookup(ino)` — resident inodes only; no `export_operations`/`fh_to_dentry`, so a handle to an evicted inode is `ESTALE`; `may_decode_fh`'s second leg absent | syscalls | `fs/fhandle.c do_handle_to_path`; `fs/exportfs/expfs.c` | `304_open_by_handle_at.rs:64,89` | L |
| 307 | `sendmmsg` | native `sendmmsg` treats `MSG_CMSG_COMPAT` as a caller-settable 32-bit-layout switch; Linux forbids the flag on every native entry point | syscalls | `net/socket.c:2851-2855,2963-2968` | `307_sendmmsg.rs:12-17` | S |
| 308 | `setns` | the `NsOwner::Mnt` arm calls only `replace_mount_namespace` — no `set_fs_root`/`set_fs_pwd`, and unlike `unshare` it does not even call `remap_fs_mount_ids`, so a joiner keeps resolving in the namespace it left. B1472 fixed only the init path | nscg | `fs/namespace.c:6479 mntns_install,:6516-6517` | `nscg/src/proc_ns.rs:279` | S |
| 314 | `sched_setattr` | extensible-struct ABI complete; `SCHED_DEADLINE` validated and permission-checked, then refused `EOPNOTSUPP` because no deadline class exists | sched | `kernel/sched/deadline.c:3644` | `sched/src/task/types.rs:36` | L |
| 315 | `sched_getattr` | every `dl_*` field and `SCHED_GETATTR_FLAG_DL_DYNAMIC` report state that cannot exist | syscalls | `kernel/sched/syscalls.c:1060` | `sched_policy.rs` | S |
| 316 | `renameat2` | same `d_move`/`__d_exchange` identity defect as 82/264 | vfs | `fs/dcache.c:3050` | `vfs/src/dcache/rename.rs:55-77` | M |
| 317 | `seccomp` | **FIXED B1478** except user-notif. `RET_TRACE` failed open; NNP/`CAP_SYS_ADMIN` gate, TSYNC, `KILL_PROCESS` (was folded onto `KILL_THREAD` by masking with `SECCOMP_RET_ACTION` 0x7fff0000, dropping bit 31), `TRAP` `_sigsys` siginfo, real `instruction_pointer`, cBPF verifier and fork `seccomp_mode` all added. **Audit corrections:** a tracerless `RET_TRACE` does NOT act as `KILL_THREAD` — Linux ENOSYS-es and SKIPS (`__seccomp_filter`), the task lives; `RET_LOG` does not fail open, it IS allow-after-audit; the filter chain WAS cloned on fork, only the MODE was not. **Audit missed:** `BPF_RET\|BPF_A` decoded with `BPF_SRC`(&0x08) not `BPF_RVAL`(&0x18), so every `return A` became `return k`≈`KILL_THREAD`; uncapped `RET_ERRNO`; `MODE_STRICT` faked with a synthesised filter; no `MAX_INSNS_PER_PATH`. **Remaining:** `RET_USER_NOTIF`/`NEW_LISTENER` — install now ENOSYS rather than returning an unsupervised filter | security | `kernel/seccomp.c __seccomp_filter` | `security/src/seccomp/` | L |
| 319 | `memfd_create` | `F_SEAL_EXEC` absent from the `F_ADD_SEALS` mask; tmpfs `setattr` has no `F_SEAL_EXEC` arm so `chmod +x` on a sealed memfd succeeds; no `vm.memfd_noexec` sysctl | syscalls+fs | `mm/memfd.c:223-230`; `mm/shmem.c:1329` | `072_fcntl.rs:116`; `fs/src/tmpfs/flags.rs` | S |
| 321 | `bpf` | a functional void, not a security hole: 10 of ~39 commands dispatched; no bpffs/BTF/object-ID registries so bpftool+libbpf load nothing; one map type | security | `kernel/bpf/syscall.c __sys_bpf` | `security/src/bpf.rs:113-128` | L |
| 323 | `userfaultfd` | **SECURITY HALF FIXED B1478.** COPY/ZEROPAGE were an arbitrary-write primitive (installed USER\|RW at any VA with NO VMA and no registration); now `validate_dst_vma`'s ENOENT ladder + the registration EBUSY/EPERM/EINVAL ladder. `userfaultfd_syscall_allowed` gate added (+ `vm.unprivileged_userfaultfd`, default 0) and `UFFD_USER_MODE_ONLY` actually enforced through the fault path on both arches. `ctx->mm` replaces `current_mm()`; `EEXIST`; `uffdio_api` now 24 bytes with `ioctls` written; range bitmap off-by-one fixed. **Audit corrections:** Linux cites `mm/userfaultfd.c` — `fs/userfaultfd.c` does NOT exist in v7.2.0-rc4; `validate_dst_vma` tests the ctx pointer NON-NULL, not identity (identity is MOVE-only); there is no `ctx->mm != current->mm` check outside `userfaultfd_move`. **Remaining:** WP/MINOR/MOVE/POISON unimplemented — now EINVAL at REGISTER (Linux's own arm without `pgtable_supports_uffd_wp()`) instead of silently never delivering | fs+mm-vmm | `mm/userfaultfd.c:4481-4503`; `uapi/linux/userfaultfd.h:50-57,162` | `fs/src/userfaultfd/ioctl.rs:34-40,113-132` | L |
| 324 | `membarrier` | `PRIVATE_EXPEDITED_RSEQ` refused and kept out of the QUERY mask, but the stated justification is now false — rseq `rseq_cs` decode, IP fixup and signature validation exist on both arches | syscalls | `kernel/sched/membarrier.c` | `syscalls/src/membarrier.rs:48-50` | S |
| 328 | `pwritev2` | `RwEffect.append`/`.nowait` are computed and never consumed — `RWF_APPEND` writes at the supplied offset instead of `i_size`, `RWF_NOWAIT` is admitted then blocks | syscalls | `fs/read_write.c:1748-1749` | `296_pwritev.rs:26-40` | S |
| 329 | `pkey_mprotect` | accepts pkey 0; on x86_64 without OSPKE Linux answers `EINVAL` because `execute_only_pkey` stays 0. Also runs the pkey check before the prot/len checks. Oxide matches arm64, not x86_64 | syscalls | `mm/mprotect.c:836-876`; `arch/x86/include/asm/pkeys.h:53-72` | `syscalls/src/pkey.rs:43-53` | S |
| 330 | `pkey_alloc` | B1434's `ENOSPC` is right for arm64 and wrong for x86_64: x86's `mm_pkey_alloc` has no OSPKE guard, so the FIRST call returns `EINVAL` from `arch_set_user_pkey_access` | syscalls | `mm/mprotect.c:999-1027`; `arch/x86/kernel/fpu/xstate.c:1083-1093` | `syscalls/src/pkey.rs:34-38` | S |
| 331 | `pkey_free` | unconditional `EINVAL` is correct on x86_64 and wrong on aarch64: arm64 `init_new_context` sets `pkey_allocation_map = BIT(0)` unconditionally, so `pkey_free(0)` returns 0 | syscalls | `arch/arm64/include/asm/pkeys.h:49-60` | `331_pkey_free.rs:19` | S |
| 332 | `statx` | `STATX_DIOALIGN` never advertised or filled (0 hits repo-wide); Linux `ext4_getattr` fills both alignment fields whenever requested. Same for `STATX_WRITE_ATOMIC` | syscalls | `fs/ext4/inode.c ext4_getattr` | `statx_abi.rs` | S |
| 333 | `io_pgetevents` | `sigmask`/`sigsetsize` never read; inherits row 208's ignored `min_nr`/`timeout` | syscalls | `fs/aio.c io_pgetevents` | `syscalls/src/aio.rs:297-299` | L |
| 336 | `uprobe` | `-ENXIO` is libbpf's POSITIVE capability signal, so we advertise a subsystem that does not exist; with `CONFIG_UPROBES=n` Linux answers `ENOSYS` | syscalls | `kernel/sys_ni.c:396`; `tools/lib/bpf/features.c:577` | `336_uprobe.rs` | S |
| 424 | `pidfd_send_signal` | a supplied siginfo is validated then DISCARDED (no `sigq_push`); `THREAD_GROUP`/`PROCESS_GROUP` post the pending bit to EVERY matching thread, so one kill is delivered N times | syscalls | `kernel/signal.c pidfd_send_signal` | `424_pidfd_send_signal.rs:25,58-80` | S |
| 425 | `io_uring_setup` | `MAX_ENTRIES` is 64 (Linux 32768) because `map_kernel_frame` maps a whole VMA to one PA; 17 `IORING_SETUP_*` flags validated-and-refused; no `io_uring_allowed()` gate, so `sysctl_io_uring_disabled`/`io_uring_group` `EPERM` never fires | syscalls | `io_uring/io_uring.c io_uring_allowed, IORING_MAX_ENTRIES` | `io_uring/abi/layout.rs:25-32` | L |
| 426 | `io_uring_enter` | `min_complete`/`flags` bound to `_` and `sig`/`argsz` never read — `GETEVENTS` never blocks, `REGISTERED_RING`/`EXT_ARG` unsupported, no sigmask. Only 15 `IORING_OP_*` dispatch; no `IOSQE_IO_LINK`/`DRAIN`/`ASYNC`/`CQE_SKIP_SUCCESS`, no `POLL_ADD`/`TIMEOUT`/`ASYNC_CANCEL`, no multishot | syscalls | `io_uring/io_uring.c io_uring_enter` | `426_io_uring_enter.rs:22-23`; `io_uring/dispatch.rs:35-58` | L |
| 427 | `io_uring_register` | 26 opcodes recognised-then-`EOPNOTSUPP`; registered buffers stored as `(base,len)` and re-validated per use instead of pinned, so a concurrent munmap/remap changes what a `REGISTERED_BUFFERS` op reads | syscalls | `io_uring/register.c __io_uring_register`; `rsrc.c io_sqe_buffer_register` | `io_uring/register.rs`; `io_uring/abi/register_op.rs` | L |
| 428 | `open_tree` | no flag validation at all; `AT_SYMLINK_NOFOLLOW`/`AT_NO_AUTOMOUNT` never reach the walker; the non-clone form installs an fd over the INODE with an anon dentry, so it cannot serve as a `move_mount` source or an `*at()` dirfd | syscalls | `fs/namespace.c:3194-3234` | `428_open_tree.rs:15-63` | M |
| 429 | `move_mount` | `args.a4` read only for a debug trace — no `MOVE_MOUNT_*` constant exists in tree, so garbage flags are accepted and `SET_GROUP`/`BENEATH`/`*_EMPTY_PATH` are neither implemented nor rejected | syscalls | `fs/namespace.c move_mount` | `429_move_mount.rs:45,55,108-114` | M |
| 430 | `fsopen` | admission is a hardcoded 20-name whitelist shadowing the VFS registry (split source of truth); no `fscontext_alloc_log`, so the error messages `fsconfig` should expose via `read(2)` are unreadable | syscalls | `fs/fsopen.c fsopen` | `430_fsopen.rs:19-30`; `fsmount_common/registry.rs:15-29` | S |
| 431 | `fsconfig` | `FSCONFIG_SET_FD` hardcoded `EINVAL`; `aux` never read so `SET_PATH`'s dirfd is ignored; `SET_BINARY` read as a NUL-terminated cstr so blobs with embedded NULs truncate; `CMD_CREATE_EXCL` aliased onto `CMD_CREATE` | syscalls | `fs/fsopen.c fsconfig` | `431_fsconfig.rs:52-56,71-84` | M |
| 432 | `fsmount` | **FIXED B1478.** `require_sys_admin()` replaced by one owner, `may_mount()` = `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` (`fs/namespace.c`), shared by 155/165/166/428/429/430/432/433/442; the gate also moved AFTER path resolution to match `do_mount` ordering. Found en route: `fs/super.c` `mount_capable` was missing entirely — `FS_USERNS_MOUNT` was set on procfs/sysfs but NOTHING read it, so a userns holder could mount ext4/tmpfs/devpts. `MNT_NOSYMFOLLOW` now set from `MS_NOSYMFOLLOW` | syscalls+vfs | `fs/namespace.c do_fsmount`; `fs/namei.c pick_link` | `432_fsmount.rs:29`; `vfs/src/mount/mnt_flags.rs` | S |
| 433 | `fspick` | `dirfd` ignored entirely (every relative fspick resolves against cwd); path capped at 256 vs `PATH_MAX`; `FSPICK_*` flags rejected where Linux honours them; no mount-root `EINVAL` | syscalls | `fs/fsopen.c fspick` | `433_fspick.rs:22-30` | S |
| 434 | `pidfd_open` | fdinfo `Pid:`/`NSpid:` render the target's own vtid with no reader-relative resolution and no ancestry chain | pidfd | `fs/pidfs.c pidfd_show_fdinfo` | `pidfd/src/file.rs:65-80` | S |
| 435 | `clone3` | `set_tid` never read (so `set_tid_size=0` with a pointer is silently accepted and CRIU pid restore is impossible); `CLONE_NEWTIME` wrongly rejected because the `CSIGNAL` test uses the whole 0xff mask; `CLONE_DETACHED` not rejected | syscalls | `kernel/fork.c:2918,2950-2955`; `uapi/linux/sched.h:48` | `435_clone3.rs:70,93-97` | S |
| 437 | `openat2` | **FIXED B1478.** The `O_CREAT` branch dropped `extra` into `resolve_parent_at`, so every `RESOLVE_*` bit stopped constraining the create. **Correction to the audit row, which named `RESOLVE_BENEATH`: only `RESOLVE_IN_ROOT` produced a LIVE escape.** IN_ROOT is the sole scoping bit that CLAMPS instead of erroring, so the scoped phase-1 walk returns ENOENT and hands control to the unscoped phase-2 parent walk, which then follows the real `..`/root. BENEATH (EXDEV), NO_SYMLINKS (ELOOP) and NO_XDEV (EXDEV) all abort in phase 1, so their create branch was unreachable — incidentally covered, not enforced. Proven in `namei_create_scope.rs`, which asserts each phase-1 errno. Now `openat2_resolve::parent_lookup_flags` + `resolve_parent_at_flags` carry every scoping bit into the parent walk, per `fs/open.c` `build_open_flags` → one `op->lookup_flags` for the whole walk | syscalls | `fs/open.c build_open_flags`; `fs/namei.c path_openat` | `openat2_resolve.rs`; `pathresolve/at.rs resolve_parent_at_flags`; tests `vfs/tests/namei_create_scope.rs`, `wait_diff/openat2_resolve.c` | S |
| 438 | `pidfd_getfd` | carries its own open-coded `__ptrace_may_access` instead of `sched::ptrace_access::may_access`, and OMITS the dumpability gate — a target that dropped privileges can still have its fds stolen | syscalls | `kernel/ptrace.c __ptrace_may_access` | `438_pidfd_getfd.rs:65-87` | S |
| 439 | `faccessat2` | the non-`AT_EACCESS` cred override never consults `issecure(SECURE_NO_SETUID_FIXUP)`, which Linux tests first; no `ESTALE` `LOOKUP_REVAL` retry | syscalls | `fs/open.c do_faccessat` | `pathresolve/cred.rs:42-46` | S |
| 440 | `process_madvise` | no `mm_access(PTRACE_MODE_READ_FSCREDS)` gate at all; advice set capped at 5 behaviours even for a SELF target; the return is the unconditional sum of iovec lengths with per-range errors discarded | syscalls | `mm/madvise.c:2085-2151,:2042` | `440_process_madvise.rs:71-77,101-134` | M |
| 441 | `epoll_pwait2` | same `set_user_sigmask` immediate-restore defect as row 281 | fs | `fs/eventpoll.c do_epoll_pwait` | `fs/src/epoll/syscalls.rs:245-285` | M |
| 442 | `mount_setattr` | no unknown-flag rejection; accepts `usize == 24` where `MOUNT_ATTR_SIZE_VER0` is 32, and no `> PAGE_SIZE` `E2BIG`; `propagation` unvalidated; `AT_RECURSIVE` applies the propagation change to the top mount only although `set_propagation_recursive` exists | syscalls | `fs/namespace.c build_mount_kattr,:4921` | `442_mount_setattr.rs:39,59,137-147` | M |
| 444 | `landlock_create_ruleset` | ABI version 1 vs Linux 10; flags tested with `&` not `==` so attr/size are not rejected; no `handled_access_fs` validation; raw `read_volatile`; `REGISTRY` Vec never pruned (unprivileged unbounded growth) | syscalls+security | `security/landlock/syscalls.c:172,209-256` | `444_landlock_create_ruleset.rs:22-30`; `security/src/landlock.rs:98` | M |
| 445 | `landlock_add_rule` | `flags` never read; `allowed_access` never validated against the ruleset's handled mask; NET_PORT rule type absent; `parent_fd` accepted from any fd | syscalls | `security/landlock/syscalls.c get_path_from_fd` | `445_landlock_add_rule.rs:22-31,47` | M |
| 446 | `landlock_restrict_self` | no `no_new_privs`/`CAP_SYS_ADMIN` gate; `flags` never read; no `LANDLOCK_MAX_NUM_LAYERS`; and `access::EXECUTE` is advertised with ZERO consumers, so no landlock check runs on the execve path | syscalls+security | `security/landlock/syscalls.c:526-548` | `446_landlock_restrict_self.rs:19-33` | M |
| 447 | `memfd_secret` | NOT ABSENT-OK: `CONFIG_SECRETMEM` is default-y with its dependency met on both arches and `can_set_direct_map()` true on both, so real Linux grants it. `ENOSYS` is caused by oxide's own 1 GiB linear map | syscalls+mm | `mm/secretmem.c:224-238`; `mm/Kconfig:1356-1359` | `447_memfd_secret.rs`; `secretmem.rs:22-49` | L |
| 448 | `process_mrelease` | wrong in both directions: current Linux has no self-target `EINVAL` and no permission check, oxide adds both; and oxide omits `find_lock_task_mm`, `MMF_OOM_SKIP`, killable-mmap-lock `EINTR`, and reaps only anonymous VMAs | syscalls | `mm/oom_kill.c:1195-1257` | `448_process_mrelease.rs:43-53,78-88` | M |
| 451 | `cachestat` | writes 40 zero bytes after a correct admission ladder; Linux walks the mapping xarray filling five counters. Fabricated data | syscalls | `mm/filemap.c filemap_cachestat` | `451_cachestat.rs:47-52` | M |
| 457 | `statmount` | `req->param` never read; a fixed mask CLAIMS `SB_BASIC\|MNT_BASIC` while six fields stay zero, so a caller cannot distinguish "not set" from zero; `mnt_root` is `"/"` for every mount including binds | syscalls | `fs/namespace.c:5304-5344,:5873` | `457_statmount.rs:45,88,94-106` | M |
| 458 | `listmount` | subtree membership is a path-STRING prefix compare, not `is_path_reachable` — wrong exactly where bind clones share mountpoint dentries; no `EOVERFLOW` cap; `mnt_ns_id` ignored | syscalls | `fs/namespace.c:6123-6163` | `458_listmount.rs:32-35,71-76` | M |
| 459 | `lsm_get_self_attr` | terminal `EOPNOTSUPP` correct; residual is ordering — flags validated before the size read where Linux does `get_user(size)`→`EFAULT` first | syscalls | `security/security.c:3746-3754` | `syscalls/src/lsm.rs:33` | S |
| 460 | `lsm_set_self_attr` | adds an `attr == LSM_ATTR_UNDEF`→`EINVAL` check Linux does not have, shadowing `E2BIG` | syscalls | `security/security.c:3819-3832` | `syscalls/src/lsm.rs:45` | S |
| 467 | `open_tree_attr` | validates `uattr`/`usize` and then DISCARDS them, tail-calling `open_tree`; Linux runs `do_mount_setattr` on the resulting path | syscalls | `fs/namespace.c:5186-5217` | `467_open_tree_attr.rs:15-24` | S |
| 468 | `file_getattr` | kernfs/devfs install no `i_op->fileattr_get`, so `/dev` inodes answer `EOPNOTSUPP` where Linux's shmem-backed devtmpfs answers 0 | vfs+kernfs | `mm/shmem.c shmem_fileattr_get` | `vfs/src/inode_ops.rs:232`; `kernfs/src/dir_ops.rs:11` | S |
| 469 | `file_setattr` | same backend hole for `fileattr_set` | vfs+kernfs | `mm/shmem.c shmem_fileattr_set` | `kernfs/src/dir_ops.rs:11` | S |
| 471 | `rseq_slice_yield` | the body is exact, but the whole slice-extension GRANT machinery is absent, so the syscall can only ever answer 0: `PR_RSEQ_SLICE_EXTENSION` `EINVAL`, no preempt-time grant, no revoke timer | sched | `kernel/rseq.c:812`; `include/linux/rseq_entry.h` | `sched/src/rseq/uaccess.rs:70`; `sched/src/prctl.rs:34` | M |

## 3 Bucket C — flip to `IMPL`

Do not edit the matrix from this document. A follow-up lane makes these three edits (`line.split('|')`: Status=8, Branch=9, Evidence=12).

| Nr | Syscall | Gap named in Evidence | Closed by | Evidence in current source |
|---|---|---|---|---|
| 162 | `sync` | journal WAL barriers discarded `dev.flush()` | `B1462-durable-write-path` (5df061976, PR#4098) | all three `commit_metadata` barriers now `map_err(…)?`; `audit-vfs.md` §4 records `sync(2)` shape incl. bind-mount sb dedup as matching; Linux `sync(2)` never propagates a writeback error, so the residue is void |
| 306 | `syncfs` | no `s_wb_err` errseq latch | `B1462-durable-write-path` (5df061976, PR#4098) | `vfs::errseq::Errseq` ports `lib/errseq.c`; `SuperBlock.s_wb_err` + `File.f_sb_err` sampled at open, harvested by `check_and_advance_sb_err()`; `f_sb_err`/`f_wb_err` advance independently |
| 322 | `execveat` | no `MAY_EXEC`/`path_noexec` gate, no setuid transition | `B1464-exec-privilege-transition` (55bacb625, PR#4095) | `pathresolve/exec.rs` is the single `do_open_execat` gate on the live path; `exec_creds::transition` implements `bprm_creds_from_file` in full; findings §2 blocker 11 marked DONE |

## 4 Work order

Grouped so each block is one lane with one owner. Ordered by value per unit of work.

### 4.1 sched — RT + deadline classes (rows 144, 148, 314, 315)
`task_tick_rt` (RR quantum **and** FIFO non-preemption — the missing tick hook inverts FIFO's defining guarantee, which the old triage missed), `sched_rt_runtime_us` throttling, then the deadline class. Highest-value sched item; `rtkit`/`pipewire`/`gnome-shell` all request RT policy. **L.**

### 4.2 sched — process-wide pending signals (rows 62, 128, 130, 282, 289)
A real `signal_struct::shared_pending` that the *delivery* path dequeues from, plus `wants_signal`, plus `sigq_push` on `kill(2)`. Five rows collapse into one structure. **L.**

### 4.3 sched+tty — controlling terminal on the thread group (rows 60, 112, 231)
Move `ctty` from `Task` to `ThreadGroup`, then `proc_clear_tty` and `disassociate_ctty(1)` at session-leader exit. **M.**

### 4.4 sched+syscalls — ptrace (rows 61, 101, 247)
`__ptrace_link` so `traced_by` reaches `wait4`/`waitid`/notify, signal-delivery-stop, `PTRACE_EVENT_*` generation. Unblocks `gdb -p` and `strace -f`. **L.**

### 4.5 sched — rlimit enforcement (rows 97, 160)
One lane fanned to six enforcement points: fork (`NPROC`), mmap (`AS`), coredump (`CORE`), POSIX CPU timers (`CPU`→SIGXCPU), `__sigqueue_alloc` (`SIGPENDING`), RT watchdog (`RTTIME`). `RSS`/`LOCKS` are upstream no-ops; `MSGQUEUE` (F760) and `MEMLOCK` are already enforced. **L.**

### 4.6 sched+user-namespace — kuid/kgid translation (rows 102-123, 16 rows)
The translator already exists and is correct (`user-namespace/src/translate.rs`) with two callers repo-wide. This is the findings §3.1 pattern at its largest. Must be a `Cred` type split (kuid vs uid) done together with `stat`/`chown`/`/proc`, or it creates the split source of truth the project forbids. **L, own phase.**

### 4.7 syscalls — the aio family (rows 206-210, 333)
Per-mm `ioctx_table`, an mmap'd ring whose address IS the `aio_context_t`, real async submission, blocking `io_getevents`. Today libaio dereferences a small integer, so fio/PostgreSQL/MySQL SIGSEGV rather than degrade. **L.**

### 4.8 syscalls — io_uring (rows 425, 426, 427)
Multi-frame ring regions (`MAX_ENTRIES` 64 → 32768), `io_uring_allowed()`, blocking `GETEVENTS` with `min_complete`/sigmask, the op table beyond 15, pinned registered buffers. **L.**

### 4.9 vfs+ext4 — inode lifetime (rows 87, 263)
`orphan_add` on every `links_count == 0` with open fds; `evict_inode` at last `iput`. The POSIX unlink-open idiom currently frees live blocks under a reader. **L.**

### 4.10 vfs — `i_writecount` (rows 76, 77, and row 59's third item)
One primitive (`get_write_access`/`deny_write_access`) closes `ETXTBSY` on truncate, ftruncate, `open(O_WRONLY)` of a live binary, and execve of a file open for write. **M.**

### 4.11 vfs — dentry identity across rename (rows 82, 264, 316)
Real `__d_move`/`__d_exchange` that re-parent in place. Fixes ` (deleted)` paths through `/proc/<pid>/fd` and `getcwd`. **M.**

### 4.12 vfs — mount flags and permission model (rows 155, 165, 166, 428-433, 442, 457, 458, 467)
Three shared root causes, one lane each:
- **`MS_*` never reaches a graft** (165) plus `may_mount()` = `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` replacing the flat `require_sys_admin()` on seven syscalls. **L.**
- **`MNT_LOCKED` is set by nothing** — four consumer checks (umount, move, pivot_root, expiry) are dead. Prerequisite for 272's unprivileged-userns story. **M.**
- **`top_mount_on` resolves by dentry pointer alone**, taking `max(mnt_id)`; sits under 166's busy test, 429's source lookup, 442's propagation target and 458's reachability. **M.**

Then the per-syscall field work on 428-433/442/457/458/467, which is mechanical once the three above land.

### 4.13 vfs+syscalls — `setns` re-root (row 308)
`set_fs_root`/`set_fs_pwd` in the `NsOwner::Mnt` arm. B1472 fixed only the init path. Smallest containment-escape fix on the list. **S.**

### 4.14 fs — blocking reads that never block (rows 253, 254, 255, 282, 283, 284, 290, 294, 300)
inotify, fanotify, eventfd, signalfd and timerfd all return `EAGAIN` or spin instead of parking on a wait queue with a signal check. One wait-queue idiom, applied at nine sites. **M.**

### 4.15 fs+sched — `set_user_sigmask` deferred restore (rows 281, 441)
`TIF_RESTORE_SIGMASK` semantics: keep the temporary mask installed on `EINTR` so the just-unblocked signal reaches its handler. `ppoll`/`pselect6` already do this. A signal-dispatch change, not an epoll change. **M.**

### 4.16 security — seccomp (row 317)
Nine named behaviours. Order: NNP gate → flags (TSYNC first) → `RET_TRACE` fail-closed → cBPF verifier at load → `seccomp_mode` fork inheritance → siginfo → user-notif. Settle the `prctl` front-door disagreement first: its justification cites an aarch64 evaluator bug that `8dcd79888` may already have fixed. **L.**

### 4.17 security — landlock (rows 444, 445, 446)
The NNP gate, the ruleset refcount/free, ABI version, flag validation, and wiring `ACCESS_FS_EXECUTE` into the execve path. **M.**

### 4.18 mm — userfaultfd (row 323)
The 24-byte `uffdio_api`, the range-ioctl bitmap, `ctx->mm` targeting with `EEXIST`, the no-VMA fallback (an unprivileged arbitrary-VA RW mapping primitive), and the admission gate. WP/MINOR modes after. **L.**

### 4.19 net — socket option inheritance and OOB (rows 43, 44, 46, 47, 288)
`sk_clone_lock`-equivalent inheritance for accepted sockets, then AF_UNIX OOB with `sk_send_sigurg`. **M.**

### 4.20 net+vfs — SIGIO/SIGURG delivery (row 16)
`kill_fasync` has no production callers; wire it from the socket, pipe and tty readiness paths. **M.**

### 4.21 Small independent fixes, no lane structure needed
Rows 49, 62, 84, 83/258, 89/267, 92/93/260, 135, 140/141, 149/150/151, 163, 221, 233, 275, 296, 307, 315, 319 (+72), 324, 328, 332, 336, 424, 434, 435, 437, 438, 439, 459, 460, 467, 468/469. Each is one check, one mask, or one field. `openat2`'s `O_CREAT` confinement bypass (437) is the highest-value of these — it is a live sandbox escape.

## 5 What I could not determine

| Question | Why it matters | Where it sits |
|---|---|---|
| Mechanism of "SIGABRT does not kill a threaded process" (findings §10 item 3) | gdm died `11/SEGV` not `6/SIGABRT`. Every link was re-read at HEAD and is correct: `do_tkill` queues an `SI_TKILL` record and calls `signal_wake_up`; `exit_to_user::work_flags` re-reads `sigpending & !sigmask` live (so the glibc `rt_sigprocmask`-unblock theory is dead); `take_lowest_pending` forces SIG_DFL; `signal_dispatch.rs:139-153` routes `Core` through `do_group_exit`. Two untested suspects: `fs::coredump::write_for_current` runs *before* `do_group_exit` and does a full tmpfs write + devfs register on the dying thread; or the observation predates B1471 | Needs a targeted guest repro (self-`tgkill(SIGABRT)` from a non-leader pthread), not more reading. Not cleanly ownable by any row; closest is 231 |
| `wait4`/`waitid` `WUNTRACED`/`WCONTINUED` encoding and one-shot re-report suppression | The constants in `exit/status.rs:23-31,64-69` are right; the consumer side was not read line by line. `audit-sched.md` lists the same item as undetermined | Rows 61, 247 |
| Whether TCP listeners honour `SO_REUSEPORT` listener-group selection on inbound SYN | UDP/ICMP endpoint groups demonstrably do (`stack_icmp.rs:101-167`); no TCP counterpart found, but the full SYN demux was not read | Adjacent to row 50; no assigned row rests on it |
| AF_VSOCK message-level conformance | Never diffed against `net/vmw_vsock/`; findings §5 records the same | Adjacent to rows 41-55 |
| Whether the `prctl(PR_SET_SECCOMP)` refusal's cited aarch64 evaluator bug is still live | If the evaluator is still wrong, slot 317 accepting the identical program is a live hazard, not just an inconsistency | Row 317 |
| Whether the production fault handler recovers from a kernel-mode fault at an unmapped user VA | Bounds the consequence of the raw-`read_volatile` user accesses in futex (202), mqueue and splice — trivially reachable unprivileged kernel fault, or merely wrong errno | Row 202 and the wider uaccess surface |

## 6 Corrections to earlier ledgers

Verified stale — strike the clause, keep the row unless noted.

| Claim | Where | Correction |
|---|---|---|
| `rseq` missing `rseq_cs`/IP-fixup | `partial-gap-triage.md` A1 | Stale. Decode, IP fixup and signature validation all present on both arches; only `rseq_signal_deliver` is absent. `membarrier`'s refusal of `PRIVATE_EXPEDITED_RSEQ` is therefore no longer justified (row 324) |
| `personality(ADDR_NO_RANDOMIZE)` is a no-op; ASLR absent | `partial-gap-triage.md` A2; row 135 | Stale. F771 implemented all six ASLR components; `exec_transition::exec_rnd` reads the bit with `per_clear` folded in first. Row 135's remaining gap is the *other three* personality bits |
| `F_SETLEASE` has no blocking lease break | `partial-gap-triage.md` A3; row 72 | Stale. `break_lease_for_open` blocks, signals, force-breaks at 45 s. The real lease gaps are the missing owner auto-setup and `try_break_deleg` outside `openat` |
| `RLIMIT_MEMLOCK` unenforced | `partial-gap-triage.md` A3 | Stale. Enforced for `mlock`/`mlock2`; bypassed only by `mlockall(2)` (row 151) and `mmap(MAP_LOCKED)` (row 9, out of scope here) |
| aarch64 vDSO blob missing, blocking the target check | matrix row 16, ~14 occurrences | Stale. `vdso-aarch64.so` is a gitignored build artifact generated by `vdso/build.sh` (clang+lld) and invoked by `tools/xtask/src/cmds.rs:38`. Closed by `98855a3fb` + `a0343d298`. Every "aarch64 target check blocked" line on row 16 is dead text |
| `ns_capable_setid` degrades to a global effective-set check | all 16 cred rows | **Not a gap.** Linux calls `ns_capable_setid(old->user_ns, CAP_SETUID)`; with `targ_ns == cred->user_ns`, `cap_capable`'s first loop iteration returns `cap_raised(cred->cap_effective, cap)` — exactly what `Task::has_cap` does. Strike it from all 16 |
| `BPF_PROG_ATTACH` returns 0 (systemd `DeviceAllow=` silently unenforced) | `audit-net-sec.md` §8 | Stale. F766 (`64e638ec7`) made it `EINVAL` via `attr::prog_attach_verdict`, matching Linux's `CONFIG_CGROUP_BPF=n` stub. Downgrade that SECURITY row |
| `bpf_lsm` reachable from `257_openat.rs` | `audit-net-sec.md` §8 | Stale call site. `bpf_lsm` is now reachable only via `LINK_CREATE`; the `file_open` hook still has no runner |
| timerfd "read parks on the 100 ms scanner; nothing ever fires" | findings §2 blocker 2, §9 | Partly stale. B1460 gave `read` an `hrtimeout` park and poll/epoll fold `poll_deadline_ns` into the park deadline, so expiry now lands on the hardware one-shot. Row 283's remaining gaps are the leak, the id aliasing, the signal check and fdinfo |
| `perf_event_open` fabricates counters | findings §3.3 | Fixed by F766. Row 298's remaining gap is the absent sampling ring buffer |
| `pkey_alloc` returns ENOSPC without OSPKE | B1434 | **Wrong for x86_64.** x86's `mm_pkey_alloc` has no `arch_pkeys_enabled()` guard, so the first call returns `EINVAL` from `arch_set_user_pkey_access`; `ENOSPC` only from the second call on. arm64 *does* guard, so `ENOSPC` is right there. Same defect class B1434 was created to fix, one level deeper |
| `acct` is ABSENT-OK | assumed | Wrong. Fedora ships `CONFIG_BSD_PROCESS_ACCT=y` and oxide implements the syscall; row 163 is a one-field A |
| `map_shadow_stack`, `memfd_secret` are symmetric "absent feature" rows | assumed | Asymmetric. `map_shadow_stack` is genuinely ABSENT-OK (both arches gate on a hardware feature the QEMU target lacks). `memfd_secret` is **not**: `CONFIG_SECRETMEM` is default-y with its dependency met, so real Linux grants it |
| `d_move` has no callers | `audit-vfs.md` §1 | Stale. `082_rename.rs:183` calls it now. The identity defect inside `d_move` is unchanged |
| Create paths use the wrong idmap | new finding | Every create path hardcodes `CreateCtx{ idmap: &vfs::IDENTITY }` while `stat`/`statx`/`fileattr` use `mount::idmap_for(mnt_id)`. **Latent only** — `mount_setattr` rejects `MOUNT_ATTR_IDMAP`, so no idmapped mount can exist. Becomes a live bug the day idmapped mounts land |
| `/proc/sys/fs/protected_regular`, `protected_fifos` | new finding | Writable `Int` cells while enforcement uses compile-time constants — writing them silently does nothing. Split source of truth affecting rows 85 and 257 |

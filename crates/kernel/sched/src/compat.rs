// P3-46 compat-stub dispatch helper. Pulls the "accept and
// return constant" + "ENOSYS" + "EPERM" tail of `oxide_syscall_dispatch`
// out of `syscall_glue.rs` to keep that file under the 1000-line
// cap per `08§7`. `try_compat(nr)` returns `Some(rv)` if `nr` is
// one of the compat-stubbed slots, `None` to let the caller
// fall through to its real-impl arms or the in-table dispatch.


use syscall::SyscallArgs;
use syscall::errno::Errno;

use syscall::nrs::*;

/// Match `nr` against the broad set of syscalls we compat-stub.
/// Real implementations override these via earlier match arms in
/// `oxide_syscall_dispatch` — `try_compat` only fires when nothing
/// upstream has claimed the slot.
/// # C: O(1)
pub fn try_compat(nr: u64, args: &SyscallArgs) -> Option<i64> {
    let _args = args;
    let enosys  = -(Errno::Enosys.as_i32() as i64);
    let eperm   = -(Errno::Eperm.as_i32()  as i64);
    let eintr   = -(Errno::Eintr.as_i32()  as i64);
    let _ = -(Errno::Eopnotsupp.as_i32() as i64); // unused after F90

    match nr {
        // ---- accept silently ----
        // GETGROUPS/SETGROUPS/SETUID/SETGID/SETREUID/SETREGID/SETRES{U,G}ID/SETFS{U,G}ID
        // moved to real impl in syscall_glue_cred.rs (F64).
        // CAPGET/CAPSET moved to real impl in F66 (Creds carries cap masks).
        // SYSLOG moved to real impl (F67) — exposes klog ring as dmesg.
        // PERSONALITY (F78), FUTIMESAT (F78), VHANGUP (F87) moved to real impls.
        // NR_SYNCFS / NR_SYNC_FILE_RANGE moved to sys_fsync
        // (real fd validation; v1 RAM-only fs is always sync, so the
        // syscall is a true no-op for valid fds and EBADF for bad).
        NR_READAHEAD | NR_FADVISE64 | NR_MLOCK2
                                       => sys_fadvise_validate(_args),

        // ---- POSIX shape: pause/sigsuspend behaviour ----
        NR_RESTART_SYSCALL  => Some(eintr),

        // ---- silent-0 (accept; nothing to track v1) ----
        // get_robust_list / set_robust_list moved to real impl in F65.
        NR_CACHESTAT
        // POSIX timer family moved to real impl in F71 (per-task slot
        // array + syscall-return-tail firing).
        // pkey_* — userspace 'always have pkey 0' fallback. Linux pkey
        // alloc returns -1 (and EINVAL) when MPK isn't supported; we
        // return 0 because callers (glibc/musl) treat any non-negative
        // alloc result as "you have a key" and skip the unsupported branch
        // by reading /proc/self/status PkeyMask. Real MPK rides docs/06.
        // pkey_* moved to real (per-task) allocator below.
        // process_madvise / process_mrelease — KCMP / NUMA family
        // moved to real impls in `syscall_glue_misc.rs`.
        // Keyring (P38b admit). PAM/login/sudo/dbus probe these at
        // start-up; -ENOSYS makes them refuse to authenticate. v1
        // returns silent-0 (a synthetic "key serial" for callers
        // that only check non-negative). Real keyring storage +
        // permission checks ride a follow-up.
        // ADD_KEY / REQUEST_KEY / KEYCTL moved to real impl (F76).
        // POSIX MQ admin ops. MQ_OPEN/UNLINK/TIMEDSEND/TIMEDRECEIVE
        // are real (priority-ordered records via posix_mq.rs).
        // MQ_NOTIFY/GETSETATTR stay silent-0 (no per-task signal-on-
        // arrival yet, no live mq_attr mutation).
        // MQ_NOTIFY / MQ_GETSETATTR moved to real impl (F77).
                                       => Some(0),

        // xattr family moved to real impl (F90, xattr_overlay.rs).

        // ---- privileged-op refuse ----
        // No substrate yet for any of these (mount/reboot/modules/
        // kexec/iopl/timex). Cap-gating (F92) doesn't change the
        // outcome on v1 since both paths land on EPERM, but the
        // substrate-landing PRs (v2 phases 29 mount, etc.) will check
        // the relevant CAP_* in the real handler.
        // MOUNT / UMOUNT2 moved to real impl in F110 (tmpfs backend).
        // NR_REBOOT moved to real impl (sys_reboot via power crate).
        NR_PIVOT_ROOT
        | NR_INIT_MODULE | NR_DELETE_MODULE | NR_FINIT_MODULE
        | NR_KEXEC_LOAD  | NR_KEXEC_FILE_LOAD
        | NR_IOPL | NR_IOPERM
        | NR_ADJTIMEX | NR_CLOCK_ADJTIME
                                       => Some(eperm),

        // ---- substrate-not-implemented ----
        // PTRACE moved to real (narrow) impl in P22a/P22b — TRACEME +
        // ATTACH/DETACH/PEEK/POKE/CONT/GETREGS admission. Real foreign-mm
        // peek/poke + signal-stop machinery rides P22c.
        // SPLICE/TEE/VMSPLICE moved to real impls in PR-N.
        // COPY_FILE_RANGE moved to real impl in PR-J.
        // MEMFD_CREATE / MEMFD_SECRET — PR-H / PR-U.
        // PIDFD_GETFD moved to real impl (F70).
        // xattr family: handled in the ENOTSUP arm below — Linux's
        // 'no xattr on this filesystem' response. Programs that
        // probe (e.g., tar, cp -a) treat ENOTSUP as gracefully-skip,
        // whereas ENOSYS aborts the operation entirely.
        NR_SWAPON | NR_SWAPOFF
        // SysV IPC + POSIX MQ + keyring.
        // SysV shm moved to real impl (P25a).
        // SysV sem moved to real impl (P25b — non-blocking semop;
        //   would-block returns EAGAIN).
        // SysV msg moved to real impl (P25c — non-blocking msgrcv).
        // POSIX MQ moved to real impl (B16 — priority-ordered
        // records in posix_mq.rs). MQ_NOTIFY/GETSETATTR stay
        // silent-0 above. Keyring moved to silent-0 admit above.
        // Misc ENOSYS.
        | NR_LOOKUP_DCOOKIE | NR_REMAP_FILE_PAGES
        | NR_USELIB | NR_USTAT | NR_SYSFS | NR_MODIFY_LDT
        | NR_QUOTACTL | NR_QUOTACTL_FD | NR_ACCT
        // POSIX timer family (timer_create/settime/gettime/getoverrun/delete)
        // moved to silent-0 below — userspace tolerates "no timer fires"
        // better than -ENOSYS, which crashes hardened systemd setups.
        // PROCESS_VM_READV/WRITEV moved to real impl (F75).
        | NR_NAME_TO_HANDLE_AT | NR_OPEN_BY_HANDLE_AT
        // OPENAT2 / FACCESSAT2 aliased to openat / faccessat in PR-M.
        // Modern mount API moved to real (admit) impls in P29a — fsopen/
        // fsconfig/fsmount/fspick/open_tree/move_mount/mount_setattr return
        // fds where applicable, accept silently otherwise. Per-NS mount
        // table substrate rides a follow-up.
        // FANOTIFY moved to real (narrow) impl in P27a — backed by
        // existing inotify infra. Only init returns an fd; mark is a
        // no-op accept that records nothing for v1. Real recursive-
        // watch + permission-event reply ride a follow-up.
        // RECVMMSG/SENDMMSG moved to real impl in PR-G.
        // PSELECT6/SELECT moved to real impl in PR-Q (poll-based).
        // WAITID moved to real impl in PR-K (alias of wait4 + siginfo_t).
        // GET_ROBUST_LIST + CACHESTAT handled below as silent-0.
        // NUMA SET/MBIND/MIGRATE/MOVE/HOME silent-0 above.
        // GET_MEMPOLICY moved to real impl (F79).
        | NR_VSERVER | NR__SYSCTL
        // FUTEX_WAITV: real multi-futex wait substrate not yet wired.
        // Silent-0 was the worst possible answer (programs thought a
        // wait completed without one). ENOSYS makes glibc fall back
        // to the per-futex FUTEX_WAIT polling loop.
        | NR_FUTEX_WAITV
        // EXECVEAT aliased to execve in PR-P (path resolved relative to dirfd).
        // PREADV2/PWRITEV2 moved to real impl (alias of preadv/pwritev) in PR-H.
        // userfaultfd; epoll moved to real impl.
        // USERFAULTFD moved to real impl in P28a (fd + UFFDIO ioctls).
        // io_uring + libaio + perf + bpf + seccomp + landlock + ns.
        // IO_URING moved to real (synchronous) impl in P23a — opcode
        // dispatch over SQ→CQ ring. SQPOLL/IOPOLL/fixed-buffer ride
        // follow-ups.
        | NR_IO_SETUP | NR_IO_DESTROY | NR_IO_GETEVENTS
        | NR_IO_SUBMIT | NR_IO_CANCEL | NR_IO_PGETEVENTS
        // SECCOMP / BPF / LANDLOCK / PERF_EVENT_OPEN moved to real
        // (narrow) impls in P24a — seccomp filter via cBPF interpreter
        // is the headliner; bpf + landlock + perf_event_open admit
        // and return fds, but full verifier / JIT / LSM-hook delivery
        // ride follow-ups.
        // UNSHARE / SETNS / PIVOT_ROOT: see real impl below (UNSHARE/SETNS)
        // and the privileged-refuse arm (PIVOT_ROOT).
        // socket family + signal-extras + preadv/pwritev (v1 alternates)
        // are all dispatched as real impls in syscall_glue.rs above
        // try_compat — these arms are dead. The real-impl path is the
        // source of truth; remove the stale ENOSYS list to avoid
        // misleading future readers.
                                       => Some(enosys),

        _ => None,
    }
}

/// Shared validation for advisory cache hints (fadvise/readahead/mlock2).
/// Linux returns 0 when args are sane, EBADF for bad fds, EINVAL for
/// negative lengths. v1 has no page cache so the hint itself is a
/// true no-op once validation passes.
/// # C: O(1)
pub fn sys_fadvise_validate(args: &SyscallArgs) -> Option<i64> {
    let fd  = args.a0 as i32;
    let len = args.a2 as i64;
    if len < 0 {
        return Some(-(Errno::Einval.as_i32() as i64));
    }
    let cur = match crate::live::current() { Some(c) => c, None => return Some(0) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return Some(0) };
    if fdt.get(fd).is_err() {
        return Some(-(Errno::Ebadf.as_i32() as i64));
    }
    Some(0)
}

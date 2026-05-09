// P3-46 compat-stub dispatch helper. Pulls the "accept and
// return constant" + "ENOSYS" + "EPERM" tail of `oxide_syscall_dispatch`
// out of `syscall_glue.rs` to keep that file under the 1000-line
// cap per `08§7`. `try_compat(nr)` returns `Some(rv)` if `nr` is
// one of the compat-stubbed slots, `None` to let the caller
// fall through to its real-impl arms or the in-table dispatch.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::syscall_nrs::*;

/// Match `nr` against the broad set of syscalls we compat-stub.
/// Real implementations override these via earlier match arms in
/// `oxide_syscall_dispatch` — `try_compat` only fires when nothing
/// upstream has claimed the slot.
/// # C: O(1)
pub fn try_compat(nr: u64, _args: &SyscallArgs) -> Option<i64> {
    let enosys  = -(Errno::Enosys.as_i32() as i64);
    let eperm   = -(Errno::Eperm.as_i32()  as i64);
    let eintr   = -(Errno::Eintr.as_i32()  as i64);
    let enotsup = -(Errno::Eopnotsupp.as_i32() as i64);

    match nr {
        // ---- accept silently ----
        // GETGROUPS/SETGROUPS/SETUID/SETGID/SETREUID/SETREGID/SETRES{U,G}ID/SETFS{U,G}ID
        // moved to real impl in syscall_glue_cred.rs (F64).
        // CAPGET/CAPSET moved to real impl in F66 (Creds carries cap masks).
        // SYSLOG moved to real impl (F67) — exposes klog ring as dmesg.
        NR_PERSONALITY | NR_VHANGUP
        // SETDOMAINNAME moved to real impl (F68) alongside hostname.
        | NR_FALLOCATE | NR_READAHEAD | NR_FADVISE64
        | NR_FLOCK | NR_SYNC_FILE_RANGE
        | NR_SYNCFS | NR_FUTEX_WAITV | NR_MLOCK2
        | NR_FUTIMESAT
                                       => Some(0),

        // ---- POSIX shape: pause/sigsuspend behaviour ----
        NR_RESTART_SYSCALL  => Some(eintr),

        // ---- silent-0 (accept; nothing to track v1) ----
        // get_robust_list / set_robust_list moved to real impl in F65.
        NR_CACHESTAT
        | NR_TIMER_CREATE | NR_TIMER_SETTIME | NR_TIMER_GETTIME
        | NR_TIMER_GETOVERRUN | NR_TIMER_DELETE
        // pkey_* — userspace 'always have pkey 0' fallback. Linux pkey
        // alloc returns -1 (and EINVAL) when MPK isn't supported; we
        // return 0 because callers (glibc/musl) treat any non-negative
        // alloc result as "you have a key" and skip the unsupported branch
        // by reading /proc/self/status PkeyMask. Real MPK rides docs/06.
        | NR_PKEY_ALLOC | NR_PKEY_FREE | NR_PKEY_MPROTECT
        // process_madvise / process_mrelease — same advise-only
        // semantics as madvise; silent 0 matches the existing madvise
        // arm. process_mrelease is a release-after-OOM optimisation.
        | NR_PROCESS_MADVISE | NR_PROCESS_MRELEASE
        // kcmp — compares two task resources. v1 returns 0 (equal)
        // for every comparison; bash + glibc only use it as an
        // optimization probe.
        | NR_KCMP
        // NUMA family — single-node UMA on v1, so these are no-ops.
        // ENOSYS makes glibc/jemalloc abort their NUMA probe; silent-0
        // matches "policy applied, just one node available". GET_MEMPOLICY
        // is handled separately below since it has writeback semantics.
        | NR_SET_MEMPOLICY | NR_MBIND | NR_MIGRATE_PAGES | NR_MOVE_PAGES
        | NR_SET_MEMPOLICY_HOME_NODE
        // Keyring (P38b admit). PAM/login/sudo/dbus probe these at
        // start-up; -ENOSYS makes them refuse to authenticate. v1
        // returns silent-0 (a synthetic "key serial" for callers
        // that only check non-negative). Real keyring storage +
        // permission checks ride a follow-up.
        | NR_ADD_KEY | NR_REQUEST_KEY | NR_KEYCTL
        // POSIX MQ admin ops. MQ_OPEN/UNLINK/TIMEDSEND/TIMEDRECEIVE
        // are real (priority-ordered records via posix_mq.rs).
        // MQ_NOTIFY/GETSETATTR stay silent-0 (no per-task signal-on-
        // arrival yet, no live mq_attr mutation).
        | NR_MQ_NOTIFY | NR_MQ_GETSETATTR => Some(0),

        // ---- ENOTSUP (Linux 'feature not supported on this fs') ----
        // xattr family: tar/cp -a/rsync probe these and skip cleanly
        // on ENOTSUP, whereas ENOSYS makes them abort the file.
        NR_GETXATTR | NR_LGETXATTR | NR_FGETXATTR
        | NR_LISTXATTR | NR_LLISTXATTR | NR_FLISTXATTR
        | NR_SETXATTR | NR_LSETXATTR | NR_FSETXATTR
        | NR_REMOVEXATTR | NR_LREMOVEXATTR | NR_FREMOVEXATTR
                                       => Some(enotsup),

        // ---- privileged-op refuse ----
        NR_REBOOT | NR_MOUNT | NR_UMOUNT2 | NR_CHROOT | NR_PIVOT_ROOT
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
        NR_PIDFD_GETFD
        // xattr family: handled in the ENOTSUP arm below — Linux's
        // 'no xattr on this filesystem' response. Programs that
        // probe (e.g., tar, cp -a) treat ENOTSUP as gracefully-skip,
        // whereas ENOSYS aborts the operation entirely.
        | NR_SWAPON | NR_SWAPOFF
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
        | NR_PROCESS_VM_READV | NR_PROCESS_VM_WRITEV
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
        // NUMA SET/MBIND/MIGRATE/MOVE/HOME promoted to silent-0 above.
        // GET_MEMPOLICY stays ENOSYS — has writeback semantics (mode/nodemask
        // pointers); silent-0 would leave caller buffers uninitialised.
        // Real impl rides v2 if anything actually depends on it.
        | NR_GET_MEMPOLICY
        | NR_VSERVER | NR__SYSCTL
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

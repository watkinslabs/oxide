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
    let enosys = -(Errno::Enosys.as_i32() as i64);
    let eperm  = -(Errno::Eperm.as_i32()  as i64);
    let eintr  = -(Errno::Eintr.as_i32()  as i64);

    match nr {
        // ---- accept silently ----
        NR_GETGROUPS  | NR_SETGROUPS
        | NR_SETUID | NR_SETGID
        | NR_SETREUID | NR_SETREGID
        | NR_SETRESUID | NR_SETRESGID
        | NR_SETFSUID | NR_SETFSGID
        | NR_CAPGET | NR_CAPSET
        | NR_PERSONALITY | NR_VHANGUP | NR_SYSLOG
        | NR_SETDOMAINNAME
        | NR_FALLOCATE | NR_READAHEAD | NR_FADVISE64
        | NR_FLOCK | NR_SYNC_FILE_RANGE
        | NR_SYNCFS | NR_FUTEX_WAITV | NR_MLOCK2
        | NR_FUTIMESAT
        | NR_SET_ROBUST_LIST
                                       => Some(0),

        // ---- POSIX shape: pause/sigsuspend behaviour ----
        NR_RESTART_SYSCALL  => Some(eintr),

        // ---- privileged-op refuse ----
        NR_REBOOT | NR_MOUNT | NR_UMOUNT2 | NR_CHROOT
        | NR_INIT_MODULE | NR_DELETE_MODULE | NR_FINIT_MODULE
        | NR_KEXEC_LOAD  | NR_KEXEC_FILE_LOAD
        | NR_IOPL | NR_IOPERM
        | NR_ADJTIMEX | NR_CLOCK_ADJTIME
                                       => Some(eperm),

        // ---- substrate-not-implemented ----
        // ptrace + xattr + sendfile/splice family.
        NR_PTRACE
        | NR_SPLICE | NR_TEE | NR_VMSPLICE
        | NR_COPY_FILE_RANGE
        | NR_MEMFD_CREATE | NR_MEMFD_SECRET
        | NR_PIDFD_GETFD
        | NR_GETXATTR | NR_LGETXATTR | NR_FGETXATTR
        | NR_LISTXATTR | NR_LLISTXATTR | NR_FLISTXATTR
        | NR_SETXATTR | NR_LSETXATTR | NR_FSETXATTR
        | NR_REMOVEXATTR | NR_LREMOVEXATTR | NR_FREMOVEXATTR
        | NR_SWAPON | NR_SWAPOFF
        // SysV IPC + POSIX MQ + keyring.
        | NR_SHMGET | NR_SHMAT | NR_SHMCTL | NR_SHMDT
        | NR_SEMGET | NR_SEMOP | NR_SEMCTL | NR_SEMTIMEDOP
        | NR_MSGGET | NR_MSGSND | NR_MSGRCV | NR_MSGCTL
        | NR_MQ_OPEN | NR_MQ_UNLINK | NR_MQ_TIMEDSEND
        | NR_MQ_TIMEDRECEIVE | NR_MQ_NOTIFY | NR_MQ_GETSETATTR
        | NR_ADD_KEY | NR_REQUEST_KEY | NR_KEYCTL
        // Misc ENOSYS.
        | NR_LOOKUP_DCOOKIE | NR_REMAP_FILE_PAGES
        | NR_USELIB | NR_USTAT | NR_SYSFS | NR_MODIFY_LDT
        | NR_QUOTACTL | NR_QUOTACTL_FD | NR_ACCT
        | NR_TIMER_CREATE | NR_TIMER_SETTIME | NR_TIMER_GETTIME
        | NR_TIMER_GETOVERRUN | NR_TIMER_DELETE
        | NR_PROCESS_VM_READV | NR_PROCESS_VM_WRITEV
        | NR_KCMP
        | NR_NAME_TO_HANDLE_AT | NR_OPEN_BY_HANDLE_AT
        | NR_PROCESS_MADVISE | NR_PROCESS_MRELEASE
        | NR_PKEY_MPROTECT | NR_PKEY_ALLOC | NR_PKEY_FREE
        | NR_OPENAT2 | NR_FACCESSAT2
        | NR_MOUNT_SETATTR | NR_OPEN_TREE | NR_MOVE_MOUNT
        | NR_FSOPEN | NR_FSCONFIG | NR_FSMOUNT | NR_FSPICK
        | NR_FANOTIFY_INIT | NR_FANOTIFY_MARK
        // RECVMMSG/SENDMMSG moved to real impl in PR-G.
        | NR_PSELECT6 | NR_SELECT
        | NR_WAITID
        | NR_GET_ROBUST_LIST | NR_CACHESTAT
        | NR_SET_MEMPOLICY | NR_GET_MEMPOLICY
        | NR_MBIND | NR_MIGRATE_PAGES | NR_MOVE_PAGES
        | NR_SET_MEMPOLICY_HOME_NODE
        | NR_VSERVER | NR__SYSCTL
        | NR_EXECVEAT | NR_PREADV2 | NR_PWRITEV2
        // userfaultfd; epoll moved to real impl.
        | NR_USERFAULTFD
        // io_uring + libaio + perf + bpf + seccomp + landlock + ns.
        | NR_IO_URING_SETUP | NR_IO_URING_ENTER | NR_IO_URING_REGISTER
        | NR_IO_SETUP | NR_IO_DESTROY | NR_IO_GETEVENTS
        | NR_IO_SUBMIT | NR_IO_CANCEL | NR_IO_PGETEVENTS
        | NR_PERF_EVENT_OPEN | NR_BPF | NR_SECCOMP
        | NR_LANDLOCK_CREATE_RULESET | NR_LANDLOCK_ADD_RULE
        | NR_LANDLOCK_RESTRICT_SELF
        | NR_UNSHARE | NR_SETNS | NR_PIVOT_ROOT
        // socket family — no net stack.
        | NR_SOCKET | NR_BIND | NR_LISTEN
        | NR_ACCEPT | NR_ACCEPT4 | NR_CONNECT
        | NR_SENDTO | NR_RECVFROM
        | NR_SENDMSG | NR_RECVMSG | NR_SHUTDOWN
        | NR_GETSOCKNAME | NR_GETPEERNAME
        | NR_SOCKETPAIR
        | NR_SETSOCKOPT | NR_GETSOCKOPT
        // Signal extras.
        // RT_SIGTIMEDWAIT / RT_SIGQUEUEINFO / RT_TGSIGQUEUEINFO
        // moved to real impls in PR-D-signals.
        // preadv/pwritev (the v1 alternates, real ones are PREADV/PWRITEV).
        | NR_PREADV | NR_PWRITEV
                                       => Some(enosys),

        _ => None,
    }
}

// 312 kcmp — one syscall, one file (docs/53 §0). ABI shim: resolve the two
// tasks, run the ptrace access gate, then hand the chosen resource pair to
// `kcmp_abi`'s ordering. The type vocabulary and result encoding live in
// `crate::kcmp_abi` (non-gated, hosted-tested); the KCMP_EPOLL_TFD interest
// walk lives in `312_kcmp/epoll_tfd.rs`.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::kcmp_abi::{self as abi, opt_cmp, ptr_cmp};
use crate::misc::misc_common::errno;

#[path = "312_kcmp/epoll_tfd.rs"]
mod epoll_tfd;

/// kcmp(2): compare two tasks' resources by pointer identity.
///
/// Ladder order is Linux's `sys_kcmp` and observable: task lookup
/// (ESRCH) → `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)` on BOTH tasks
/// (EPERM) → the type switch (EINVAL). Validating `type` first, as this shim
/// used to, reports EINVAL where Linux reports ESRCH for a dead pid.
///
/// The return encoding is Linux's ordered, NON-NEGATIVE triple: 0 = same
/// resource, 1 = idx1 orders before idx2, 2 = after. A raw syscall return in
/// `[-4095,-1]` is read by musl/glibc as `-errno`, so an ordering result must
/// never be negative — systemd's `same_fd()` does
/// `r = kcmp(...); if (r >= 0) return !r;`.
/// # C: O(1); O(N_epoll_entries) for KCMP_EPOLL_TFD
pub fn sys_kcmp(args: &SyscallArgs) -> i64 {
    let pid1 = args.a0 as u32;
    let pid2 = args.a1 as u32;
    let ty   = args.a2 as u32;
    let idx1 = args.a3 as u64;
    let idx2 = args.a4 as u64;
    let t1 = match sched::live::registry::resolve_user_pid(pid1) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    let t2 = match sched::live::registry::resolve_user_pid(pid2) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    // Linux gates on the caller being able to inspect BOTH tasks. Without it
    // any process could probe another's descriptor-table / address-space
    // identity — the side channel this gate exists to close.
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Esrch) };
    if crate::s101_ptrace_perm::may_access(cur, &t1).is_err()
        || crate::s101_ptrace_perm::may_access(cur, &t2).is_err() {
        return errno(Errno::Eperm);
    }
    if !abi::type_is_known(ty) { return errno(Errno::Einval); }
    match ty {
        abi::KCMP_FILE => {
            // t1/t2 are arbitrary (possibly-foreign) tasks: clone_fd_table pins
            // each against a concurrent exit-time replace_fd_table(None).
            let f1 = t1.clone_fd_table().and_then(|t| t.get(idx1 as i32).ok());
            let f2 = t2.clone_fd_table().and_then(|t| t.get(idx2 as i32).ok());
            // Linux guarantees -EBADF if either fd is not allocated.
            match (f1, f2) {
                (Some(f1), Some(f2)) => ptr_cmp(Arc::as_ptr(&f1) as usize,
                                                Arc::as_ptr(&f2) as usize),
                _ => errno(Errno::Ebadf),
            }
        }
        // KCMP_VM is 1 and KCMP_FILES is 2.
        // This shim had them swapped, so every caller asking "same address
        // space?" was answered about descriptor tables, and vice versa.
        abi::KCMP_VM => {
            // clone_mm pins each against a concurrent exit/execve mm replacement.
            let p1 = t1.clone_mm().map(|m| Arc::as_ptr(&m) as usize);
            let p2 = t2.clone_mm().map(|m| Arc::as_ptr(&m) as usize);
            opt_cmp(p1, p2)
        }
        abi::KCMP_FILES => {
            let p1 = t1.clone_fd_table().map(|t| Arc::as_ptr(&t) as usize);
            let p2 = t2.clone_fd_table().map(|t| Arc::as_ptr(&t) as usize);
            opt_cmp(p1, p2)
        }
        abi::KCMP_FS => ptr_cmp(Arc::as_ptr(&t1.fs_context()) as usize,
                                Arc::as_ptr(&t2.fs_context()) as usize),
        // Linux `task->sighand`, shared by CLONE_SIGHAND. `sigactions_arc`
        // clones the same Arc `clone(2)` installs, so its allocation address
        // IS the sighand identity two threads of one process share. The old
        // `ptr_cmp(pid1, pid2)` fallback answered "different" for two threads
        // that demonstrably share one table.
        abi::KCMP_SIGHAND => ptr_cmp(Arc::as_ptr(&t1.sigactions_arc()) as usize,
                                     Arc::as_ptr(&t2.sigactions_arc()) as usize),
        // Linux `task->io_context`, allocated lazily by the block layer's I/O
        // scheduler. oxide allocates none, so every task presents the same
        // NULL — exactly what Linux reports for two tasks that never entered
        // an io-context-allocating scheduler.
        abi::KCMP_IO => opt_cmp(None, None),
        // Linux `task->sysvsem.undo_list` — the handle itself, which is what
        // `CLONE_SYSVSEM` shares. Answering from the thread-group id instead
        // reported two threads of one process as sharing a list even when
        // neither had ever registered an adjustment, and reported a
        // `clone(CLONE_SYSVSEM)` child that genuinely shares one as different.
        abi::KCMP_SYSVSEM => ptr_cmp(t1.sysvsem_undo.load(Ordering::Acquire) as usize,
                                     t2.sysvsem_undo.load(Ordering::Acquire) as usize),
        abi::KCMP_EPOLL_TFD => epoll_tfd::compare(&t1, &t2, idx1, idx2),
        _ => errno(Errno::Einval),
    }
}

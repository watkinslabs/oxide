// 312 kcmp — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// kcmp(2): compare two tasks' resources by pointer identity.
///
/// Return encoding is Linux's ordered, NON-NEGATIVE triple (kernel
/// `kcmp_ptr` via `kptr_obfuscate`): 0 = same resource, 1 = idx1's
/// resource orders before idx2's, 2 = idx1 orders after idx2. A raw
/// syscall return in `[-4095,-1]` is read by musl/glibc as `-errno`,
/// so a valid ordering result MUST NOT be negative — the previous
/// `-1` for "less than" was seen by userspace as EPERM. systemd's
/// `same_fd()` does `r = kcmp(...); if (r >= 0) return !r;`, i.e. it
/// requires a non-negative result and only reaches its fstat fallback
/// on a (spurious) error. ESRCH for missing pids; EINVAL for unknown
/// type; EBADF when a KCMP_FILE fd is not allocated (Linux guarantee).
/// # C: O(1)
pub fn sys_kcmp(args: &SyscallArgs) -> i64 {
    let pid1 = args.a0 as u32;
    let pid2 = args.a1 as u32;
    let ty   = args.a2 as u32;
    let idx1 = args.a3 as u64;
    let idx2 = args.a4 as u64;
    if ty > 7 { return errno(Errno::Einval); }
    let t1 = match sched::live::registry::resolve_user_pid(pid1) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    let t2 = match sched::live::registry::resolve_user_pid(pid2) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    // KCMP_FILE = 0: compare File at fd idx1 in t1 vs fd idx2 in t2.
    match ty {
        0 => {
            // t1/t2 are arbitrary (possibly-foreign) tasks: clone_fd_table pins
            // each against a concurrent exit-time replace_fd_table(None).
            let f1 = t1.clone_fd_table().and_then(|t| t.get(idx1 as i32).ok());
            let f2 = t2.clone_fd_table().and_then(|t| t.get(idx2 as i32).ok());
            // Linux guarantees -EBADF if either fd is not allocated.
            match (f1, f2) {
                (Some(f1), Some(f2)) => ptr_cmp(
                    alloc::sync::Arc::as_ptr(&f1) as usize,
                    alloc::sync::Arc::as_ptr(&f2) as usize),
                _ => errno(Errno::Ebadf),
            }
        },
        // KCMP_FILES = 1: compare fd_table identity.
        1 => {
            // t1/t2 are arbitrary (possibly-foreign) tasks: clone_fd_table pins
            // each against a concurrent exit-time replace_fd_table(None).
            let p1 = t1.clone_fd_table().map(|t| alloc::sync::Arc::as_ptr(&t) as usize);
            let p2 = t2.clone_fd_table().map(|t| alloc::sync::Arc::as_ptr(&t) as usize);
            opt_cmp(p1, p2)
        },
        // KCMP_VM = 2: address-space identity.
        2 => {
            // t1/t2 are arbitrary (possibly-foreign) tasks: clone_mm pins
            // each against a concurrent exit/execve mm replacement.
            let p1 = t1.clone_mm().map(|m| alloc::sync::Arc::as_ptr(&m) as usize);
            let p2 = t2.clone_mm().map(|m| alloc::sync::Arc::as_ptr(&m) as usize);
            opt_cmp(p1, p2)
        },
        // KCMP_FS = 3: Linux fs_struct allocation identity.
        3 => ptr_cmp(alloc::sync::Arc::as_ptr(&t1.fs_context()) as usize,
                      alloc::sync::Arc::as_ptr(&t2.fs_context()) as usize),
        // KCMP_SIGHAND=4 / KCMP_IO=5 / KCMP_SYSVSEM=6 are task-local until
        // their corresponding shared Linux owners are implemented.
        _ => ptr_cmp(pid1 as usize, pid2 as usize),
    }
}

/// Linux kcmp ordering of two present resource ids: 0 equal, 1 less,
/// 2 greater. Never negative (see `sys_kcmp` return-encoding note).
/// # C: O(1)
fn ptr_cmp(a: usize, b: usize) -> i64 {
    if a == b { 0 } else if a < b { 1 } else { 2 }
}

/// Ordering when a resource id may be absent (task without the slot).
/// Absent sorts before present; both-absent is "equal". Non-negative.
/// # C: O(1)
fn opt_cmp(a: Option<usize>, b: Option<usize>) -> i64 {
    match (a, b) {
        (Some(x), Some(y)) => ptr_cmp(x, y),
        (None,    None)    => 0,
        (None,    Some(_)) => 1,
        (Some(_), None)    => 2,
    }
}

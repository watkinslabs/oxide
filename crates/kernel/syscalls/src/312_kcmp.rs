// 312 kcmp — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// kcmp(2): compare two tasks' resources by pointer identity.
/// Returns 0/1/-1 (equal/greater/less); ESRCH for missing pids;
/// EINVAL for unknown type.
/// # C: O(1)
pub fn sys_kcmp(args: &SyscallArgs) -> i64 {
    let pid1 = args.a0 as u32;
    let pid2 = args.a1 as u32;
    let ty   = args.a2 as u32;
    let idx1 = args.a3 as u64;
    let idx2 = args.a4 as u64;
    if ty > 7 { return errno(Errno::Einval); }
    let t1 = match sched::live::registry::lookup(pid1) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    let t2 = match sched::live::registry::lookup(pid2) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    // KCMP_FILE = 0: compare File at fd idx1 in t1 vs fd idx2 in t2.
    let cmp = match ty {
        0 => {
            // SAFETY: fd_table slot single-mutator per `13§5`; snapshot via Arc clone.
            unsafe {
                let f1 = (*t1.fd_table.get()).as_ref().and_then(|t| t.get(idx1 as i32).ok());
                let f2 = (*t2.fd_table.get()).as_ref().and_then(|t| t.get(idx2 as i32).ok());
                ptr_cmp(f1.map(|f| alloc::sync::Arc::as_ptr(&f) as usize),
                        f2.map(|f| alloc::sync::Arc::as_ptr(&f) as usize))
            }
        },
        // KCMP_FILES = 1: compare fd_table identity.
        1 => {
            // SAFETY: fd_table slot single-mutator per `13§5`; pointer identity is the resource id.
            unsafe {
                let p1 = (*t1.fd_table.get()).as_ref().map(|t| alloc::sync::Arc::as_ptr(t) as usize);
                let p2 = (*t2.fd_table.get()).as_ref().map(|t| alloc::sync::Arc::as_ptr(t) as usize);
                ptr_cmp(p1, p2)
            }
        },
        // KCMP_VM = 2: address-space identity.
        2 => {
            // SAFETY: mm slot single-mutator per `13§5`; pointer identity = AS resource id.
            unsafe {
                let p1 = t1.mm_ref().map(|m| alloc::sync::Arc::as_ptr(m) as usize);
                let p2 = t2.mm_ref().map(|m| alloc::sync::Arc::as_ptr(m) as usize);
                ptr_cmp(p1, p2)
            }
        },
        // KCMP_FS=3 / KCMP_SIGHAND=4 / KCMP_IO=5 / KCMP_SYSVSEM=6:
        // v1 ties these to the task identity since we don't yet
        // share these resources across CLONE_FS / CLONE_SIGHAND.
        _ => ptr_cmp(Some(pid1 as usize), Some(pid2 as usize)),
    };
    cmp as i64
}

/// # C: O(1)
fn ptr_cmp(a: Option<usize>, b: Option<usize>) -> i64 {
    match (a, b) {
        (Some(x), Some(y)) if x == y => 0,
        (Some(x), Some(y)) if x  < y => -1,
        (Some(_), Some(_))           => 1,
        (None,    None)              => 0,
        (None,    Some(_))           => -1,
        (Some(_), None)              => 1,
    }
}

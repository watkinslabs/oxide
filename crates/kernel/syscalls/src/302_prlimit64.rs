// 302 prlimit64 — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perm_common::prlimit_perm_check;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `sys_prlimit64(pid, resource, new, old)` — slot 302. Reads/
/// writes the per-task `rlimits` slot (cur,max). Enforcement is
/// partial — RLIMIT_NOFILE consulted at fd_table::alloc; other
/// resources stored but not yet checked.
///
/// Linux `do_prlimit`: a non-self target requires
/// `check_prlimit_permission` (matching creds or `CAP_SYS_RESOURCE`
/// in the target's user namespace — `prlimit_perm_check` below), and
/// raising the HARD limit beyond its current value always requires
/// `CAP_SYS_RESOURCE`, self included.
/// # C: O(1) self; O(N_tasks) for non-self lookup
pub fn sys_prlimit64(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pid      = args.a0 as u32;
    let resource = args.a1 as usize;
    let new_ptr  = args.a2;
    let old_ptr  = args.a3;
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let task = if pid == 0 {
        sched::live::registry::lookup(cur.tid)
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let task = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };

    if task.tid != cur.tid && !prlimit_perm_check(&cur, &task) {
        return -(Errno::Eperm.as_i32() as i64);
    }

    if old_ptr != 0 {
        if let Err(rv) = validate_user_buf_writable(old_ptr, 16, 1) { return rv; }
        let (rcur, rmax) = task.rlimit(resource);
        // SAFETY: old_ptr validated writable for the 16-byte rlimit result.
        unsafe {
            core::ptr::write_unaligned( old_ptr       as *mut u64, rcur);
            core::ptr::write_unaligned((old_ptr + 8)  as *mut u64, rmax);
        }
    }
    if new_ptr != 0 {
        if let Err(rv) = validate_user_buf(new_ptr, 16, 1) { return rv; }
        // SAFETY: new_ptr validated readable for the 16-byte rlimit input.
        let (nc, nm) = unsafe {
            let c = core::ptr::read_unaligned( new_ptr       as *const u64);
            let m = core::ptr::read_unaligned((new_ptr + 8)  as *const u64);
            (c, m)
        };
        let pair = match sched::rlimit::clamp_pair(nc, nm) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let (_, old_max) = task.rlimit(resource);
        if pair.1 > old_max && !cur.has_cap(sched::cap::SYS_RESOURCE) {
            return -(Errno::Eperm.as_i32() as i64);
        }
        // `task` may not be `current` (prlimit64 explicitly targets an
        // arbitrary pid); set_rlimit takes rlimits' own lock so this
        // cross-task write can't race a concurrent reader/writer on
        // another CPU.
        task.set_rlimit(resource, pair);
    }
    0
}

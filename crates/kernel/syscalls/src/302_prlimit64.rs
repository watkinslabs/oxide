// 302 prlimit64 — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_prlimit64(pid, resource, new, old)` — slot 302. Reads/
/// writes the per-task `rlimits` slot (cur,max). Enforcement is
/// partial — RLIMIT_NOFILE consulted at fd_table::alloc; other
/// resources stored but not yet checked.
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
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup(pid)
    };
    let task = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };

    if old_ptr != 0 && old_ptr < hal::USER_VA_END {
        // SAFETY: same single-mutator invariant as getrlimit.
        let (rcur, rmax) = unsafe { (*task.rlimits.get())[resource] };
        // SAFETY: old_ptr validated; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( old_ptr       as *mut u64, rcur);
            core::ptr::write_volatile((old_ptr + 8)  as *mut u64, rmax);
        }
    }
    if new_ptr != 0 && new_ptr < hal::USER_VA_END {
        // SAFETY: validated; CPL=0 reads through caller's AS.
        let (nc, nm) = unsafe {
            let c = core::ptr::read_volatile( new_ptr       as *const u64);
            let m = core::ptr::read_volatile((new_ptr + 8)  as *const u64);
            (c, m)
        };
        let pair = match sched::rlimit::clamp_pair(nc, nm) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        // SAFETY: rlimits write — task may not be `current` but the slot
        // is single-mutator in v1's UP scheduler model (no preemption mid-syscall).
        unsafe { (*task.rlimits.get())[resource] = pair; }
    }
    0
}

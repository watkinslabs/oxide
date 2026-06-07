// 097 getrlimit — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrlimit(res, rlim)` — slot 97. Reads the per-task
/// rlimit slot for `res` and writes `(cur, max)` to user `rlim`.
/// # C: O(1)
pub fn sys_getrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if rlim == 0 || rlim >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: rlimits slot single-mutator per `13§5`; current task is the running task on this CPU.
    let (rcur, rmax) = unsafe { (*cur.rlimits.get())[resource] };
    // SAFETY: rlim validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( rlim       as *mut u64, rcur);
        core::ptr::write_volatile((rlim + 8)  as *mut u64, rmax);
    }
    0
}

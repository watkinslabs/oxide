// 160 setrlimit — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setrlimit(res, rlim)` — slot 160. Reads `(cur, max)` from
/// user `rlim`, validates `cur <= max`, writes to per-task slot.
/// # C: O(1)
pub fn sys_setrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if rlim == 0 || rlim >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: rlim validated < USER_VA_END; CPL=0 reads through caller's AS.
    let (new_cur, new_max) = unsafe {
        let c = core::ptr::read_volatile( rlim       as *const u64);
        let m = core::ptr::read_volatile((rlim + 8)  as *const u64);
        (c, m)
    };
    let pair = match sched::rlimit::clamp_pair(new_cur, new_max) {
        Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: same single-mutator invariant as the getrlimit reader.
    unsafe { (*cur.rlimits.get())[resource] = pair; }
    0
}

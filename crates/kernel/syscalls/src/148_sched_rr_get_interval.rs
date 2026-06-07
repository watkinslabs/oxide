// 148 sched_rr_get_interval — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_sched_rr_get_interval(pid, tp)` — slot 148. Writes the SCHED_RR
/// timeslice (100 ms = 100_000_000 ns) into the user `struct timespec`.
/// Returns -ESRCH for unknown pid, -EFAULT on bad pointer.
/// # C: O(N_tasks)
pub fn sys_sched_rr_get_interval(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let tp  = args.a1;
    if tp == 0 || tp + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let t = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup(pid)
    };
    if t.is_none() { return -(Errno::Esrch.as_i32() as i64); }
    // SAFETY: tp+16 validated < USER_VA_END; struct timespec is { i64 sec; i64 nsec }; CPL=0.
    unsafe {
        core::ptr::write_volatile( tp        as *mut i64, 0);
        core::ptr::write_volatile((tp +  8)  as *mut i64, 100_000_000);
    }
    0
}

// 274 get_robust_list — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_get_robust_list(pid, head_out, len_out)` — slot 274. `pid==0`
/// means the calling thread; non-zero pids are looked up in the
/// scheduler registry. Writes the stored head+len through the two
/// user pointers.
/// # C: O(1) | O(N_tasks) when pid != 0 (registry walk)
pub fn sys_get_robust_list(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let pid      = args.a0 as u32;
    let head_out = args.a1;
    let len_out  = args.a2;
    if head_out == 0 || head_out >= hal::USER_VA_END
        || len_out == 0 || len_out >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let (head, len) = if pid == 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
        };
        (cur.robust_list_head.load(Ordering::Acquire),
         cur.robust_list_len.load(Ordering::Acquire))
    } else {
        let task = match sched::live::registry::lookup(pid) {
            Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
        };
        (task.robust_list_head.load(Ordering::Acquire),
         task.robust_list_len.load(Ordering::Acquire))
    };
    // SAFETY: head_out/len_out validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(head_out as *mut u64, head);
        core::ptr::write_volatile(len_out  as *mut u64, len);
    }
    0
}

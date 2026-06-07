// 124 getsid — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getsid(pid)` — slot 124. `pid==0` means the current task.
/// # C: O(N_tasks) for non-self lookup
pub fn sys_getsid(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as u32;
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup_by_vpid(pid)
    };
    match task {
        Some(t) => t.sid.load(Ordering::Acquire) as i64,
        None    => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}

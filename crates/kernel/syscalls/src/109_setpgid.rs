// 109 setpgid — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setpgid(pid, pgid)` — slot 109. Sets target task's pgid.
/// `pid==0` means current; `pgid==0` means use the target's tid.
/// Returns -ESRCH if the target task isn't live.
/// # C: O(N_tasks)
pub fn sys_setpgid(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid  = args.a0 as u32;
    let pgid = args.a1 as u32;
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup_by_vpid(pid)
    };
    let t = match task { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    let target_vpid = t.vtgid.load(Ordering::Acquire);
    let new_pgid = if pgid == 0 {
        if target_vpid != 0 { target_vpid } else { t.tid }
    } else {
        pgid
    };
    t.pgid.store(new_pgid, Ordering::Release);
    0
}

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
    let cur = match sched::live::current() {
        Some(cur) => cur,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let namespace = match cur.namespace_owner(namespace_identity::NamespaceKind::Pid) {
        Some(namespace) => namespace,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let task = if pid == 0 {
        sched::live::registry::lookup(cur.tid)
    } else {
        sched::registry::lookup_in_namespace(&namespace, pid)
    };
    let t = match task { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    let leader_tid = t.tgid.load(Ordering::Acquire);
    let target_vpid = match sched::live::registry::lookup(leader_tid)
        .and_then(|leader| leader.pid.visible_tid(&namespace))
    {
        Some(target_vpid) => target_vpid,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let new_pgid = if pgid == 0 {
        target_vpid
    } else {
        pgid
    };
    t.pgid.store(new_pgid, Ordering::Release);
    0
}

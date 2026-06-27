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
    let cur = sched::live::current();
    let task = if pid == 0 {
        cur.and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        // `pid` is a NAMESPACE pid (the visible vpid/vtid), not the opaque
        // internal tid. Resolve within the caller's pid namespace, matching
        // the visible pid (vtgid OR vtid) — `lookup_in_ns`. Then fall back to
        // the caller's own ids, so `setpgid(getpid(), …)` / the post-fork
        // `setpgid(child_vpid, …)` systemd issues resolve instead of ESRCH —
        // the same vpid-resolution the capget/capset path in cred.rs uses.
        let ns = cur.map(|c| c.pid_ns.load(Ordering::Acquire)).unwrap_or(0);
        sched::live::registry::lookup_in_ns(ns, pid)
            .or_else(|| sched::live::registry::lookup_by_vpid(pid))
            .or_else(|| sched::live::registry::lookup(pid))
            .or_else(|| cur
                .filter(|c| pid == c.tid
                    || pid == c.vtid.load(Ordering::Acquire)
                    || pid == c.vtgid.load(Ordering::Acquire))
                .and_then(|c| sched::live::registry::lookup(c.tid)))
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

// 062 kill — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;

/// `sys_kill(pid, sig)` — slot 62. pgrp-aware per `28§4`:
///   pid > 0 — signal that tid via the registry.
///   pid == 0 — fan to caller's pgrp.
///   pid == -1 — not implemented; -EPERM.
///   pid <  -1 — fan to pgrp `(-pid)`.
/// `sig == 0` is a permission probe.
/// # C: O(N_tasks) on pgrp fan; O(N_tasks) lookup for non-self pid
pub fn sys_kill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(0..=64).contains(&sig) { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let bit = if sig == 0 { 0 } else { 1u64 << (sig - 1) };
    if pid > 0 {
        if pid as u32 == cur.tid {
            if sig != 0 { cur.sigpending.fetch_or(bit, Ordering::Release); }
            return 0;
        }
        // F109: cross-NS pid translation. Caller in non-init pid_ns
        // means `pid` is a vpid in their NS, not a global tid.
        let cur_ns = cur.pid_ns.load(Ordering::Acquire);
        match sched::live::registry::lookup_in_ns(cur_ns, pid as u32) {
            Some(t) => {
                if !sig_perm_check(cur, &t, sig) {
                    return -(syscall::errno::Errno::Eperm.as_i32() as i64);
                }
                if sig != 0 {
                    t.sigpending.fetch_or(bit, Ordering::Release);
                    if sig == 18 { sched::live::registry::wake_if_stopped(&t); }
                    // F168: a signal raised on a Sleeping task must
                    // wake it so the parked helper can observe the
                    // bit and return -EINTR (Linux semantic). No-op
                    // for any other task state.
                    sched::live::wake_if_sleeping(&t);
                }
                0
            }
            None => -(syscall::errno::Errno::Esrch.as_i32() as i64),
        }
    } else if pid == 0 {
        let pgid = cur.pgid.load(Ordering::Acquire);
        let n = post_pgrp(pgid, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    } else if pid == -1 {
        -(syscall::errno::Errno::Eperm.as_i32() as i64)
    } else {
        let n = post_pgrp((-pid) as u32, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    }
}

fn post_pgrp(pgid: u32, bit: u64, sig: i32) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = sched::live::registry::tasks_in_pgrp(pgid);
    let mut n = 0usize;
    let cur = sched::live::current();
    for t in &tasks {
        let allowed = match cur {
            Some(c) => sig_perm_check(c, t, sig),
            None    => true,
        };
        if !allowed { continue; }
        if sig != 0 {
            t.sigpending.fetch_or(bit, Ordering::Release);
            if sig == 18 { sched::live::registry::wake_if_stopped(t); }
            // Mirror sys_kill: a signal posted to a pgrp member that is
            // parked (Sleeping) must wake it so its blocking helper
            // observes the bit and returns -EINTR. Without this,
            // kill(pgid=0, sig) cannot interrupt a parked group member.
            sched::live::wake_if_sleeping(t);
        }
        n += 1;
    }
    n
}

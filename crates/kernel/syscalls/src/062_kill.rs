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
    use sched::Signum;
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(0..=64).contains(&sig) { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let namespace = match cur.namespace_owner(namespace_identity::NamespaceKind::Pid) {
        Some(namespace) => namespace,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let bit = if sig == 0 { 0 } else { 1u64 << (sig - 1) };
    if pid > 0 {
        // Self fast-path: a task signalling its own VPID (the value getpid()/
        // gettid() report) posts to itself. (Was `== cur.tid`, the internal
        // tid — which userspace never passes, so it silently never matched.)
        let p = pid as u32;
        if p == cur.vtgid.load(Ordering::Acquire) || p == cur.vtid.load(Ordering::Acquire) {
            if sig != 0 { cur.sigpending.fetch_or(bit, Ordering::Release); }
            return 0;
        }
        // F109: cross-NS pid translation. Caller in non-init pid_ns
        // means `pid` is a vpid in their NS, not a global tid.
        match sched::registry::lookup_in_namespace(&namespace, pid as u32) {
            Some(t) => {
                if !sig_perm_check(cur, &t, sig) {
                    return -(syscall::errno::Errno::Eperm.as_i32() as i64);
                }
                if sig != 0 {
                    t.sigpending.fetch_or(bit, Ordering::Release);
                    if sig == Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(&t); }
                    sched::live::signal_wake_up(&t);
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
        // Broadcast: signal every process the caller may signal, EXCEPT itself
        // and init (pid 1) — Linux `kill(-1)`. Used by `killall5` and systemd's
        // final SIGTERM/SIGKILL sweep at shutdown/reboot. Returns 0 if it
        // signalled at least one, else ESRCH.
        let n = post_broadcast(cur, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    } else {
        let n = post_pgrp((-pid) as u32, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    }
}

/// `kill(-1)` fan-out: post `sig` to every real user process the caller may
/// signal, excluding itself, init (vtgid 1), and kernel threads (vtgid 0).
/// Mirrors `post_pgrp`'s permission + wake handling over the whole task set.
fn post_broadcast(cur: &sched::Task, bit: u64, sig: i32) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return 0 };
    let mut n = 0usize;
    for t in &tasks {
        if t.reaped.load(Ordering::Acquire) { continue; }
        let vtgid = t.vtgid.load(Ordering::Acquire);
        if vtgid == 0 || vtgid == 1 { continue; } // skip kthreads + init(pid 1)
        if t.tid == cur.tid { continue; }          // skip self
        if !sig_perm_check(cur, t, sig) { continue; }
        if sig != 0 {
            t.sigpending.fetch_or(bit, Ordering::Release);
            if sig == sched::Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(t); }
            sched::live::signal_wake_up(t);
        }
        n += 1;
    }
    n
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
            if sig == sched::Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(t); }
            sched::live::signal_wake_up(t);
        }
        n += 1;
    }
    n
}

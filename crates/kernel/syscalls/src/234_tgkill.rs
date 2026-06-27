// 234 tgkill — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;

/// `sys_tgkill(tgid, tid, sig)` — slot 234. Validates that the
/// target tid belongs to the named tgid before delivering.
/// # C: O(N_tasks) lookup
pub fn sys_tgkill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    if tgid <= 0 || tid <= 0 { return -(Errno::Esrch.as_i32() as i64); }
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let want_tgid = tgid as u32;
    let want_tid = tid as u32;
    if (want_tgid == cur.vtgid.load(Ordering::Acquire)
            || want_tgid == cur.tgid.load(Ordering::Acquire))
        && (want_tid == cur.vtid.load(Ordering::Acquire) || want_tid == cur.tid)
    {
        if sig != 0 {
            cur.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
        }
        return 0;
    }
    let cur_ns = cur.pid_ns.load(Ordering::Acquire);
    // F109: in non-init pid_ns, `tid` is a vtid in caller's NS.
    match sched::live::registry::lookup_in_ns(cur_ns, want_tid) {
        Some(t) => {
            // Validate the tgid matches what userspace sees. Boot PID1 lives
            // in init ns but is stamped vtgid/vtid=1; compare that visible id
            // before falling back to the opaque internal scheduler tgid.
            let visible_tgid = t.vtgid.load(Ordering::Acquire);
            let got_tgid = if visible_tgid != 0 {
                visible_tgid
            } else {
                t.tgid.load(Ordering::Acquire)
            };
            if got_tgid != want_tgid {
                return -(Errno::Esrch.as_i32() as i64);
            }
            if !sig_perm_check(cur, &t, sig) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if sig != 0 {
                t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                if sig == 18 { sched::live::registry::wake_if_stopped(&t); }
                sched::live::wake_if_sleeping(&t);
            }
            0
        }
        None => -(Errno::Esrch.as_i32() as i64),
    }
}

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
    let cur_ns = cur.pid_ns.load(Ordering::Acquire);
    // F109: in non-init pid_ns, `tid` is a vtid in caller's NS.
    match sched::live::registry::lookup_in_ns(cur_ns, tid as u32) {
        Some(t) => {
            // Validate the tgid matches as well (vtgid in NS, real otherwise).
            let want_tgid = tgid as u32;
            let got_tgid = if cur_ns == 0 { t.tgid.load(Ordering::Acquire) }
                           else { t.vtgid.load(Ordering::Acquire) };
            if got_tgid != want_tgid {
                return -(Errno::Esrch.as_i32() as i64);
            }
            if !sig_perm_check(cur, &t, sig) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if sig != 0 {
                t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                if sig == 18 { sched::live::registry::wake_if_stopped(&t); }
            }
            0
        }
        None => -(Errno::Esrch.as_i32() as i64),
    }
}

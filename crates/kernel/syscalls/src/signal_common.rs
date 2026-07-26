// signal_common — shared helpers for the signal syscall family
// (docs/53 §0). Moved verbatim from signal.rs.

#![cfg(target_os = "oxide-kernel")]

// `sig_perm_check` lives in the hosted-testable `perm_common` module
// (shared with `prlimit_perm_check`); re-exported here so the existing
// `use crate::signal_common::*;` call sites (`062_kill.rs`) keep resolving.
pub(crate) use crate::perm_common::sig_perm_check;

/// Internal helper: decode the user `siginfo_t` (first 32 bytes
/// — signo/errno/code/pid/uid/value), enqueue on the target's RT
/// queue, set the pending bit. Wakes if stopped.
///
/// Linux `do_rt_sigqueueinfo`: applies the same permission rule as
/// `kill(2)` (`check_kill_permission` — `sig_perm_check` here), and
/// additionally forbids forging a kernel/tkill-origin `si_code`
/// (`signum::is_forged_si_code`) at any target other than self.
/// # C: O(1)
pub(crate) fn rt_sigqueue_to(tid: u32, sig: u32, info_ptr: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // `tid` is a USERSPACE pid/tid (rt_sigqueueinfo / rt_tgsigqueueinfo) —
    // resolve it as a vpid, not the internal tid.
    let target = match sched::live::registry::resolve_user_pid(tid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf(info_ptr, 32, 1) { return rv; }
    // SAFETY: info_ptr validated readable for the siginfo_t leading fields used here.
    let info = unsafe {
        let signo_u = core::ptr::read_unaligned(info_ptr as *const i32) as u32;
        let _errno = core::ptr::read_unaligned((info_ptr + 4) as *const i32);
        let code   = core::ptr::read_unaligned((info_ptr + 8) as *const i32);
        let pid    = core::ptr::read_unaligned((info_ptr + 16) as *const u32);
        let uid    = core::ptr::read_unaligned((info_ptr + 20) as *const u32);
        let value  = core::ptr::read_unaligned((info_ptr + 24) as *const u64);
        sched::SigInfo { signo: signo_u, code, pid, uid, value }
    };
    if !sig_perm_check(&cur, &target, sig as i32) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if cur.tid != target.tid && sched::signum::is_forged_si_code(info.code) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    target.rt_push(info);
    target.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
    sched::live::registry::wake_if_stopped(&target);
    sched::live::signal_wake_up(&target);
    0
}

// Shared `do_tkill` for slots 200 (tkill) and 234 (tgkill) — Linux
// `kernel/signal.c` `do_tkill` → `do_send_specific`. One owner for the
// thread-directed signal path so `tkill` cannot drift from `tgkill`.
//
// Module manifest:
// - `arg_check`: the pid/tgid admission rules, hosted-tested (non-gated).
// - `do_tkill`: the live registry lookup + SI_TKILL queue + wake.

#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::errno::Errno;

/// Linux `valid_signal()` bound: `sig` in `0..=_NSIG`, where `0` is the
/// existence/permission probe that sends nothing.
pub const NSIG: i32 = 64;

/// Outcome of `tkill`/`tgkill` argument admission, before any task lookup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgCheck {
    /// Proceed to the registry lookup.
    Ok,
    /// Linux `SYSCALL_DEFINE2(tkill)` / `SYSCALL_DEFINE3(tgkill)`:
    /// `if (pid <= 0 || tgid <= 0) return -EINVAL;`
    Einval,
}

/// `tgid <= 0` is passed as `None` only by `tkill`, which supplies no tgid at
/// all (Linux calls `do_tkill(0, pid, sig)`), so it is not an EINVAL there.
///
/// Signal validity is deliberately NOT checked here: Linux validates `sig`
/// inside `check_kill_permission`, which runs only AFTER `find_task_by_vpid`
/// succeeded. An unknown tid therefore reports ESRCH even with a bogus signal.
/// # C: O(1)
pub const fn arg_check(tgid: Option<i32>, tid: i32) -> ArgCheck {
    if tid <= 0 { return ArgCheck::Einval; }
    if let Some(t) = tgid { if t <= 0 { return ArgCheck::Einval; } }
    ArgCheck::Ok
}

/// Linux `check_kill_permission`'s `valid_signal(sig)` gate, applied after the
/// target task resolved.
/// # C: O(1)
pub const fn signal_valid(sig: i32) -> bool { sig >= 0 && sig <= NSIG }

/// Encoded EINVAL / ESRCH / EPERM returns for the slots.
/// # C: O(1)
pub const fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
/// # C: O(1)
pub const fn esrch() -> i64 { -(Errno::Esrch.as_i32() as i64) }
/// # C: O(1)
pub const fn eperm() -> i64 { -(Errno::Eperm.as_i32() as i64) }

#[cfg(target_os = "oxide-kernel")]
pub use live::do_tkill;

#[cfg(target_os = "oxide-kernel")]
mod live {
    use super::*;
    use core::sync::atomic::Ordering;
    use crate::perm_common::sig_perm_check;

    /// Linux `do_tkill(tgid, pid, sig)` → `do_send_specific`: resolve `tid` in
    /// the CALLER's pid namespace, reject it when `tgid` is supplied and the
    /// thread does not belong to that thread group (this is the entire reason
    /// `tgkill` exists — it closes the tid-reuse race), run
    /// `check_kill_permission`, then queue an `SI_TKILL` siginfo stamped with
    /// the SENDER's pid/uid.
    ///
    /// `tgid == None` is `tkill(2)`, Linux's `do_tkill(0, pid, sig)`: the
    /// `tgid <= 0` arm of `do_send_specific` skips the thread-group check.
    /// # C: O(N_tasks) registry lookup
    pub fn do_tkill(tgid: Option<u32>, tid: u32, sig: i32) -> i64 {
        let Some(cur) = sched::live::current() else { return esrch(); };
        let Some(namespace) = cur.namespace_owner(namespace_identity::NamespaceKind::Pid)
            else { return esrch(); };
        // Linux resolves `pid` with `find_task_by_vpid` — the caller's pid
        // namespace, never a global tid.
        let Some(t) = sched::registry::lookup_in_namespace(&namespace, tid) else { return esrch(); };
        if let Some(want_tgid) = tgid {
            if !in_thread_group(&t, &namespace, want_tgid) { return esrch(); }
        }
        // `check_kill_permission`: EINVAL for a bad signal, then the
        // credential/session rules. Ordered AFTER the lookup, exactly as
        // `do_send_specific` calls it.
        if !signal_valid(sig) { return einval(); }
        if !sig_perm_check(cur, &t, sig) { return eperm(); }
        // "The null signal is a permissions and process existence probe. No
        // signal is actually delivered."
        if sig == 0 { return 0; }
        queue_si_tkill(cur, &t, sig);
        0
    }

    /// Linux `task_tgid_vnr(p) == tgid`: the resolved thread's group leader,
    /// as numbered in the CALLER's pid namespace.
    /// # C: O(N_tasks) leader lookup
    fn in_thread_group(t: &sched::Task, namespace: &namespace_identity::NamespaceRef, want_tgid: u32) -> bool {
        let leader_tid = t.tgid.load(Ordering::Acquire);
        sched::live::registry::lookup(leader_tid).is_some_and(|leader| {
            leader.pid.visible_tid(namespace) == Some(want_tgid)
                && alloc::sync::Arc::ptr_eq(&leader.thread_group, &t.thread_group)
        })
    }

    /// Linux `prepare_kill_siginfo(sig, &info, PIDTYPE_PID)` + the
    /// `do_send_sig_info(..., PIDTYPE_PID)` delivery: si_code = SI_TKILL,
    /// si_pid = `task_tgid_vnr(current)`, si_uid = `current_uid()` — the
    /// sender's REAL uid, not the effective one (`include/linux/cred.h`
    /// `current_uid()` is `current_cred()->uid`).
    ///
    /// EVERY signal gets a record, not just the realtime range: glibc's
    /// `__nptl_setxid_sighandler` (SIGSETXID) and SIGCANCEL both validate
    /// `si_pid`/`si_code` before acting, and a zeroed siginfo makes them
    /// silently no-op.
    /// # C: O(1)
    fn queue_si_tkill(cur: &sched::Task, t: &alloc::sync::Arc<sched::Task>, sig: i32) {
        let spid = cur.vtgid.load(Ordering::Acquire);
        let spid = if spid != 0 { spid } else { cur.tgid.load(Ordering::Acquire) };
        t.sigq_reserve(sig as u32);
        t.sigq_push(sched::SigInfo {
            signo: sig as u32,
            code: sched::signum::SI_TKILL,
            pid: spid,
            uid: cur.creds.ruid.load(Ordering::Relaxed),
            value: 0,
        });
        t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
        if sig == sched::Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(t); }
        sched::live::signal_wake_up(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tkill_rejects_non_positive_tid_with_einval() {
        // Linux: `if (pid <= 0) return -EINVAL;` — NOT ESRCH, and no pgrp or
        // broadcast meaning for 0 / -1 the way kill(2) has.
        assert_eq!(arg_check(None, 0), ArgCheck::Einval);
        assert_eq!(arg_check(None, -1), ArgCheck::Einval);
        assert_eq!(arg_check(None, i32::MIN), ArgCheck::Einval);
        assert_eq!(arg_check(None, 1), ArgCheck::Ok);
        assert_eq!(arg_check(None, i32::MAX), ArgCheck::Ok);
    }

    #[test]
    fn tgkill_rejects_non_positive_tgid_with_einval() {
        assert_eq!(arg_check(Some(0), 5), ArgCheck::Einval);
        assert_eq!(arg_check(Some(-2), 5), ArgCheck::Einval);
        assert_eq!(arg_check(Some(5), 0), ArgCheck::Einval);
        assert_eq!(arg_check(Some(5), -5), ArgCheck::Einval);
        assert_eq!(arg_check(Some(1), 1), ArgCheck::Ok);
    }

    #[test]
    fn tkill_has_no_tgid_so_zero_tgid_is_not_reachable() {
        // Linux calls `do_tkill(0, pid, sig)`; the `tgid <= 0` arm of
        // do_send_specific means "skip the thread-group check", it is not an
        // error. Modelled as `None`, so it never trips the EINVAL rule.
        assert_eq!(arg_check(None, 7), ArgCheck::Ok);
    }

    #[test]
    fn signal_range_matches_valid_signal() {
        assert!(signal_valid(0));   // existence probe
        assert!(signal_valid(1));
        assert!(signal_valid(64));  // SIGRTMAX
        assert!(!signal_valid(65));
        assert!(!signal_valid(-1));
    }

    #[test]
    fn errno_encodings_are_the_typed_constants() {
        assert_eq!(einval(), -(Errno::Einval.as_i32() as i64));
        assert_eq!(esrch(), -(Errno::Esrch.as_i32() as i64));
        assert_eq!(eperm(), -(Errno::Eperm.as_i32() as i64));
    }
}

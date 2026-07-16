// signal_common — shared helpers for the signal syscall family
// (docs/53 §0). Moved verbatim from signal.rs.

#![cfg(target_os = "oxide-kernel")]

/// Linux signal-permission check per `kill(2)`: sender may signal
/// receiver if sender holds CAP_KILL OR sender's real/effective uid
/// matches receiver's real or saved-set uid. SIGCONT is additionally
/// allowed within the same session (so `kill -CONT 0` from a parent
/// shell works even after setuid drops).
/// # C: O(1)
pub(crate) fn sig_perm_check(cur: &sched::Task, target: &sched::Task, sig: i32) -> bool {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    if cur.tid == target.tid { return true; }
    // F118: CAP_KILL must be held in a NS that's an ancestor of (or
    // equal to) the target's user_ns. Init-NS callers pass through.
    if target.namespace_owner(namespace_identity::NamespaceKind::User).as_ref()
        .is_some_and(|owner| nscg::proc_ns::has_cap_for(cur, &owner.pin(), sched::cap::KILL))
    {
        return true;
    }
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let tr = target.creds.ruid.load(Ordering::Acquire);
    let ts = target.creds.suid.load(Ordering::Acquire);
    if ce == tr || ce == ts || cr == tr || cr == ts { return true; }
    // SIGCONT (18) — same session bypass.
    if sig == Signum::Sigcont as i32 && cur.sid.load(Ordering::Acquire) == target.sid.load(Ordering::Acquire) {
        return true;
    }
    false
}

/// Internal helper: decode the user `siginfo_t` (first 32 bytes
/// — signo/errno/code/pid/uid/value), enqueue on the target's RT
/// queue, set the pending bit. Wakes if stopped.
/// # C: O(1)
pub(crate) fn rt_sigqueue_to(tid: u32, sig: u32, info_ptr: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
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
    target.rt_push(info);
    target.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
    sched::live::registry::wake_if_stopped(&target);
    // A queued RT signal to a task PARKED in epoll_wait/ppoll (Sleeping) must
    // wake it, exactly like sys_kill / sys_tgkill / sys_pidfd_send_signal — else
    // it only observes the signal on the next timer re-scan. `journalctl --flush`
    // rt_sigqueue's SIGRTMIN+1 to journald (parked on its sd-event signalfd);
    // without this wake journald never runs the flush → systemd-journal-flush
    // hangs its full 90s timeout and the boot never reaches graphical.target.
    sched::live::wake_if_sleeping(&target);
    0
}

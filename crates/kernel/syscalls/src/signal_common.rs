// signal_common — shared helpers for the signal syscall family
// (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

// `sig_perm_check` lives in the hosted-testable `perm_common` module
// (shared with `prlimit_perm_check`); re-exported here so the existing
// `use crate::signal_common::*;` call sites (`062_kill.rs`) keep resolving.
pub(crate) use crate::perm_common::sig_perm_check;

// `sizeof(sigset_t)` and the `sigsetsize` argument rules are owned by the ABI
// crate (`syscall::sigset`) so every signal slot enforces the same one.
pub(crate) use syscall::sigset::SIGSET_BYTES;

/// `sizeof(struct kernel_siginfo)` — the prefix of the 128-byte user
/// `siginfo_t` that Linux's `__copy_siginfo_from_user` actually copies in.
pub(crate) const KERNEL_SIGINFO_BYTES: u64 = 48;

/// Full user-visible `siginfo_t` size (`_SI_MAX_SIZE`), what
/// `copy_siginfo_to_user` writes out.
pub(crate) const SIGINFO_BYTES: u64 = 128;

/// siginfo_t field offsets shared by every signal syscall that reads or writes
/// one (`asm-generic/siginfo.h`). `SI_VALUE` is the `_rt` union arm's
/// `sigval_t`, a full 8 bytes — the `_sigchld` arm's `si_status` aliases its
/// low half.
pub(crate) const SI_SIGNO: u64 = 0;
pub(crate) const SI_ERRNO: u64 = 4;
pub(crate) const SI_CODE:  u64 = 8;
pub(crate) const SI_PID:   u64 = 16;
pub(crate) const SI_UID:   u64 = 20;
pub(crate) const SI_VALUE: u64 = 24;

/// Decode the leading `kernel_siginfo` fields of a user `siginfo_t`.
/// Caller must have validated `info_ptr` readable for `KERNEL_SIGINFO_BYTES`.
/// # C: O(1)
pub(crate) fn read_user_siginfo(info_ptr: u64, signo: u32) -> sched::SigInfo {
    // SAFETY: caller validated info_ptr readable for KERNEL_SIGINFO_BYTES, which
    // covers every offset read here (highest is SI_VALUE + 8 = 32).
    unsafe {
        let code  = core::ptr::read_unaligned((info_ptr + SI_CODE)  as *const i32);
        let pid   = core::ptr::read_unaligned((info_ptr + SI_PID)   as *const u32);
        let uid   = core::ptr::read_unaligned((info_ptr + SI_UID)   as *const u32);
        let value = core::ptr::read_unaligned((info_ptr + SI_VALUE) as *const u64);
        // Linux `__copy_siginfo_from_user` overwrites si_signo with the
        // syscall's `sig` argument — the sender cannot make the two disagree.
        sched::SigInfo { signo, code, pid, uid, value }
    }
}

/// Write a dequeued signal into a user `siginfo_t` (Linux
/// `copy_siginfo_to_user`): zero all 128 bytes, then fill si_signo, si_errno,
/// si_code and the `_rt` arm. Caller must have validated `info_ptr` writable
/// for `SIGINFO_BYTES`.
/// # C: O(1)
pub(crate) fn write_user_siginfo(info_ptr: u64, sig: u32, rec: Option<sched::SigInfo>) {
    // Linux `collect_signal`'s fallback for a pending signal with no queued
    // record (`kill(2)` queues nothing): si_code = SI_USER, si_pid/si_uid = 0.
    let rec = rec.unwrap_or(sched::SigInfo {
        signo: sig, code: sched::signum::SI_USER, pid: 0, uid: 0, value: 0,
    });
    // SAFETY: caller validated info_ptr writable for SIGINFO_BYTES, which covers
    // the zero-fill and every field offset written below.
    unsafe {
        core::ptr::write_bytes(info_ptr as *mut u8, 0, SIGINFO_BYTES as usize);
        core::ptr::write_unaligned((info_ptr + SI_SIGNO) as *mut i32, sig as i32);
        core::ptr::write_unaligned((info_ptr + SI_ERRNO) as *mut i32, 0);
        core::ptr::write_unaligned((info_ptr + SI_CODE)  as *mut i32, rec.code);
        core::ptr::write_unaligned((info_ptr + SI_PID)   as *mut u32, rec.pid);
        core::ptr::write_unaligned((info_ptr + SI_UID)   as *mut u32, rec.uid);
        core::ptr::write_unaligned((info_ptr + SI_VALUE) as *mut u64, rec.value);
    }
}

/// Linux `do_rt_sigqueueinfo` / `do_rt_tgsigqueueinfo` tail: queue an
/// already-decoded `info` on the task `vpid` resolves to and wake it.
///
/// Error order is Linux's `kill_proc_info` → `kill_pid_info` →
/// `group_send_sig_info`: EINVAL for an out-of-range signal, then ESRCH for an
/// unknown pid, then EPERM from `check_kill_permission`. The si_code forgery
/// guard belongs to the CALLER and runs before all of these — Linux checks it
/// in `do_rt_sigqueueinfo` against the pid ARGUMENT, not the resolved task.
/// # C: O(1) after the registry lookup
pub(crate) fn sigqueue_to(vpid: u32, sig: u32, info: sched::SigInfo) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    if sig > sched::signum::RT_SIGNAL_MAX { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let target = match sched::live::registry::resolve_user_pid(vpid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !sig_perm_check(&cur, &target, sig as i32) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // `sig == 0` is the permission probe: every check above ran, nothing is sent.
    let Some(bit) = sched::signum::bit_for(sig) else { return 0 };
    target.sigq_reserve(sig);
    target.sigq_push(info);
    target.sigpending.fetch_or(bit, Ordering::Release);
    sched::live::registry::wake_if_stopped(&target);
    sched::live::signal_wake_up(&target);
    0
}

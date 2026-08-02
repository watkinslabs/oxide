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

/// `si_signo`'s offset, the one field a caller reads on its own (the signal
/// number a record claims, before the syscall's argument overrides it). Every
/// other offset belongs to `hal::siginfo`, the one owner of the union arms —
/// a second table here is what let a `_sigfault` record copy in as a `_kill`
/// one.
pub(crate) const SI_SIGNO: u64 = 0;

/// Decode a user `siginfo_t` (Linux `copy_siginfo_from_user`).
///
/// Linux copies the union verbatim, so the arm survives the copy untouched;
/// our record is decomposed, so the arm is recovered from `(signo, si_code)`
/// by the same classifier the write side and `signalfd` use.
///
/// Caller must have validated `info_ptr` readable for `KERNEL_SIGINFO_BYTES`.
/// # C: O(1)
pub(crate) fn read_user_siginfo(info_ptr: u64, signo: u32) -> sched::SigInfo {
    let mut buf = [0u8; SIGINFO_BYTES as usize];
    // SAFETY: caller validated info_ptr readable for KERNEL_SIGINFO_BYTES; only that prefix is copied and the 128-byte destination is a local array, so the tail stays zero exactly as Linux's `kernel_siginfo` copy-in leaves it.
    unsafe {
        core::ptr::copy_nonoverlapping(info_ptr as *const u8, buf.as_mut_ptr(),
                                       KERNEL_SIGINFO_BYTES as usize);
    }
    // Linux `__copy_siginfo_from_user` overwrites si_signo with the syscall's
    // `sig` argument — the sender cannot make the two disagree.
    sched::SigInfo::from_payload(signo, hal::read_siginfo(&buf, signo))
}

/// Write a dequeued signal into a user `siginfo_t` (Linux
/// `copy_siginfo_to_user`).
///
/// Renders through `hal::write_siginfo` — the SAME writer the per-arch signal
/// frame builders use — so the union arm a handler reads and the one
/// `rt_sigtimedwait`/`waitid` copies out can never disagree. A second offset
/// table here is exactly the split source of truth that let a `_sigfault`
/// record copy out as a `_kill` one.
///
/// Caller must have validated `info_ptr` writable for `SIGINFO_BYTES`.
/// # C: O(1)
pub(crate) fn write_user_siginfo(info_ptr: u64, sig: u32, rec: Option<sched::SigInfo>) {
    // Linux `collect_signal`'s fallback for a pending signal with no queued
    // record (`kill(2)` from a context that queues nothing): si_code = SI_USER,
    // si_pid/si_uid = 0.
    let rec = rec.unwrap_or(sched::SigInfo {
        signo: sig, code: sched::signum::SI_USER, pid: 0, uid: 0, value: 0,
        sys: None, fault: None, poll: None,
    });
    let mut buf = [0u8; SIGINFO_BYTES as usize];
    hal::write_siginfo(&mut buf, sig, Some(rec.payload(sig)));
    // SAFETY: caller validated info_ptr writable for SIGINFO_BYTES, which is exactly this buffer's length.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), info_ptr as *mut u8, buf.len()); }
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
    if sig == 0 { return 0; }
    // Linux `do_send_sig_info(sig, info, p, PIDTYPE_TGID)`: `sigqueue(3)` is
    // PROCESS-directed, so any thread of the target that has not blocked the
    // signal can take it. The open-coded private-set push this replaced meant a
    // `sigqueue()` aimed at a process whose main thread blocked the signal was
    // never seen by the worker that unblocked it.
    match sched::live::send_signal(&target, sig, sched::sigsend::SigSource::Info(info),
                                   sched::sigsend::SigTarget::Process) {
        Ok(()) => 0,
        // `__send_signal_locked`'s queue-overflow arm: a real-time signal from
        // a user queueing mechanism reports EAGAIN rather than losing its
        // record. POSIX requires it — `sigqueue(3)` documents EAGAIN.
        Err(sched::live::SendErr::Again) => -(Errno::Eagain.as_i32() as i64),
    }
}

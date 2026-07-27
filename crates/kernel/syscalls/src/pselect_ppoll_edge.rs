// User-memory edge shared by pselect6 (270) and ppoll (271): Linux
// `fs/select.c::poll_select_set_timeout` / `poll_select_finish` and
// `kernel/signal.c::set_user_sigmask`. The pure rules these apply live in
// `crate::pselect_ppoll`; this file owns only the user reads/writes and the
// task-state effects, in ONE place so the two slots cannot drift.
#![cfg(any(target_os = "oxide-kernel", test))]

use core::sync::atomic::Ordering;

use crate::poll::poll_common::monotonic_ns;
use crate::pselect_ppoll::{TIMESPEC_BYTES, TIMESPEC_NSEC_OFF, TimeoutWriteback, finish_return,
                           remaining_timespec, restores_saved_sigmask, timeout_writeback_plan,
                           user_sigmask_wanted};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// Linux `get_timespec64` + `poll_select_set_timeout`. A NULL `tsp` waits
/// indefinitely (`to = NULL`); otherwise the pair is read (EFAULT), validated
/// (`timespec64_valid` → EINVAL for `tv_sec < 0` or `tv_nsec` outside
/// `[0, NSEC_PER_SEC)`) and turned into the absolute monotonic `end_time`.
/// Both checks run BEFORE any mask is installed and before the wait, exactly
/// as `do_pselect`/`ppoll` order them. Returns the caller's `(tv_sec,
/// tv_nsec)` alongside the deadline because `poll_select_finish` needs the
/// requested pair to apply the "no update for zero timeout" rule.
/// # C: O(1)
pub(crate) fn poll_select_set_timeout(tsp: u64) -> Result<(i64, i64, Option<u64>), i64> {
    if tsp == 0 { return Ok((0, 0, None)); }
    validate_user_buf(tsp, TIMESPEC_BYTES, 1)?;
    // SAFETY: tsp validated readable for the whole 16-byte user timespec.
    let (sec, nsec) = unsafe {
        (core::ptr::read_unaligned(tsp as *const i64),
         core::ptr::read_unaligned((tsp + TIMESPEC_NSEC_OFF) as *const i64))
    };
    // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
    // KTIME_MAX_NS instead of an unbounded relative timeout.
    let total_ns = match syscall::time::timespec_to_ns(sec, nsec) {
        Ok(ns) => ns,
        Err(e) => return Err(-(e.as_i32() as i64)),
    };
    Ok((sec, nsec, Some(monotonic_ns().saturating_add(total_ns))))
}

/// Linux `set_user_sigmask`: NULL sigset pointer leaves the mask alone;
/// otherwise `sigsetsize != sizeof(sigset_t)` is EINVAL, the mask is copied
/// in (EFAULT), and it is installed with `TIF_RESTORE_SIGMASK` armed —
/// `Task::arm_saved_sigmask` (`saved_sigmask = blocked; set_current_blocked(new);
/// set_restore_sigmask()`), which also drops the never-blockable
/// SIGKILL/SIGSTOP bits. "Install, wait, put it back" without the armed flag
/// would let a handler run under the caller's ORIGINAL mask, which is the
/// exact race these two syscalls exist to close.
/// # C: O(1)
pub(crate) fn set_user_sigmask(cur: Option<&sched::Task>, ss_ptr: u64, ss_len: u64)
    -> Result<(), i64>
{
    match user_sigmask_wanted(ss_ptr, ss_len) {
        Ok(false) => return Ok(()),
        Ok(true)  => {}
        Err(e)    => return Err(-(e.as_i32() as i64)),
    }
    validate_user_buf(ss_ptr, syscall::sigset::SIGSET_BYTES, 1)?;
    // SAFETY: ss_ptr validated readable for the 8-byte user sigset_t.
    let new = unsafe { core::ptr::read_unaligned(ss_ptr as *const u64) };
    if let Some(c) = cur { c.arm_saved_sigmask(new); }
    Ok(())
}

/// Linux `poll_select_finish(end_time, tsp, PT_TIMESPEC, ret)`:
///   1. `restore_saved_sigmask_unless(ret == -ERESTARTNOHAND)` — an
///      interrupted wait KEEPS the temporary mask so the handler runs under
///      it and `rt_sigreturn` drops back to the caller's original mask.
///   2. write the REMAINING time back to `tsp` unless `tsp` is NULL, the
///      persona carries `STICKY_TIMEOUTS`, or the request was a zero timeout.
///      The raw syscalls do update the caller's timespec; only the glibc
///      wrappers hide it behind a local copy.
///   3. a writeback fault never becomes EFAULT — Linux refuses to turn a
///      completed wait into an error because the caller put its timespec in
///      read-only memory. It does, however, fold `-ERESTARTNOHAND` down to
///      `-EINTR` there and under `STICKY_TIMEOUTS`, because a call whose
///      residual timeout never reached userspace cannot be restarted
///      (`fs/select.c:353-363`).
/// # C: O(1)
pub(crate) fn poll_select_finish(cur: Option<&sched::Task>, rv: i64, tsp: u64,
                                 req_sec: i64, req_nsec: i64,
                                 deadline_ns: Option<u64>) -> i64 {
    if let Some(c) = cur {
        if restores_saved_sigmask(rv) { c.restore_saved_sigmask(); }
    }
    if tsp == 0 { return rv; }
    let persona = cur.map(|c| c.personality.load(Ordering::Acquire)).unwrap_or(0);
    let plan = timeout_writeback_plan(persona, req_sec, req_nsec);
    if plan != TimeoutWriteback::Wrote { return finish_return(rv, plan); }
    let Some(deadline) = deadline_ns else { return finish_return(rv, TimeoutWriteback::Skipped) };
    let (sec, nsec) = remaining_timespec(deadline, monotonic_ns());
    let done = if validate_user_buf_writable(tsp, TIMESPEC_BYTES, 1).is_ok() {
        // SAFETY: tsp validated writable for the whole 16-byte user timespec.
        unsafe {
            core::ptr::write_unaligned(tsp as *mut i64, sec);
            core::ptr::write_unaligned((tsp + TIMESPEC_NSEC_OFF) as *mut i64, nsec);
        }
        TimeoutWriteback::Wrote
    } else {
        TimeoutWriteback::Faulted
    };
    finish_return(rv, done)
}

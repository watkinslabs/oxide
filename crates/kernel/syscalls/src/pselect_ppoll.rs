// Shared pselect6/ppoll (slots 270/271) decision rules — Linux's
// `SYSCALL_DEFINE6(pselect6)`, `do_pselect`, `SYSCALL_DEFINE5(ppoll)`,
// `poll_select_finish`, `do_poll`, `do_select`, `core_sys_select`, and
// `set_user_sigmask`.
//
// NOT `#[cfg(target_os = "oxide-kernel")]`: these two slots are the event-loop
// core (glibc implements `poll(2)` on `ppoll` and `select(2)` on `pselect6`),
// so the ABI rules live in ONE module compiled into the hosted test build too.

use syscall::errno::Errno;

/// `sizeof(struct sigset_argpack)`. pselect6's 6th argument is a POINTER to
/// `{ const sigset_t *ss; size_t ss_len; }` — never the sigset itself, and
/// never a bare mask value. Linux `get_sigset_argpack`.
pub const SIGSET_ARGPACK_BYTES: u64 = 16;

/// Byte offset of `ss_len` inside `struct sigset_argpack`.
pub const SIGSET_ARGPACK_LEN_OFF: u64 = 8;

/// `sizeof(struct __kernel_timespec)` — `{ i64 tv_sec, i64 tv_nsec }`.
/// pselect6/ppoll take a timespec, not select's `timeval` or poll's `int ms`.
pub const TIMESPEC_BYTES: u64 = 16;

/// Byte offset of `tv_nsec` inside `struct __kernel_timespec`.
pub const TIMESPEC_NSEC_OFF: u64 = 8;

/// Linux `set_user_sigmask`: `if (!umask) return 0;` — a NULL sigset pointer
/// means "do not touch the mask", NOT "install an empty mask". Only a
/// non-NULL pointer is size-checked, so `ppoll(…, NULL, 0)` and a pselect6
/// argpack of `{NULL, 0}` are both legal.
/// # C: O(1)
pub fn user_sigmask_wanted(ss_ptr: u64, ss_len: u64) -> Result<bool, Errno> {
    if ss_ptr == 0 { return Ok(false); }
    syscall::sigset::check_exact(ss_len)?;
    Ok(true)
}

/// Linux `poll_select_finish`'s `restore_saved_sigmask_unless(ret ==
/// -ERESTARTNOHAND)`. `-ERESTARTNOHAND` is the one return
/// value that must LEAVE the temporary mask installed: the syscall-return tail
/// then either builds a handler frame under it (`Task::sigmask_to_save` folds
/// the saved mask into what `rt_sigreturn` restores) or restores it itself. A
/// syscall that restores eagerly instead reopens the delivery race
/// pselect6/ppoll exist to close.
/// # C: O(1)
pub fn restores_saved_sigmask(rv: i64) -> bool {
    rv != syscall::restart::restart_nohand()
}

/// Linux `do_poll` / `do_select` break order for one readiness scan:
/// `if (!count) { if (signal_pending(current)) count = -ERESTARTNOHAND; }`
/// / `core_sys_select`'s `ret = -ERESTARTNOHAND; if
/// (signal_pending(current)) goto out;`, then `if
/// (count || timed_out) break;`. Readiness outranks a pending signal, and a
/// pending signal outranks an expired timeout.
///
/// The interrupted verdict is `-ERESTARTNOHAND`, NOT `-EINTR`: Linux restarts
/// these calls whenever no user handler frame was built (SIG_DFL/SIG_IGN
/// disposition, a job-control stop, or a raced dequeue), and only reports
/// EINTR once a handler actually ran. Folding it to EINTR inside the engine
/// destroys that distinction — see `finish_return` for the two places Linux
/// itself does fold it. `None` = keep waiting.
/// # C: O(1)
pub fn wait_verdict(ready: i64, timed_out: bool, signal_pending: bool) -> Option<i64> {
    if ready > 0 { return Some(ready); }
    if signal_pending { return Some(syscall::restart::restart_nohand()); }
    if timed_out { return Some(0); }
    None
}

/// What `poll_select_finish` did about the caller's residual-timeout buffer.
/// The distinction is load-bearing: it decides whether `-ERESTARTNOHAND`
/// survives (the call may restart) or collapses to `-EINTR`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeoutWriteback {
    /// Linux's `if (!p) return ret;` / "No update for zero timeout" early
    /// returns — nothing to write, `ret` untouched.
    Skipped,
    /// `STICKY_TIMEOUTS` persona: `goto sticky`.
    Sticky,
    /// The residual timeout reached userspace.
    Wrote,
    /// `copy_to_user`/`put_timespec64` failed and control fell into `sticky:`.
    Faulted,
}

/// Linux `poll_select_finish`'s `sticky:` tail — `if (ret == -ERESTARTNOHAND)
/// ret = -EINTR;`. Reached ONLY when the residual
/// timeout could not be written back, because Linux's own comment there
/// spells out why: "because we're not updating the timeval, we can't restart
/// the system call". A successful writeback — and the `!p` / zero-timeout
/// early returns, which have nothing to update — keep `-ERESTARTNOHAND` so the
/// no-handler case restarts.
/// # C: O(1)
pub fn finish_return(rv: i64, wb: TimeoutWriteback) -> i64 {
    match wb {
        TimeoutWriteback::Sticky | TimeoutWriteback::Faulted
            if rv == syscall::restart::restart_nohand() => -(Errno::Eintr.as_i32() as i64),
        _ => rv,
    }
}

/// Linux `core_sys_select`: `if (ret < 0) goto out;` — the caller's fd sets
/// (and, for poll, its `revents`) are only copied out on a non-negative
/// return, so an interrupted `select` leaves the caller's sets untouched.
/// # C: O(1)
pub fn copies_out_fd_sets(rv: i64) -> bool { rv >= 0 }

/// Linux `poll_select_finish`: the RAW pselect6/ppoll/select syscalls DO write
/// the remaining time back to the caller's timespec/timeval
/// (`put_timespec64`/`copy_to_user`); only the glibc wrappers hide it behind a
/// local copy. Two cases skip the update, in Linux's order — a
/// `STICKY_TIMEOUTS` personality (`goto sticky`, checked FIRST) and a zero
/// timeout, whose `end_time` stays `{0,0}` ("No update for zero timeout").
/// The two differ in more than the write: only `sticky` folds
/// `-ERESTARTNOHAND` down to `-EINTR`.
/// # C: O(1)
pub fn timeout_writeback_plan(personality: u32, req_sec: i64, req_nsec: i64) -> TimeoutWriteback {
    if personality & sched::personality::STICKY_TIMEOUTS != 0 { return TimeoutWriteback::Sticky; }
    if req_sec == 0 && req_nsec == 0 { return TimeoutWriteback::Skipped; }
    TimeoutWriteback::Wrote
}

/// Linux `poll_select_finish`: `rts = timespec64_sub(*end_time, now)` with
/// `if (rts.tv_sec < 0) rts.tv_sec = rts.tv_nsec = 0;`. An already-expired
/// deadline reports `{0,0}`, never a negative remainder.
/// # C: O(1)
pub fn remaining_timespec(deadline_ns: u64, now_ns: u64) -> (i64, i64) {
    let rem = deadline_ns.saturating_sub(now_ns);
    ((rem / syscall::time::NSEC_PER_SEC) as i64,
     (rem % syscall::time::NSEC_PER_SEC) as i64)
}

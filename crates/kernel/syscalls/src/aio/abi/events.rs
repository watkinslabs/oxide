// `io_getevents`/`io_pgetevents` argument rules and return folding.
//
// The timeout here is NOT the pselect/ppoll timespec: it is never validated
// (`tv_sec < 0` and an out-of-range `tv_nsec` are legal), never written back,
// and a NULL pointer means "wait forever" rather than "poll". A `{0,0}`
// timeout is the non-blocking form. Keeping these rules apart from
// `crate::pselect_ppoll` is deliberate — sharing that module's validation
// would turn a legal aio call into EINVAL.

use syscall::errno::Errno;

/// Nanoseconds per second.
pub const NSEC_PER_SEC: i64 = 1_000_000_000;
/// Largest `tv_sec` that still converts to a finite nanosecond deadline;
/// anything at or above it saturates to "wait forever".
pub const KTIME_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC;

/// How long a reap may block.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Until {
    /// No timeout pointer was supplied.
    Forever,
    /// A zero or already-elapsed timeout: take what is queued and return.
    Immediate,
    /// Relative nanoseconds to wait for.
    Relative(u64),
}

/// Convert the caller's relative `timespec` into a wait bound. A negative
/// second count, or a nanosecond field outside `[0, 1e9)`, is not rejected —
/// it simply produces a non-positive interval, which is the immediate form.
/// # C: O(1)
pub fn until_from_timespec(sec: i64, nsec: i64) -> Until {
    if sec >= KTIME_SEC_MAX { return Until::Relative(u64::MAX); }
    let ns = sec.saturating_mul(NSEC_PER_SEC).saturating_add(nsec);
    if ns <= 0 { return Until::Immediate; }
    Until::Relative(ns as u64)
}

/// `min_nr` must be non-negative and no larger than `nr`; anything else is
/// `EINVAL`. A negative `nr` therefore cannot pass, and neither can
/// `min_nr > nr`, which would otherwise wait for events the call could not
/// return.
/// # C: O(1)
pub fn validate_reap_counts(min_nr: i64, nr: i64) -> Result<(), Errno> {
    if min_nr < 0 || min_nr > nr { return Err(Errno::Einval); }
    Ok(())
}

/// `io_getevents` tail: a reap that produced nothing while a signal is pending
/// reports `EINTR`. A reap that delivered events keeps its count, and an
/// error return is left alone.
/// # C: O(1)
pub fn getevents_return(ret: i64, signal_pending: bool) -> i64 {
    if ret == 0 && signal_pending { return -(Errno::Eintr.as_i32() as i64); }
    ret
}

/// `io_pgetevents` tail: same shape, but an interrupted empty reap reports the
/// restart code rather than `EINTR`, so a `SA_RESTART` handler resumes the
/// call instead of failing it. The temporary sigmask stays installed for that
/// case; every other outcome restores it.
/// # C: O(1)
pub fn pgetevents_return(ret: i64, signal_pending: bool) -> i64 {
    if ret == 0 && signal_pending { return syscall::restart::restart_nohand(); }
    ret
}

/// Whether the saved sigmask must be put back before returning: everything
/// except the restart code, which deliberately leaves the temporary mask in
/// place for the signal-return path to unwind.
/// # C: O(1)
pub fn restores_sigmask(rv: i64) -> bool { rv != syscall::restart::restart_nohand() }

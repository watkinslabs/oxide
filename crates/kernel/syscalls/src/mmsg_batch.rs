// `recvmmsg` batch rules: what admits a batch, what ends one, and what a
// partly-delivered batch reports.
//
// A batch is a loop over one pinned socket. Every decision it makes belongs
// here, and the slot file (`299_recvmmsg.rs`) keeps only the ABI work — import
// one entry, call the receive, publish one length. That split is not cosmetic:
// the slot file is `#[cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]`
// block inside it compiles away in silence and reports nothing.
//
// The rules, in the order the batch applies them:
//
// - the native entry never speaks the compat message layout, and rejects it
//   before the timeout, the descriptor, or any entry is touched;
// - a supplied timeout is validated NEXT, still ahead of the descriptor, so a
//   malformed one reports EINVAL whatever the descriptor is;
// - a pending socket error is reported before the batch runs and consumed by
//   doing so — unless this is an error-queue read, which is how that error is
//   meant to be collected;
// - `recvmmsg` walks the caller's WHOLE array; the `UIO_MAXIOV` clamp belongs
//   to `sendmmsg` alone, and copying it here silently truncated long batches;
// - `MSG_WAITFORONE` is never passed to a single receive; instead, once one
//   message has landed it becomes `MSG_DONTWAIT`, so the rest of the batch
//   drains what is already queued rather than waiting again;
// - after each delivered message the timeout is re-read, then out-of-band data
//   ends the batch — a caller must see an urgent message on its own;
// - a failing entry with nothing delivered reports the failure; with messages
//   already delivered it reports the count and LATCHES the failure as the
//   socket's pending error, except EAGAIN, which means only "nothing more is
//   queued" and is not an error to remember;
// - the remaining timeout is written back only when at least one message
//   landed; an empty nonblocking return leaves the caller's timespec alone.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

use syscall::errno::Errno;

use net::uapi::{MSG_CMSG_COMPAT, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_WAITFORONE};

/// Nanoseconds in one second, for the supplied-timeout range check.
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Negative-errno form of one failed batch entry. # C: O(1)
fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The native entry rejects the compat message layout before it touches the
/// timeout, the descriptor, or any entry. # C: O(1)
pub fn admit_flags(flags: u64) -> Result<(), Errno> {
    if flags & MSG_CMSG_COMPAT != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Total nanoseconds of a supplied batch timeout. A negative second or
/// nanosecond count, or a nanosecond count that is not less than a second, is
/// EINVAL — reported before the descriptor is resolved. # C: O(1)
pub fn timeout_total_ns(sec: i64, nsec: i64) -> Result<u64, Errno> {
    if sec < 0 || nsec < 0 || nsec >= NSEC_PER_SEC as i64 { return Err(Errno::Einval); }
    Ok((sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(nsec as u64))
}

/// Whether a pending socket error is reported ahead of the batch. An
/// error-queue read is the one caller that wants to reach the queue instead.
/// # C: O(1)
pub fn reports_pending_error(flags: u64) -> bool { flags & MSG_ERRQUEUE == 0 }

/// Entries the batch walks. `recvmmsg` takes the caller's count as given —
/// the `UIO_MAXIOV` clamp is `sendmmsg`'s alone. # C: O(1)
pub fn batch_len(vlen: u64) -> u64 { vlen as u32 as u64 }

/// Flags one entry's receive runs with. `MSG_WAITFORONE` never reaches a
/// single receive; after the first message it turns into `MSG_DONTWAIT`.
/// # C: O(1)
pub fn entry_flags(flags: u64, delivered: u64) -> u64 {
    let plain = flags & !MSG_WAITFORONE;
    if flags & MSG_WAITFORONE != 0 && delivered != 0 { plain | MSG_DONTWAIT } else { plain }
}

/// What the batch does after one message is delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfterDelivery {
    /// Take the next entry.
    Continue,
    /// The supplied timeout ran out.
    TimedOut,
    /// The message carried out-of-band data; the caller must see it alone.
    OutOfBand,
}

/// The batch re-reads the timeout first, then asks whether the message that
/// just landed was urgent. `remaining_ns` is `None` when no timeout was
/// supplied. # C: O(1)
pub fn after_delivery(remaining_ns: Option<u64>, oob: bool) -> AfterDelivery {
    if remaining_ns == Some(0) { return AfterDelivery::TimedOut; }
    if oob { return AfterDelivery::OutOfBand; }
    AfterDelivery::Continue
}

/// What a failing entry does to the batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnFailure {
    /// Nothing was delivered, so the failure IS the answer.
    Report(i64),
    /// Report what was delivered; `latch` is the errno stored as the socket's
    /// pending error for the next call to collect.
    Deliver { count: i64, latch: Option<i32> },
}

/// `delivered` is the count already published, `failure` the negative errno
/// the entry produced. # C: O(1)
pub fn on_failure(delivered: i64, failure: i64) -> OnFailure {
    if delivered == 0 { return OnFailure::Report(failure); }
    if failure == neg(Errno::Eagain) { return OnFailure::Deliver { count: delivered, latch: None }; }
    match i32::try_from(-failure) {
        Ok(errno) if errno > 0 => OnFailure::Deliver { count: delivered, latch: Some(errno) },
        _ => OnFailure::Deliver { count: delivered, latch: None },
    }
}

/// Whether the remaining timeout is written back to the caller. # C: O(1)
pub fn copies_timeout_back(result: i64) -> bool { result > 0 }

#[cfg(test)]
mod tests;

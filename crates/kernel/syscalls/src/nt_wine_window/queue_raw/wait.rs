//! Wait-slot arithmetic and result encoding for `MsgWaitForMultipleObjectsEx`
//! and `WaitMessage`. Queue-status classification belongs to the queue owner.

/// Wait for an already-available message rather than only for a new one.
#[allow(dead_code)] // KI-0711
pub(crate) const MWMO_INPUTAVAILABLE: u32 = 0x0004;
#[allow(dead_code)] // KI-0711
pub(crate) const MWMO_ALERTABLE: u32 = 0x0002;
/// The queue occupies one wait slot, so a caller may name at most one fewer.
pub(crate) const MAXIMUM_WAIT_OBJECTS: u32 = 64;
pub(crate) const WAIT_OBJECT_0: u32 = 0;
pub(crate) const WAIT_TIMEOUT: u32 = 0x0000_0102;
pub(crate) const WAIT_IO_COMPLETION: u32 = 0x0000_00c0;
pub(crate) const WAIT_FAILED: u32 = 0xffff_ffff;
pub(crate) const INFINITE: u32 = 0xffff_ffff;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;

/// A count leaving no slot for the queue handle refuses the wait. # C: O(1)
pub(crate) const fn count_admitted(count: u32) -> bool { count < MAXIMUM_WAIT_OBJECTS }

/// The queue is appended after the caller's objects, so it answers at `count`. # C: O(1)
pub(crate) const fn queue_result(count: u32) -> u32 { WAIT_OBJECT_0 + count }

/// # C: O(1)
pub(crate) const fn object_result(index: u32) -> u32 { WAIT_OBJECT_0 + index }

/// Deadline in monotonic nanoseconds; an infinite timeout has none. # C: O(1)
pub(crate) const fn deadline_ns(now_ns: u64, timeout_ms: u32) -> Option<u64> {
    if timeout_ms == INFINITE { return None; }
    Some(now_ns.saturating_add((timeout_ms as u64).saturating_mul(1_000_000)))
}

/// A wait that already accepts available input consults the queue before parking. # C: O(1)
#[allow(dead_code)] // KI-0711
pub(crate) const fn checks_before_waiting(flags: u32) -> bool { flags & MWMO_INPUTAVAILABLE != 0 }

/// `WaitMessage` reports success for anything but an outright failure. # C: O(1)
pub(crate) const fn wait_message_result(status: u32) -> u64 { (status != WAIT_FAILED) as u64 }

/// What one pass of the message wait answers, before it parks again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Step {
    /// A named object at this wait index is signaled.
    Object(u32),
    /// The queue holds work in the named classes; it answers at its own slot.
    Queue,
    /// The timeout expired with nothing signaled.
    TimedOut,
    /// Nothing is ready: park on the process wait list.
    Park,
}

/// Decide one pass of the wait over the objects and the queue, which shares
/// the object wait list and occupies the slot after them. The lowest signaled
/// wait index answers first, so a named object outranks the queue and both
/// outrank the timeout. # C: O(N_objects)
pub(crate) fn step(signaled: impl IntoIterator<Item = bool>, queue_ready: bool, expired: bool) -> Step {
    for (index, ready) in signaled.into_iter().enumerate() {
        if ready { return Step::Object(index as u32); }
    }
    if queue_ready { return Step::Queue; }
    if expired { return Step::TimedOut; }
    Step::Park
}

/// Encode the answer of one pass; a parked pass has no answer. # C: O(1)
pub(crate) const fn step_result(step: Step, count: u32) -> Option<u32> {
    match step {
        Step::Object(index) => Some(object_result(index)),
        Step::Queue => Some(queue_result(count)),
        Step::TimedOut => Some(WAIT_TIMEOUT),
        Step::Park => None,
    }
}

/// The parked wait resumes for queue work in the named classes or for any
/// named object, because both signal the one process wait list. # C: O(1)
pub(crate) const fn wake_condition(queue_ready: bool, object_signaled: bool) -> bool {
    queue_ready || object_signaled
}

#[cfg(test)]
#[path = "../tests/queue_wait.rs"]
mod tests;

//! Sleep queues for VM migration markers.
//!
//! The VMM registry calls `park` while holding only its token lock, then the
//! fault path drops its page-table lock and schedules.  Completion commits a
//! replacement PTE first and wakes by token; every woken path restarts and
//! revalidates the PTE instead of interpreting a migration marker as swap.

use super::{schedule, KeyedWaitQueues};

static WAITERS: KeyedWaitQueues<u64> = KeyedWaitQueues::new();

/// Register current on `token`. Caller holds the VMM token lock, which closes
/// the completion-before-park race; no VM or page-table lock may be held.
pub fn park(token: u64) {
    WAITERS.prepare(token);
}

/// Sleep after [`park`], then revalidate and restart the operation. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller just parked on this list and holds no VM locks.
    unsafe { schedule(); }
}

/// Wake all marker waiters after the replacement PTE and registry completion
/// are visible. # C: O(N_waiters)
pub fn wake(token: u64) {
    // Completion is terminal for a token: the VMM registry prevents a new
    // registration after it flips pending=false.  Remove this strong map
    // owner before waking; WaitList itself retains each parked task until it
    // is consumed, so no waiter can be lost and completed tokens cannot leak.
    WAITERS.take_and_wake_all(token);
}

#[cfg(test)]
pub(crate) fn queue_count() -> usize { WAITERS.queue_count() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_wake_retires_each_token_queue() {
        let before = queue_count();
        let token_a = 0xa5a5_u64;
        let token_b = token_a + 1;
        assert!(queue_count() == before);
        // No scheduler is installed in this hosted unit, so `park` does not
        // add a task, but it still materializes the keyed queue.
        park(token_a);
        park(token_b);
        assert_eq!(queue_count(), before + 2);
        wake(token_a);
        assert_eq!(queue_count(), before + 1);
        wake(token_b);
        assert_eq!(queue_count(), before);
    }
}

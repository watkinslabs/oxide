//! Sleep queues for VM migration markers.
//!
//! The VMM registry calls `park` while holding only its token lock, then the
//! fault path drops its page-table lock and schedules.  Completion commits a
//! replacement PTE first and wakes by token; every woken path restarts and
//! revalidates the PTE instead of interpreting a migration marker as swap.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use sync::{Spinlock, TaskList as WaitClass};

use super::{schedule, WaitList};

static WAITERS: Spinlock<BTreeMap<u64, Arc<WaitList>>, WaitClass> = Spinlock::new(BTreeMap::new());

fn wait_list(token: u64) -> Arc<WaitList> {
    let mut waiters = WAITERS.lock();
    waiters.entry(token).or_insert_with(|| Arc::new(WaitList::new())).clone()
}

/// Register current on `token`. Caller holds the VMM token lock, which closes
/// the completion-before-park race; no VM or page-table lock may be held.
pub fn park(token: u64) {
    let wait = wait_list(token);
    // SAFETY: fault/fork caller schedules immediately after registration.
    unsafe { wait.park(); }
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
    let wait = { WAITERS.lock().remove(&token) };
    if let Some(wait) = wait { wait.wake_all(); }
}

#[cfg(test)]
pub(crate) fn queue_count() -> usize { WAITERS.lock().len() }

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

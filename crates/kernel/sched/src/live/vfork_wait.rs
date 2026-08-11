//! CLONE_VFORK completion wait. The child arms `vfork_pending` before it is
//! runnable; exec or exit clears it before waking that child's completion
//! queue. Keeping completions keyed by child prevents one vfork departure from
//! waking unrelated vfork parents.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as WaitClass};

use crate::{Task, WaitOutcome};

use super::{WaitList, wait_event_killable};

static WAITERS: Spinlock<BTreeMap<u32, Arc<WaitList>>, WaitClass> = Spinlock::new(BTreeMap::new());

fn wait_list(tid: u32) -> Arc<WaitList> {
    let mut waiters = WAITERS.lock();
    waiters.entry(tid).or_insert_with(|| Arc::new(WaitList::new())).clone()
}

/// Wait for one vfork child to release its parent's borrowed address space.
/// Returns false when a fatal signal interrupted the killable completion wait.
/// # SAFETY: process context on the child's parent, no lock held by vfork_done.
/// # C: O(log N) plus sleeps
pub unsafe fn wait_for_done(child: &Task) -> bool {
    let wait = wait_list(child.tid);
    // SAFETY: forwards this function's process-context contract to the keyed
    // completion predicate loop; child stays referenced by the caller.
    let completed = matches!(unsafe { wait_event_killable(&wait,
        || !child.vfork_pending.load(Ordering::Acquire)) }, WaitOutcome::Ready);
    prune(child.tid, &wait);
    completed
}

/// Release the parent waiting for `child`'s vfork completion. # C: O(log N)
pub fn wake(child: &Task) {
    let wait = { WAITERS.lock().get(&child.tid).cloned() };
    if let Some(wait) = wait {
        wait.wake_all();
        prune(child.tid, &wait);
    }
}

fn prune(tid: u32, wait: &Arc<WaitList>) {
    // Map + this local reference are the only references once the parent has
    // finished its wait. Holding the map lock makes replacement atomic with a
    // new registrar selecting the list, so removing an idle entry cannot lose
    // a concurrent child's completion wake.
    let mut waiters = WAITERS.lock();
    let mapped = waiters.get(&tid).is_some_and(|mapped| Arc::ptr_eq(mapped, wait));
    if mapped && !wait.has_waiters() && Arc::strong_count(wait) == 2 {
        waiters.remove(&tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_removes_an_idle_completion() {
        const TID: u32 = u32::MAX;
        let wait = wait_list(TID);
        prune(TID, &wait);
        assert!(!WAITERS.lock().contains_key(&TID));
    }
}

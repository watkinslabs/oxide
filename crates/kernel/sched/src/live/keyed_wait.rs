//! Scheduler-owned keyed wait queues for state machines whose objects live in
//! lower layers (VFS, VMM).  Linux normally embeds a `wait_queue_head_t` in
//! the owning object; the dependency boundary here instead passes an opaque
//! object identity to sched.  This type centralizes that bridge.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as WaitClass};

use super::WaitList;

/// One lazily-created wait queue per owner key.  A caller's state lock is the
/// condition gate: it must cover `prepare*` and the corresponding wake, just
/// as Linux holds the lock protecting a `wait_event` predicate.
pub struct KeyedWaitQueues<K: Ord + Copy> {
    queues: Spinlock<BTreeMap<K, Arc<WaitList>>, WaitClass>,
}

impl<K: Ord + Copy> KeyedWaitQueues<K> {
    /// # C: O(1)
    pub const fn new() -> Self { Self { queues: Spinlock::new(BTreeMap::new()) } }

    fn queue(&self, key: K) -> Arc<WaitList> {
        let mut queues = self.queues.lock();
        queues.entry(key).or_insert_with(|| Arc::new(WaitList::new())).clone()
    }

    /// Publish the running task on `key`'s uninterruptible queue.  The caller
    /// immediately drops its condition gate and schedules.
    /// # C: O(log N)
    pub fn prepare(&self, key: K) {
        let queue = self.queue(key);
        // SAFETY: callers provide the same condition-gate contract as Linux
        // `prepare_to_wait`; this owner only centralizes queue lifetime.
        unsafe { queue.prepare_to_wait(); }
    }

    /// Interruptible form of [`Self::prepare`]. # C: O(log N)
    pub fn prepare_interruptible(&self, key: K) {
        let queue = self.queue(key);
        // SAFETY: same condition-gate contract as `prepare`.
        unsafe { queue.prepare_to_wait_interruptible(); }
    }

    /// Wake every waiter registered for `key`. # C: O(N_waiters + log N)
    pub fn wake_all(&self, key: K) {
        let queue = { self.queues.lock().get(&key).cloned() };
        if let Some(queue) = queue {
            queue.wake_all();
            self.prune(key, &queue);
        }
    }

    /// Wake one waiter registered for `key`. # C: O(log N)
    pub fn wake_one(&self, key: K) {
        let queue = { self.queues.lock().get(&key).cloned() };
        if let Some(queue) = queue {
            queue.wake_one();
            self.prune(key, &queue);
        }
    }

    /// Terminal completion: remove the registry's strong reference before
    /// waking every waiter.  A completed key cannot be registered again.
    /// # C: O(N_waiters + log N)
    pub fn take_and_wake_all(&self, key: K) {
        if let Some(queue) = self.queues.lock().remove(&key) { queue.wake_all(); }
    }

    /// Number of materialized queues, for hosted lifecycle tests. # C: O(1)
    #[cfg(test)]
    pub fn queue_count(&self) -> usize { self.queues.lock().len() }

    fn prune(&self, key: K, queue: &Arc<WaitList>) {
        // Retire empty one-shot queues.  Holding the map lock makes removal
        // atomic with a new registrar selecting its queue; that registrar's
        // Arc keeps the queue alive until its publication completes.
        let mut queues = self.queues.lock();
        let mapped = queues.get(&key).is_some_and(|mapped| Arc::ptr_eq(mapped, queue));
        if mapped && !queue.has_waiters() && Arc::strong_count(queue) == 2 {
            queues.remove(&key);
        }
    }
}

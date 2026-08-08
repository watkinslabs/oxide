// The record backlog.
//
// Two queues, because a record has two ways of not being deliverable yet:
//   - `queue` holds records produced while a consumer is registered but has
//     not drained them. Its depth is the `backlog` field userspace reads.
//   - `hold` keeps records produced while NO consumer is registered, so a
//     daemon that starts after the kernel still sees what happened before it.
// Both are bounded by the same configured limit; over the limit a record is
// dropped and counted lost, which is the accounting a consumer uses to know
// its log has a hole.

extern crate alloc;

use alloc::collections::VecDeque;

use crate::record::Record;

/// Whether one more record fits a queue already holding `queued` of them.
/// A zero limit is unlimited; otherwise the limit is a high-water mark that
/// the queue may sit exactly on, so admission stops once it is exceeded.
/// # C: O(1)
pub fn backlog_admits(queued: usize, limit: u32) -> bool {
    limit == 0 || queued <= limit as usize
}

/// The two record queues.
#[derive(Default)]
pub struct Backlog {
    queue: VecDeque<Record>,
    hold:  VecDeque<Record>,
}

impl Backlog {
    /// # C: O(1)
    pub const fn new() -> Self { Self { queue: VecDeque::new(), hold: VecDeque::new() } }

    /// Depth of the deliverable queue — the `backlog` status field.
    /// # C: O(1)
    pub fn len(&self) -> usize { self.queue.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
    /// # C: O(1)
    pub fn hold_len(&self) -> usize { self.hold.len() }

    /// Queue a record for a registered consumer. `false` means the limit
    /// refused it and the caller must count it lost.
    /// # C: O(1)
    pub fn push(&mut self, r: Record, limit: u32) -> bool {
        if !backlog_admits(self.queue.len(), limit) { return false; }
        self.queue.push_back(r);
        true
    }

    /// Park a record until a consumer registers.
    /// # C: O(1)
    pub fn hold(&mut self, r: Record, limit: u32) -> bool {
        if !backlog_admits(self.hold.len(), limit) { return false; }
        self.hold.push_back(r);
        true
    }

    /// # C: O(1)
    pub fn pop(&mut self) -> Option<Record> { self.queue.pop_front() }

    /// Move everything parked into the deliverable queue, oldest first. A
    /// consumer that registers late gets the history in the order it happened.
    /// # C: O(N_held)
    pub fn release_hold(&mut self) {
        while let Some(r) = self.hold.pop_front() { self.queue.push_back(r); }
    }

    /// # C: O(1)
    #[cfg(test)]
    pub(crate) fn pop_hold_for_test(&mut self) -> Option<Record> { self.hold.pop_front() }
}

#[cfg(test)]
#[path = "tests/queue.rs"]
mod tests;

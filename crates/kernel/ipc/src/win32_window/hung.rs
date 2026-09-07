//! Whether a window's owning thread has stopped reading its message queue.
//! A queue counts as hung once it has work waiting and its owner has not read
//! it for the reference's five-second window.
use super::*;

/// Reference window after which a signalled, unread queue counts as hung.
pub const HUNG_QUEUE_NS: u64 = 5_000_000_000;

impl MessageQueue {
    /// Work the owning thread would be woken for. # C: O(1)
    fn signalled(&self) -> bool { !self.messages.is_empty() || self.quit.is_some() }
    /// # C: O(1)
    pub(super) fn note_access(&mut self, now_ns: u64) { self.access_ns = now_ns; }
    /// # C: O(1)
    pub(super) fn hung(&self, now_ns: u64) -> bool { self.signalled() && now_ns.saturating_sub(self.access_ns) > HUNG_QUEUE_NS }
}

impl WindowManager {
    /// Record that a thread read its own message queue. # C: O(N_threads)
    pub fn note_queue_access(&mut self, tid: u64, now_ns: u64) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.note_access(now_ns); }
        else { let mut queue = MessageQueue::default(); queue.note_access(now_ns); self.queues.push((tid, queue)); }
    }

    /// A thread with no queue has nothing waiting and is not hung. # C: O(N_threads)
    pub fn thread_hung(&self, tid: u64, now_ns: u64) -> bool {
        self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.hung(now_ns))
    }

    /// # C: O(N_windows + N_threads)
    pub fn window_hung(&self, id: WindowId, now_ns: u64) -> bool {
        self.get(id).is_some_and(|record| self.thread_hung(record.owner_tid, now_ns))
    }
}

#[cfg(test)]
#[path = "tests/hung.rs"]
mod tests;

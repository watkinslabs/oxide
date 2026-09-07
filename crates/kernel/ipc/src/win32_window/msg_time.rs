//! Message time: the tick count stamped on a message when it is queued, and
//! the time of the message a thread last read.
//!
//! A queued message carries the tick count of the moment it was queued; a
//! synthesised retrieval (the quit message, a deferred paint) carries the tick
//! count of the retrieval, because no queue entry ever held it. The class of
//! the thread-state query that reports the message time reads the value the
//! last successful retrieval recorded.

use super::{MessageQueue, WindowManager};

/// Nanoseconds in one tick.
const NS_PER_TICK: u64 = 1_000_000;

/// Tick count for one monotonic timestamp. The count is a 32-bit millisecond
/// counter and wraps, as the tick count a message carries does. # C: O(1)
pub const fn tick_ms_from_ns(ns: u64) -> u32 { (ns / NS_PER_TICK) as u32 }

/// Tick count now. # C: O(1)
pub fn tick_ms() -> u32 { tick_ms_from_ns(timekeeper::monotonic_ns()) }

impl MessageQueue {
    /// # C: O(1)
    pub(super) fn note_message_time(&mut self, time: u32) { self.message_time = time; }
    /// # C: O(1)
    pub(super) fn last_message_time(&self) -> u32 { self.message_time }
}

impl WindowManager {
    /// Time of the message one thread last read. A thread that has read none,
    /// and one with no queue, report zero. # C: O(N_queues)
    pub fn message_time(&self, tid: u64) -> u32 {
        self.queues.iter().find(|(owner, _)| *owner == tid).map_or(0, |(_, queue)| queue.last_message_time())
    }

    /// Record the time of a retrieval that no queue entry carried. # C: O(N_queues)
    pub(super) fn note_thread_message_time(&mut self, tid: u64, time: u32) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.note_message_time(time); }
    }
}

#[cfg(test)]
#[path = "tests/msg_time.rs"]
mod tests;

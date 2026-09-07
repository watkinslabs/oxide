//! Message position and message extra information: the two per-thread values a
//! retrieval records beside the message time.
//!
//! A queued message carries the desktop cursor position of the moment it was
//! queued, exactly as it carries the tick count of that moment; a retrieval
//! copies that position into the reading thread's record, so a query answers
//! where the pointer was when the message was generated rather than where it
//! is now. Extra information is thread state a caller sets and a retrieval
//! resets: every message this owner queues carries none, which is the value a
//! retrieval therefore records.

use super::{MessageQueue, WindowManager};

/// Pack a screen point the way the position query reports it: the x coordinate
/// in the low half and the y coordinate in the high half, each truncated to a
/// signed 16-bit coordinate. # C: O(1)
pub const fn pack_pos(x: i32, y: i32) -> u32 { ((y as u16 as u32) << 16) | x as u16 as u32 }

/// Signed x coordinate of a packed position. # C: O(1)
pub const fn pos_x(packed: u32) -> i32 { (packed as u16) as i16 as i32 }

/// Signed y coordinate of a packed position. # C: O(1)
pub const fn pos_y(packed: u32) -> i32 { ((packed >> 16) as u16) as i16 as i32 }

impl MessageQueue {
    /// # C: O(1)
    pub(super) fn note_message_pos(&mut self, pos: u32) { self.message_pos = pos; }
    /// # C: O(1)
    pub(super) fn last_message_pos(&self) -> u32 { self.message_pos }
    /// # C: O(1)
    pub(super) fn note_message_extra(&mut self, extra: i64) { self.message_extra = extra; }
    /// # C: O(1)
    pub(super) fn last_message_extra(&self) -> i64 { self.message_extra }
}

impl WindowManager {
    /// Packed position of the message one thread last read. A thread that has
    /// read none, and one with no queue, report the origin. # C: O(N_queues)
    pub fn message_pos(&self, tid: u64) -> u32 {
        self.queues.iter().find(|(owner, _)| *owner == tid).map_or(0, |(_, queue)| queue.last_message_pos())
    }

    /// Extra information the calling thread last set, which a retrieval resets.
    /// # C: O(N_queues)
    pub fn message_extra(&self, tid: u64) -> i64 {
        self.queues.iter().find(|(owner, _)| *owner == tid).map_or(0, |(_, queue)| queue.last_message_extra())
    }

    /// Replace one thread's extra information and report what it replaced. A
    /// thread with no queue yet gets one, so the value it sets survives until
    /// its first retrieval. # C: O(N_queues)
    pub fn set_message_extra(&mut self, tid: u64, extra: i64) -> i64 {
        if self.queues.iter().all(|(owner, _)| *owner != tid) { self.queues.push((tid, MessageQueue::default())); }
        let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) else { return 0; };
        let previous = queue.last_message_extra();
        queue.note_message_extra(extra);
        previous
    }

    /// Record the position of a retrieval that no queue entry carried.
    /// # C: O(N_queues)
    pub(super) fn note_thread_message_pos(&mut self, tid: u64, pos: u32) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) {
            queue.note_message_pos(pos);
            queue.note_message_extra(0);
        }
    }

    /// Desktop cursor position packed for the message defaults a post records.
    /// # C: O(1)
    pub(super) fn queue_pos_default(&self) -> u32 { pack_pos(self.cursor.0, self.cursor.1) }
}

#[cfg(test)]
#[path = "tests/msg_pos.rs"]
mod tests;

//! Queue wake and changed bits, and the thread-state classes that read the
//! per-thread input records.
//!
//! Wake bits describe what the queue holds right now; changed bits accumulate
//! as messages arrive and are cleared by the query that reports them.

use super::{MessageQueue, WindowId, WindowManager};

pub const QS_KEY: u32 = 0x0001;
pub const QS_MOUSEMOVE: u32 = 0x0002;
pub const QS_MOUSEBUTTON: u32 = 0x0004;
pub const QS_MOUSE: u32 = QS_MOUSEMOVE | QS_MOUSEBUTTON;
pub const QS_POSTMESSAGE: u32 = 0x0008;
pub const QS_TIMER: u32 = 0x0010;
pub const QS_PAINT: u32 = 0x0020;
pub const QS_SENDMESSAGE: u32 = 0x0040;
pub const QS_HOTKEY: u32 = 0x0080;
pub const QS_ALLPOSTMESSAGE: u32 = 0x0100;
pub const QS_RAWINPUT: u32 = 0x0400;
pub const QS_TOUCH: u32 = 0x0800;
pub const QS_POINTER: u32 = 0x1000;
pub const QS_INPUT: u32 = QS_MOUSE | QS_KEY | QS_RAWINPUT | QS_TOUCH | QS_POINTER;
pub const QS_ALLEVENTS: u32 = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY;
pub const QS_ALLINPUT: u32 = QS_ALLEVENTS | QS_SENDMESSAGE;
/// Requests the result of the last inter-thread send rather than a wake bit.
pub const QS_SMRESULT: u32 = 0x8000;
/// Bits a posted message carries.
pub const QS_POSTED: u32 = QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;

use super::hardware::{WM_KEYFIRST, WM_KEYLAST, WM_MOUSEMOVE, WM_NCMOUSEMOVE};

const WM_INPUT_DEVICE_CHANGE: u32 = 0x00fe;
const WM_INPUT: u32 = 0x00ff;
const WM_POINTERUPDATE: u32 = 0x0245;
const WM_POINTERLEAVE: u32 = 0x024a;

/// Wake bit one hardware message contributes. # C: O(1)
pub const fn hardware_bit(message: u32) -> u32 {
    if message >= WM_POINTERUPDATE && message <= WM_POINTERLEAVE { return QS_POINTER; }
    if message == WM_INPUT_DEVICE_CHANGE || message == WM_INPUT { return QS_RAWINPUT; }
    if message == WM_MOUSEMOVE || message == WM_NCMOUSEMOVE { return QS_MOUSEMOVE; }
    if message >= WM_KEYFIRST && message <= WM_KEYLAST { return QS_KEY; }
    QS_MOUSEBUTTON
}

/// Thread-state classes, in the order the query enumerates them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadState {
    FocusWindow, ActiveWindow, CaptureWindow, DefaultImeWindow, DefaultInputContext,
    InputState, Cursor, ExtraInfo, InSendMessage, MessageTime, IsForeground,
}

/// # C: O(1)
pub const fn thread_state(code: u32) -> Option<ThreadState> {
    Some(match code {
        0 => ThreadState::FocusWindow, 1 => ThreadState::ActiveWindow, 2 => ThreadState::CaptureWindow,
        3 => ThreadState::DefaultImeWindow, 4 => ThreadState::DefaultInputContext, 5 => ThreadState::InputState,
        6 => ThreadState::Cursor, 7 => ThreadState::ExtraInfo, 8 => ThreadState::InSendMessage,
        9 => ThreadState::MessageTime, 10 => ThreadState::IsForeground,
        _ => return None,
    })
}

/// Pack the reported bits: changed in the low half, wake in the high half.
/// # C: O(1)
pub const fn queue_status_result(changed: u32, wake: u32, flags: u32) -> u32 {
    ((changed & flags) & 0xffff) | (((wake & flags) & 0xffff) << 16)
}

impl MessageQueue {
    /// # C: O(N_messages)
    pub(super) fn wake_bits(&self) -> u32 {
        let queued = self.messages.iter().fold(0, |bits, entry| bits | entry.bits);
        queued | if self.quit_pending() { QS_POSTED } else { 0 }
    }
    /// Clear posted changes only when neither posted entries nor quit remain. # C: O(N_messages)
    pub(super) fn clear_drained_posted(&mut self) {
        if !self.quit_pending() && !self.messages.iter().any(|entry| entry.bits & QS_POSTED != 0) { self.changed &= !QS_POSTED; }
    }
    /// # C: O(1)
    pub(super) fn changed_bits(&self) -> u32 { self.changed }
    /// # C: O(1)
    pub(super) fn clear_changed(&mut self, bits: u32) { self.changed &= !bits; }
}

impl WindowManager {
    /// Wake and changed bits for one thread's queue, clearing the reported
    /// changed bits. Answers zero when the flags name bits outside the query's
    /// admitted set. # C: O(N_queues + N_messages + N_windows)
    pub fn queue_status(&mut self, tid: u64, flags: u32) -> Option<u32> {
        if flags & !(QS_ALLINPUT | QS_ALLPOSTMESSAGE | QS_SMRESULT) != 0 { return None; }
        let paint = self.thread_has_pending_paint(tid);
        let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) else { return Some(0); };
        let wake = queue.wake_bits() | if paint { QS_PAINT } else { 0 };
        let changed = queue.changed_bits() | if paint { QS_PAINT } else { 0 };
        queue.clear_changed(flags);
        Some(queue_status_result(changed, wake, flags))
    }

    /// Key and mouse-button wake bits, which the input-state class reports.
    /// # C: O(N_queues + N_messages)
    pub fn input_state(&self, tid: u64) -> u32 {
        self.queues.iter().find(|(owner, _)| *owner == tid)
            .map_or(0, |(_, queue)| queue.wake_bits() & (QS_KEY | QS_MOUSEBUTTON))
    }

    /// # C: O(N_windows)
    fn thread_has_pending_paint(&self, tid: u64) -> bool {
        self.dirty_windows().into_iter().any(|id| self.get(id).is_some_and(|record| record.owner_tid == tid))
    }

    /// Windows carrying undrawn damage. # C: O(N_dirty)
    pub fn dirty_windows(&self) -> alloc::vec::Vec<WindowId> {
        self.dirty.iter().map(|(id, _)| *id).collect()
    }

    /// Status bits pending for one thread, including a deferred paint.
    /// # C: O(N_queues + N_messages + N_windows)
    pub fn pending_status(&self, tid: u64) -> u32 {
        let queued = self.queues.iter().find(|(owner, _)| *owner == tid).map_or(0, |(_, queue)| queue.wake_bits());
        queued | if self.thread_has_pending_paint(tid) { QS_PAINT } else { 0 }
    }
    /// Whether any pending class satisfies a requested wait mask. # C: O(N_queues + N_messages + N_windows)
    pub fn queue_satisfies(&self, tid: u64, mask: u32) -> bool { self.pending_status(tid) & mask != 0 }
}

#[cfg(test)]
#[path = "tests/queue_status.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/posted_status.rs"]
mod posted_tests;

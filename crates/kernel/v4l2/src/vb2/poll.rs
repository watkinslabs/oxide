//! Readiness of a video device for `poll(2)`, `select(2)` and `epoll(7)`.

use super::queue::Queue;
use super::state::BufState;
use crate::uapi::flags;

/// `POLLERR`.
pub const POLL_ERR: u32 = 0x0008;
/// `POLLIN | POLLRDNORM`.
pub const POLL_IN: u32 = 0x0001 | 0x0040;
/// `POLLOUT | POLLWRNORM`.
pub const POLL_OUT: u32 = 0x0004 | 0x0100;
/// `POLLPRI`, which is how a V4L2 event announces itself — never `POLLIN`, so
/// a program can wait for events without waking on every captured frame.
pub const POLL_PRI: u32 = 0x0002;

/// Readiness contributed by the buffer queue.
///
/// A queue that is not streaming, or that has failed, is an error rather than
/// merely not-ready: a program that polls a stopped device must be woken and
/// told, not left waiting for a frame that will never come.
///
/// The end-of-stream case reads as readable even with nothing on the done
/// list, so the `DQBUF` it provokes can return `EPIPE` and the application
/// learns the stream ended.
/// # C: O(1)
pub fn queue_mask(q: &Queue) -> u32 {
    if q.error { return POLL_ERR; }
    if !q.streaming {
        // A queue with no buffers has nothing to report either way; the
        // reference answers an error so a poll on an unconfigured device does
        // not hang.
        return POLL_ERR;
    }
    let ready = if flags::is_output(q.buf_type) { POLL_OUT } else { POLL_IN };
    if q.done.is_empty() {
        if q.last_buffer_dequeued { return ready; }
        return 0;
    }
    match q.done.front().and_then(|i| q.buffer(*i)).map(|b| b.state) {
        Some(BufState::Done) | Some(BufState::Error) => ready,
        _ => 0,
    }
}

/// Full readiness of one open file description: the queue's, plus `POLLPRI`
/// when an event is waiting for this handle. # C: O(1)
pub fn poll_mask(q: &Queue, event_pending: bool) -> u32 {
    let mut mask = queue_mask(q);
    if event_pending { mask |= POLL_PRI; }
    mask
}

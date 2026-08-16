//! Starting and stopping the stream, and the completion path the driver
//! calls into.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::flags;
use super::queue::{Owner, Queue};
use super::state::{cancelled_state, completion_target, BufState};

/// `VIDIOC_STREAMON`.
///
/// Starting a stream that is already running is not an error — the reference
/// returns success and does nothing, and applications rely on that to make
/// their start path idempotent. What is refused is starting with too few
/// buffers queued, because the device would run dry immediately.
///
/// Returns the buffers that must be handed to the driver, in queue order.
/// # C: O(queued)
pub fn streamon(q: &mut Queue, who: Owner, buf_type: u32) -> Result<Vec<u32>, Errno> {
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    if q.streaming { return Ok(Vec::new()); }
    if !q.is_busy() { return Err(Errno::Einval); }
    if (q.queued.len() as u32) < q.min_queued_buffers { return Err(Errno::Einval); }
    q.streaming = true;
    q.last_buffer_dequeued = false;
    let handoff: Vec<u32> = q.queued.iter().copied().collect();
    q.queued.clear();
    for index in handoff.iter() {
        if let Some(buf) = q.buffer_mut(*index) { buf.state = BufState::Active; }
    }
    Ok(handoff)
}

/// Undo a `start_streaming` the driver refused: every buffer it was given goes
/// back to `Queued` rather than to an error state, so the caller's pool is
/// intact and a second `STREAMON` can use it unchanged.
/// # C: O(buffers)
pub fn streamon_failed(q: &mut Queue, handed: &[u32]) {
    q.streaming = false;
    for index in handed.iter().rev() {
        if let Some(buf) = q.buffer_mut(*index) { buf.state = BufState::Queued; }
        q.queued.push_front(*index);
    }
}

/// `VIDIOC_STREAMOFF`.
///
/// Unconditional: it succeeds whether or not the queue was streaming, and it
/// returns every buffer to userspace whatever state it was in. A buffer left
/// behind in any other state is one the application can never get back.
/// # C: O(buffers)
pub fn streamoff(q: &mut Queue, who: Owner, buf_type: u32) -> Result<(), Errno> {
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    cancel(q);
    Ok(())
}

/// Return every buffer to userspace and clear both lists. Shared by
/// `STREAMOFF`, by a `REQBUFS` that reallocates, and by the last close of the
/// owning file description.
/// # C: O(buffers)
pub fn cancel(q: &mut Queue) {
    q.streaming = false;
    q.error = false;
    q.last_buffer_dequeued = false;
    q.queued.clear();
    q.done.clear();
    for buf in q.bufs.iter_mut() {
        buf.state = cancelled_state(buf.state);
        buf.prepared = false;
        buf.flags &= !(flags::BUF_FLAG_QUEUED | flags::BUF_FLAG_DONE
                       | flags::BUF_FLAG_ERROR | flags::BUF_FLAG_PREPARED
                       | flags::BUF_FLAG_LAST);
        for plane in buf.planes.iter_mut() { plane.bytesused = 0; }
    }
}

/// What a driver reports when it finishes with a buffer.
#[derive(Copy, Clone, Debug)]
pub struct Completion {
    pub index: u32,
    /// `Done`, `Error`, or `Queued` to return a buffer unused.
    pub state: BufState,
    /// Payload per plane, index-parallel with the buffer's planes.
    pub bytesused: [u32; crate::uapi::layout::MAX_PLANES],
    /// Monotonic nanoseconds the frame is stamped with.
    pub timestamp_ns: u64,
    /// The driver's own frame counter.
    pub sequence: u32,
    pub field: u32,
    /// Set on the final buffer of a stream, so the next `DQBUF` after it
    /// reports `EPIPE` instead of blocking forever.
    pub last: bool,
}

/// The driver finished with a buffer.
///
/// Returns `true` when the buffer landed on the done list, which is the signal
/// to wake anyone waiting in `DQBUF` and to raise the read-readiness of every
/// poller. A completion reported for a buffer the driver was not holding is
/// forced to the error state rather than trusted, because acting on it would
/// corrupt the done list.
/// # C: O(planes)
pub fn buffer_done(q: &mut Queue, c: &Completion) -> bool {
    let Some(buf) = q.buffer_mut(c.index) else { return false };
    let target = completion_target(buf.state, c.state);
    if target == BufState::Queued {
        buf.state = BufState::Queued;
        q.queued.push_back(c.index);
        return false;
    }
    for (i, plane) in buf.planes.iter_mut().enumerate() {
        let used = c.bytesused[i.min(crate::uapi::layout::MAX_PLANES - 1)];
        plane.bytesused = used.min(plane.length);
    }
    buf.state = target;
    buf.timestamp_ns = c.timestamp_ns;
    buf.sequence = c.sequence;
    buf.field = c.field;
    if c.last { buf.flags |= flags::BUF_FLAG_LAST; }
    q.done.push_back(c.index);
    true
}

/// Mark the queue failed. Every command that would otherwise block now
/// returns `EIO`, and pollers see an error rather than hanging.
/// # C: O(1)
pub fn set_error(q: &mut Queue) { q.error = true; }

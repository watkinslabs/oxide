//! Handing buffers to the device and taking them back: `PREPARE_BUF`, `QBUF`
//! and `DQBUF`.

use syscall::errno::Errno;

use crate::uapi::flags;
use super::queue::{Owner, Queue};
use super::state::{may_prepare, may_queue, BufState};

/// What the caller told the queue about one plane of a buffer being queued.
#[derive(Copy, Clone, Debug, Default)]
pub struct PlaneIn {
    pub bytesused: u32,
    pub length: u32,
    pub userptr: u64,
    pub dmabuf_fd: i32,
    pub data_offset: u32,
}

/// A `QBUF`/`PREPARE_BUF` request, after the wire form is decoded.
#[derive(Clone, Debug)]
pub struct QbufIn {
    pub index: u32,
    pub buf_type: u32,
    pub memory: u32,
    pub field: u32,
    pub flags: u32,
    pub planes: [PlaneIn; crate::uapi::layout::MAX_PLANES],
    pub num_planes: usize,
    /// Payload of a single-planar buffer, which carries no plane array.
    pub bytesused: u32,
}

/// Common admission checks for a command naming one buffer.
///
/// Ordering matters and is the reference's: the buffer type is wrong before
/// the index is out of range, and both come before the memory model, so a
/// program probing a device gets the same answer here as it would from Linux.
/// # C: O(1)
fn resolve(q: &Queue, buf_type: u32, memory: Option<u32>, index: u32) -> Result<(), Errno> {
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    if index >= q.num_buffers() { return Err(Errno::Einval); }
    if let Some(m) = memory {
        if m != q.memory { return Err(Errno::Einval); }
    }
    Ok(())
}

/// Copy the caller's per-plane description onto the buffer for the memory
/// models where userspace supplies the memory. In the MMAP model the queue
/// owns the pages and the caller's plane words are advisory only.
/// # C: O(planes)
fn take_planes(q: &mut Queue, index: u32, req: &QbufIn) -> Result<(), Errno> {
    let memory = q.memory;
    let Some(buf) = q.buffer_mut(index) else { return Err(Errno::Einval) };
    let multi = flags::is_multiplanar(req.buf_type);
    if multi && req.num_planes != buf.planes.len() { return Err(Errno::Einval); }
    for (i, plane) in buf.planes.iter_mut().enumerate() {
        let incoming = if multi { req.planes[i] } else {
            PlaneIn { bytesused: req.bytesused, length: plane.length, ..PlaneIn::default() }
        };
        match memory {
            flags::MEMORY_USERPTR => {
                let src = if multi { incoming.userptr } else { req.planes[0].userptr };
                if src == 0 { return Err(Errno::Einval); }
                let len = if multi { incoming.length } else { req.planes[0].length };
                if len < plane.length { return Err(Errno::Einval); }
                plane.userptr = src;
                plane.length = len;
            }
            flags::MEMORY_DMABUF => {
                let fd = if multi { incoming.dmabuf_fd } else { req.planes[0].dmabuf_fd };
                if fd < 0 { return Err(Errno::Einval); }
                plane.dmabuf_fd = fd;
            }
            _ => {}
        }
        // An output buffer's payload comes from the caller and cannot exceed
        // the plane. A capture buffer's payload is written by the device, so
        // whatever the caller put here is discarded.
        if flags::is_output(req.buf_type) {
            if incoming.bytesused > plane.length { return Err(Errno::Einval); }
            plane.bytesused = incoming.bytesused;
        } else {
            plane.bytesused = 0;
        }
        plane.data_offset = incoming.data_offset;
    }
    Ok(())
}

/// `VIDIOC_PREPARE_BUF`: do the per-buffer work `QBUF` would do, without
/// giving the buffer to the device, so the cost is paid off the streaming path.
/// # C: O(planes)
pub fn prepare_buf(q: &mut Queue, who: Owner, req: &QbufIn) -> Result<(), Errno> {
    prepare_buf_with(q, who, req, || Ok(()))
}

/// `PREPARE_BUF` with the driver's per-buffer validation inserted after the
/// queue's own admission checks and before any queue state is changed.
/// # C: O(planes)
pub fn prepare_buf_with(
    q: &mut Queue, who: Owner, req: &QbufIn,
    prepare: impl FnOnce() -> Result<(), Errno>,
) -> Result<(), Errno> {
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    resolve(q, req.buf_type, Some(req.memory), req.index)?;
    if q.error { return Err(Errno::Eio); }
    let state = q.buffer(req.index).map(|b| b.state).ok_or(Errno::Einval)?;
    may_prepare(state)?;
    // A buffer already prepared is refused even though its state is still the
    // caller's: the preparation would be done twice, and on a memory model
    // where it pins pages that is a leak.
    if q.buffer(req.index).map(|b| b.prepared).unwrap_or(false) { return Err(Errno::Einval); }
    prepare()?;
    take_planes(q, req.index, req)?;
    if let Some(buf) = q.buffer_mut(req.index) {
        buf.prepared = true;
        buf.flags |= flags::BUF_FLAG_PREPARED;
    }
    Ok(())
}

/// `VIDIOC_QBUF`. Returns `true` when the buffer must be handed to the driver
/// straight away, which is the case whenever the queue is already streaming.
/// # C: O(planes)
pub fn qbuf(q: &mut Queue, who: Owner, req: &QbufIn) -> Result<bool, Errno> {
    qbuf_with(q, who, req, || Ok(()))
}

/// `QBUF` with the driver's per-buffer validation inserted after the queue's
/// own admission checks and before any queue state is changed.
/// # C: O(planes)
pub fn qbuf_with(
    q: &mut Queue, who: Owner, req: &QbufIn,
    prepare: impl FnOnce() -> Result<(), Errno>,
) -> Result<bool, Errno> {
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    resolve(q, req.buf_type, Some(req.memory), req.index)?;
    if q.error { return Err(Errno::Eio); }
    let state = q.buffer(req.index).map(|b| b.state).ok_or(Errno::Einval)?;
    may_queue(state)?;
    let already_prepared = q.buffer(req.index).map(|b| b.prepared).unwrap_or(false);
    if !already_prepared { prepare()?; }
    if !already_prepared { take_planes(q, req.index, req)?; }
    let field = req.field;
    if let Some(buf) = q.buffer_mut(req.index) {
        buf.state = BufState::Queued;
        buf.prepared = true;
        buf.flags = (buf.flags & !flags::BUF_FLAG_DONE) | flags::BUF_FLAG_PREPARED;
        if flags::is_output(req.buf_type) { buf.field = field; }
    }
    q.queued.push_back(req.index);
    Ok(q.streaming)
}

/// The admission ladder a `DQBUF` walks before it can look at the done list.
///
/// `Ok(Some(index))` — take that buffer. `Ok(None)` — nothing ready and the
/// caller may block. Everything else is the error the reference returns, in
/// the reference's order: a second waiter first, then streaming state, then
/// the queue's error, then the end-of-stream marker, and only then the
/// emptiness that a non-blocking caller sees as `EAGAIN`.
/// # C: O(1)
pub fn dqbuf_ready(q: &Queue, nonblocking: bool) -> Result<Option<u32>, Errno> {
    if q.waiting_in_dqbuf { return Err(Errno::Ebusy); }
    if !q.streaming { return Err(Errno::Einval); }
    if q.error { return Err(Errno::Eio); }
    if q.last_buffer_dequeued { return Err(Errno::Epipe); }
    if let Some(index) = q.done.front() { return Ok(Some(*index)); }
    if nonblocking { return Err(Errno::Eagain); }
    Ok(None)
}

/// Take the buffer at the head of the done list.
///
/// A buffer that completed with an error is still handed back: the failure
/// travels as `V4L2_BUF_FLAG_ERROR` on a successful `DQBUF`, because losing
/// the buffer would leak it out of the pool.
/// # C: O(planes)
pub fn dqbuf(q: &mut Queue, who: Owner, buf_type: u32) -> Result<u32, Errno> {
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    let index = q.done.pop_front().ok_or(Errno::Eagain)?;
    let last = {
        let Some(buf) = q.buffer_mut(index) else { return Err(Errno::Einval) };
        if !buf.state.is_done() { return Err(Errno::Einval); }
        buf.state = BufState::Dequeued;
        buf.prepared = false;
        buf.flags &= !(flags::BUF_FLAG_PREPARED | flags::BUF_FLAG_QUEUED);
        buf.flags & flags::BUF_FLAG_LAST != 0
    };
    if last { q.last_buffer_dequeued = true; }
    Ok(index)
}

/// `VIDIOC_QUERYBUF`: report a buffer without changing it. # C: O(1)
pub fn querybuf(q: &Queue, buf_type: u32, index: u32) -> Result<&super::queue::Buffer, Errno> {
    resolve(q, buf_type, None, index)?;
    q.buffer(index).ok_or(Errno::Einval)
}

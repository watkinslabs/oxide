//! The buffer-queue command set.

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::device::FileHandle;
use crate::uapi::flags;
use crate::uapi::layout as l;
use crate::usermem::{r32, r64, w32, w64, zero};
use crate::vb2::{self, PlaneIn, QbufIn};
use super::Ctx;

/// Decode the caller's `v4l2_buffer`. The plane array a multi-planar buffer
/// points at is read through the caller's memory, which is the one place this
/// command follows a pointer.
/// # C: O(planes)
fn read_buffer(arg: &[u8], ctx: &dyn Ctx) -> Result<QbufIn, Errno> {
    let buf_type = r32(arg, l::BUF_TYPE);
    let mut req = QbufIn {
        index: r32(arg, l::BUF_INDEX),
        buf_type,
        memory: r32(arg, l::BUF_MEMORY),
        field: r32(arg, l::BUF_FIELD),
        flags: r32(arg, l::BUF_FLAGS),
        planes: [PlaneIn::default(); l::MAX_PLANES],
        num_planes: 1,
        bytesused: r32(arg, l::BUF_BYTESUSED),
    };
    let m = r64(arg, l::BUF_M);
    if flags::is_multiplanar(buf_type) {
        let count = r32(arg, l::BUF_LENGTH) as usize;
        if count == 0 || count > l::MAX_PLANES { return Err(Errno::Einval); }
        req.num_planes = count;
        let mut raw = [0u8; l::PLANE_SIZE * l::MAX_PLANES];
        let span = l::PLANE_SIZE * count;
        ctx.user().read(m, &mut raw[..span])?;
        for i in 0..count {
            let p = &raw[i * l::PLANE_SIZE..];
            req.planes[i] = PlaneIn {
                bytesused: r32(p, l::PLANE_BYTESUSED),
                length: r32(p, l::PLANE_LENGTH),
                userptr: r64(p, l::PLANE_M),
                dmabuf_fd: r64(p, l::PLANE_M) as i32,
                data_offset: r32(p, l::PLANE_DATA_OFFSET),
            };
        }
    } else {
        req.planes[0] = PlaneIn {
            bytesused: req.bytesused,
            length: r32(arg, l::BUF_LENGTH),
            userptr: m,
            dmabuf_fd: m as i32,
            data_offset: 0,
        };
    }
    Ok(req)
}

/// Encode one buffer back into the caller's `v4l2_buffer`, and into the plane
/// array when the buffer is multi-planar.
/// # C: O(planes)
fn write_buffer(arg: &mut [u8], buf: &vb2::Buffer, queue: &vb2::Queue, ctx: &dyn Ctx)
    -> Result<(), Errno>
{
    let multi = flags::is_multiplanar(queue.buf_type);
    w32(arg, l::BUF_INDEX, buf.index);
    w32(arg, l::BUF_TYPE, queue.buf_type);
    w32(arg, l::BUF_FIELD, buf.field);
    w32(arg, l::BUF_SEQUENCE, buf.sequence);
    w32(arg, l::BUF_MEMORY, queue.memory);
    // `timestamp` is a `struct timeval`: whole seconds and microseconds, so a
    // nanosecond stamp loses its last three digits crossing the ABI.
    w64(arg, l::BUF_TIMESTAMP_SEC, buf.timestamp_ns / 1_000_000_000);
    w64(arg, l::BUF_TIMESTAMP_USEC, (buf.timestamp_ns % 1_000_000_000) / 1_000);
    zero(arg, l::BUF_TIMECODE, l::BUF_TIMECODE_LEN);
    w32(arg, l::BUF_RESERVED2, 0);
    w32(arg, l::BUF_REQUEST_FD, 0);

    let mut reported = buf.flags | buf.state.user_flags() | queue.timestamp_flags;
    if buf.is_mapped() { reported |= flags::BUF_FLAG_MAPPED; }
    w32(arg, l::BUF_FLAGS, reported);

    if multi {
        let m = r64(arg, l::BUF_M);
        let count = buf.planes.len().min(l::MAX_PLANES);
        w32(arg, l::BUF_LENGTH, count as u32);
        w32(arg, l::BUF_BYTESUSED, 0);
        let mut raw = [0u8; l::PLANE_SIZE * l::MAX_PLANES];
        for (i, plane) in buf.planes.iter().take(count).enumerate() {
            let p = &mut raw[i * l::PLANE_SIZE..(i + 1) * l::PLANE_SIZE];
            w32(p, l::PLANE_BYTESUSED, plane.bytesused);
            w32(p, l::PLANE_LENGTH, plane.length);
            let cookie = match queue.memory {
                flags::MEMORY_MMAP => plane.offset as u64,
                flags::MEMORY_USERPTR => plane.userptr,
                flags::MEMORY_DMABUF => plane.dmabuf_fd as u32 as u64,
                _ => 0,
            };
            w64(p, l::PLANE_M, cookie);
            w32(p, l::PLANE_DATA_OFFSET, plane.data_offset);
        }
        ctx.user().write(m, &raw[..count * l::PLANE_SIZE])?;
        return Ok(());
    }
    let plane = buf.planes.first().ok_or(Errno::Einval)?;
    w32(arg, l::BUF_BYTESUSED, plane.bytesused);
    w32(arg, l::BUF_LENGTH, plane.length);
    let cookie = match queue.memory {
        flags::MEMORY_MMAP => plane.offset as u64,
        flags::MEMORY_USERPTR => plane.userptr,
        flags::MEMORY_DMABUF => plane.dmabuf_fd as u32 as u64,
        _ => 0,
    };
    w64(arg, l::BUF_M, cookie);
    Ok(())
}

/// `VIDIOC_REQBUFS`. # C: O(buffers)
pub fn reqbufs(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::REQUESTBUFFERS_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let count = r32(arg, l::REQBUFS_COUNT);
    let buf_type = r32(arg, l::REQBUFS_TYPE);
    let memory = r32(arg, l::REQBUFS_MEMORY);
    let alloc = device.alloc.clone();
    let ops = device.ops.clone();
    let made = {
        let mut state = device.state.lock();
        let format = state.format;
        if state.queue.streaming { ops.stop_streaming(); }
        let setup = |want: u32| ops.queue_setup(want, &format);
        vb2::reqbufs::reqbufs(&mut state.queue, handle.id, buf_type, memory, count,
                              setup, alloc.as_ref())?
    };
    let state = device.state.lock();
    w32(arg, l::REQBUFS_COUNT, made);
    w32(arg, l::REQBUFS_CAPABILITIES, state.queue.supported_caps);
    crate::usermem::w8(arg, l::REQBUFS_FLAGS, 0);
    zero(arg, l::REQBUFS_RESERVED, l::REQBUFS_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_CREATE_BUFS`. # C: O(count)
pub fn create_bufs(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CREATE_BUFFERS_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let count = r32(arg, l::CREATE_COUNT);
    let memory = r32(arg, l::CREATE_MEMORY);
    let buf_type = r32(arg, l::CREATE_FORMAT + l::FORMAT_TYPE);
    let alloc = device.alloc.clone();
    let ops = device.ops.clone();
    let (first, made) = {
        let mut state = device.state.lock();
        let format = state.format;
        let setup = |want: u32| ops.queue_setup(want, &format);
        vb2::reqbufs::create_bufs(&mut state.queue, handle.id, buf_type, memory, count,
                                  setup, alloc.as_ref())?
    };
    let state = device.state.lock();
    w32(arg, l::CREATE_INDEX, first);
    w32(arg, l::CREATE_COUNT, made);
    w32(arg, l::CREATE_CAPABILITIES, state.queue.supported_caps);
    w32(arg, l::CREATE_MAX_NUM_BUFFERS, state.queue.max_num_buffers);
    zero(arg, l::CREATE_RESERVED, l::CREATE_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_QUERYBUF`. # C: O(planes)
pub fn querybuf(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::BUFFER_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let state = device.state.lock();
    let buf = vb2::qbuf::querybuf(&state.queue, r32(arg, l::BUF_TYPE), r32(arg, l::BUF_INDEX))?
        .clone();
    write_buffer(arg, &buf, &state.queue, ctx)
}

/// `VIDIOC_PREPARE_BUF`. # C: O(planes)
pub fn prepare_buf(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::BUFFER_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let req = read_buffer(arg, ctx)?;
    let mut state = device.state.lock();
    vb2::qbuf::prepare_buf_with(&mut state.queue, handle.id, &req,
                                || device.ops.buf_prepare(req.index))?;
    let buf = state.queue.buffer(req.index).cloned().ok_or(Errno::Einval)?;
    write_buffer(arg, &buf, &state.queue, ctx)
}

/// `VIDIOC_QBUF`. # C: O(planes)
pub fn qbuf(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::BUFFER_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let req = read_buffer(arg, ctx)?;
    let (hand_off, buf) = {
        let mut state = device.state.lock();
        let hand_off = vb2::qbuf::qbuf_with(
            &mut state.queue, handle.id, &req,
            || device.ops.buf_prepare(req.index))?;
        if hand_off {
            if let Some(b) = state.queue.buffer_mut(req.index) { b.state = vb2::BufState::Active; }
            state.queue.queued.retain(|i| *i != req.index);
        }
        let buf = state.queue.buffer(req.index).cloned().ok_or(Errno::Einval)?;
        (hand_off, buf)
    };
    if hand_off { device.ops.buf_queue(req.index); }
    let state = device.state.lock();
    write_buffer(arg, &buf, &state.queue, ctx)
}

/// `VIDIOC_DQBUF`, including the wait a blocking caller does.
///
/// The wait is a loop rather than a single sleep: a wake-up does not prove a
/// buffer is there — a `STREAMOFF` from another thread wakes the same queue —
/// so the admission ladder is re-walked every time round, and it is the ladder
/// that produces the `EINVAL` such a caller must get.
/// # C: O(planes), blocking
pub fn dqbuf(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::BUFFER_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let buf_type = r32(arg, l::BUF_TYPE);
    loop {
        {
            let state = device.state.lock();
            match vb2::qbuf::dqbuf_ready(&state.queue, ctx.nonblocking())? {
                Some(_) => {}
                None => {
                    drop(state);
                    // Publish the wait before sleeping. The reference keys two
                    // rules on it — a second `DQBUF` is `EBUSY`, and a
                    // `REQBUFS` that would free the buffers out from under
                    // this reader is refused — and neither can fire unless the
                    // waiter marks itself.
                    device.state.lock().queue.waiting_in_dqbuf = true;
                    let waited = ctx.wait_for_buffer(&device);
                    device.state.lock().queue.waiting_in_dqbuf = false;
                    waited?;
                    continue;
                }
            }
        }
        let mut state = device.state.lock();
        // The buffer is described BEFORE it is taken off the done list: the
        // completed state is what carries `V4L2_BUF_FLAG_DONE` and, on a
        // failure, `V4L2_BUF_FLAG_ERROR`, and reporting after the transition
        // would hand the caller a buffer that looks as though nothing had
        // happened to it.
        let snapshot = state.queue.done.front()
            .and_then(|i| state.queue.buffer(*i))
            .cloned();
        // The head can be taken by another thread between the check and here;
        // an empty list simply means someone else won, so wait again rather
        // than reporting an error the caller did not earn.
        let index = match vb2::qbuf::dqbuf(&mut state.queue, handle.id, buf_type) {
            Ok(index) => index,
            Err(Errno::Eagain) if !ctx.nonblocking() => {
                drop(state);
                device.state.lock().queue.waiting_in_dqbuf = true;
                let waited = ctx.wait_for_buffer(&device);
                device.state.lock().queue.waiting_in_dqbuf = false;
                waited?;
                continue;
            }
            Err(e) => return Err(e),
        };
        let buf = snapshot.filter(|b| b.index == index).ok_or(Errno::Einval)?;
        return write_buffer(arg, &buf, &state.queue, ctx);
    }
}

/// `VIDIOC_STREAMON`. # C: O(queued)
pub fn streamon(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let buf_type = r32(arg, 0);
    let handed: Vec<u32> = {
        let mut state = device.state.lock();
        vb2::stream::streamon(&mut state.queue, handle.id, buf_type)?
    };
    if handed.is_empty() { return Ok(()); }
    if let Err(e) = device.ops.start_streaming(&handed) {
        let mut state = device.state.lock();
        vb2::stream::streamon_failed(&mut state.queue, &handed);
        return Err(e);
    }
    ctx.wake(&device);
    Ok(())
}

/// `VIDIOC_STREAMOFF`. # C: O(buffers)
pub fn streamoff(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let buf_type = r32(arg, 0);
    let was_streaming = {
        let state = device.state.lock();
        if buf_type != state.queue.buf_type { return Err(Errno::Einval); }
        state.queue.streaming
    };
    // The transport stops before the buffers are reclaimed, so it cannot
    // complete into one the caller already owns again.
    if was_streaming { device.ops.stop_streaming(); }
    {
        let mut state = device.state.lock();
        vb2::stream::streamoff(&mut state.queue, handle.id, buf_type)?;
    }
    // Anyone parked in `DQBUF` must be woken to discover the queue stopped;
    // without this they wait for a frame that will never arrive.
    ctx.wake(&device);
    Ok(())
}

/// `VIDIOC_REMOVE_BUFS`, which reuses the `v4l2_requestbuffers` layout's first
/// two words as index and count. # C: O(count)
pub fn remove_bufs(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::REQUESTBUFFERS_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let index = r32(arg, 0);
    let count = r32(arg, 4);
    let alloc = device.alloc.clone();
    let mut state = device.state.lock();
    if state.queue.owner != Some(handle.id) { return Err(Errno::Ebusy); }
    vb2::reqbufs::remove_bufs(&mut state.queue, index, count, alloc.as_ref())
}

/// `VIDIOC_EXPBUF`: export one plane as a descriptor another subsystem can
/// import.
///
/// There is no descriptor exporter for these pages yet, so this refuses rather
/// than handing back a descriptor that names nothing. `EINVAL` is what the
/// reference returns on a queue whose memory model does not support exporting,
/// and it is the answer an application already handles by falling back to the
/// mapped model.
/// # C: O(1)
pub fn expbuf(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::EXPORTBUFFER_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let state = device.state.lock();
    if r32(arg, l::EXPBUF_TYPE) != state.queue.buf_type { return Err(Errno::Einval); }
    if r32(arg, l::EXPBUF_INDEX) >= state.queue.num_buffers() { return Err(Errno::Einval); }
    Err(Errno::Einval)
}

//! Allocating and freeing the queue's buffers: `REQBUFS`, `CREATE_BUFS` and
//! the teardown both share.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::flags;
use super::queue::{Buffer, Plane, PlaneAlloc, Queue, QueueSetup, Owner, MAX_BUFFERS};
use super::state::BufState;

/// Is `memory` a model this queue supports?
///
/// The reference answers `EINVAL` for a memory model the driver did not
/// declare, and for the overlay model on any queue that is not an overlay —
/// which is every queue here. A program probing capabilities relies on that
/// being `EINVAL` and not, say, `ENOTTY`, because it distinguishes "this
/// device cannot do USERPTR" from "this device is not V4L2".
/// # C: O(1)
pub fn verify_memory(q: &Queue, memory: u32) -> Result<(), Errno> {
    let bit = match memory {
        flags::MEMORY_MMAP => flags::BUF_CAP_SUPPORTS_MMAP,
        flags::MEMORY_USERPTR => flags::BUF_CAP_SUPPORTS_USERPTR,
        flags::MEMORY_DMABUF => flags::BUF_CAP_SUPPORTS_DMABUF,
        _ => return Err(Errno::Einval),
    };
    if q.supported_caps & bit == 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Free every buffer, returning the queue to the unallocated state.
///
/// A plane userspace still maps is orphaned rather than kept: the queue drops
/// its own reference and forgets the frames, and the pages die when the last
/// mapping does. Refusing the free instead would let a program that leaked a
/// mapping wedge the device forever.
/// # C: O(buffers * planes)
pub fn free_buffers(q: &mut Queue, alloc: &dyn PlaneAlloc) {
    for buf in q.bufs.iter_mut() {
        for plane in buf.planes.iter_mut() {
            if !plane.frames.is_empty() { alloc.free(&plane.frames); }
            plane.frames = Vec::new();
        }
    }
    q.bufs.clear();
    q.queued.clear();
    q.done.clear();
    q.memory = 0;
    q.owner = None;
    q.last_buffer_dequeued = false;
    q.next_offset = 0;
}

/// Build `count` buffers of the shape `setup` describes, appending them after
/// whatever the queue already holds. # C: O(count * planes)
fn allocate(q: &mut Queue, setup: &QueueSetup, alloc: &dyn PlaneAlloc, memory: u32) -> Result<u32, Errno> {
    let page = alloc.page_bytes().max(1);
    let first = q.num_buffers();
    for i in 0..setup.count {
        let mut planes: Vec<Plane> = Vec::new();
        for p in 0..setup.num_planes {
            let size = setup.plane_sizes[p];
            let mut plane = Plane::new(size, q.next_offset);
            // Cookies advance by whole pages so a plane's offset is always a
            // legal `mmap(2)` offset and two planes never share a page.
            q.next_offset = q.next_offset.saturating_add(size.div_ceil(page).saturating_mul(page));
            if memory == flags::MEMORY_MMAP {
                match alloc.alloc(size) {
                    Some(frames) => plane.frames = frames,
                    None => {
                        // Undo this partial allocation: a queue left holding
                        // half a request would report buffers a caller cannot
                        // use.
                        for done in planes.iter() { alloc.free(&done.frames); }
                        q.bufs.truncate(first as usize);
                        return Err(Errno::Enomem);
                    }
                }
            }
            planes.push(plane);
        }
        q.bufs.push(Buffer::new(first + i, planes));
    }
    Ok(setup.count)
}

/// `VIDIOC_REQBUFS`.
///
/// A count of zero is not an error and not a query: it frees everything, which
/// is how a program releases a device it is done with. A non-zero count on a
/// queue that already has buffers replaces them, whatever memory model they
/// used — the mismatch a caller might expect to be refused is instead the
/// normal way of switching models.
/// # C: O(buffers * planes)
pub fn reqbufs(
    q: &mut Queue,
    who: Owner,
    buf_type: u32,
    memory: u32,
    count: u32,
    setup: impl FnOnce(u32) -> Result<QueueSetup, Errno>,
    alloc: &dyn PlaneAlloc,
) -> Result<u32, Errno> {
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    if q.streaming { return Err(Errno::Ebusy); }
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    verify_memory(q, memory)?;
    // Freeing buffers out from under a parked reader would strand it, so a
    // request that reallocates is refused while one is waiting. Freeing
    // everything is still allowed: that is the teardown path.
    if q.waiting_in_dqbuf && count != 0 { return Err(Errno::Ebusy); }

    free_buffers(q, alloc);
    if count == 0 {
        q.owner = None;
        return Ok(0);
    }
    let want = count.min(q.max_num_buffers.min(MAX_BUFFERS));
    let mut settled = setup(want)?;
    settled.count = settled.count.min(q.max_num_buffers.min(MAX_BUFFERS)).max(1);
    if settled.num_planes == 0 || settled.num_planes > crate::uapi::layout::MAX_PLANES {
        return Err(Errno::Einval);
    }
    q.memory = memory;
    let made = allocate(q, &settled, alloc, memory)?;
    q.owner = Some(who);
    Ok(made)
}

/// `VIDIOC_CREATE_BUFS`: add buffers without disturbing the ones already
/// allocated, so a program can grow its pool mid-stream. The index of the
/// first new buffer comes back to the caller.
/// # C: O(count * planes)
pub fn create_bufs(
    q: &mut Queue,
    who: Owner,
    buf_type: u32,
    memory: u32,
    count: u32,
    setup: impl FnOnce(u32) -> Result<QueueSetup, Errno>,
    alloc: &dyn PlaneAlloc,
) -> Result<(u32, u32), Errno> {
    if buf_type != q.buf_type { return Err(Errno::Einval); }
    if !q.owned_by(who) { return Err(Errno::Ebusy); }
    verify_memory(q, memory)?;
    // Mixing memory models within one allocation is meaningless: the queue has
    // one model at a time, and a second one would make `QBUF` ambiguous.
    if q.is_busy() && q.memory != memory { return Err(Errno::Einval); }
    if count == 0 { return Ok((q.num_buffers(), 0)); }

    let first = q.num_buffers();
    let headroom = q.max_num_buffers.min(MAX_BUFFERS).saturating_sub(first);
    if headroom == 0 { return Err(Errno::Enobufs); }
    let mut settled = setup(count.min(headroom))?;
    settled.count = settled.count.min(headroom);
    if settled.num_planes == 0 || settled.num_planes > crate::uapi::layout::MAX_PLANES {
        return Err(Errno::Einval);
    }
    q.memory = memory;
    let made = allocate(q, &settled, alloc, memory)?;
    q.owner = Some(who);
    Ok((first, made))
}

/// `VIDIOC_REMOVE_BUFS`: drop a contiguous run of buffers no one is using.
/// A buffer the queue or the driver still owns cannot go, or the driver would
/// complete into freed memory.
/// # C: O(count * planes)
pub fn remove_bufs(q: &mut Queue, index: u32, count: u32, alloc: &dyn PlaneAlloc) -> Result<(), Errno> {
    if count == 0 { return Err(Errno::Einval); }
    let end = index.checked_add(count).ok_or(Errno::Einval)?;
    if end > q.num_buffers() { return Err(Errno::Einval); }
    for i in index..end {
        let Some(buf) = q.buffer(i) else { return Err(Errno::Einval) };
        if buf.state != BufState::Dequeued { return Err(Errno::Ebusy); }
        if buf.is_mapped() { return Err(Errno::Ebusy); }
    }
    for i in index..end {
        if let Some(buf) = q.buffer_mut(i) {
            for plane in buf.planes.iter_mut() {
                if !plane.frames.is_empty() { alloc.free(&plane.frames); }
                plane.frames = Vec::new();
            }
        }
    }
    q.bufs.drain(index as usize..end as usize);
    // Indices are positional; renumber so `QUERYBUF` and `QBUF` keep naming
    // the buffer the application just saw enumerated.
    for (i, buf) in q.bufs.iter_mut().enumerate() { buf.index = i as u32; }
    let remaining = q.num_buffers();
    q.queued.retain(|i| *i < remaining);
    q.done.retain(|i| *i < remaining);
    Ok(())
}

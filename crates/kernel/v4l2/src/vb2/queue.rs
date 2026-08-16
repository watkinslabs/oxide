//! The buffer queue: its state, its buffers, and the plane allocator it
//! borrows memory from.
//!
//! The queue holds no lock of its own. Whoever owns the video device
//! serialises access, which is what lets every rule in this subtree be a plain
//! function tested without a kernel.

use alloc::vec::Vec;
use alloc::collections::VecDeque;

use super::state::BufState;

/// One plane of one buffer.
#[derive(Clone, Debug)]
pub struct Plane {
    /// Bytes the plane can hold.
    pub length: u32,
    /// Bytes the device wrote into it, set at completion.
    pub bytesused: u32,
    /// `mmap` cookie for this plane in the MMAP model: the offset a caller
    /// passes to `mmap(2)` to reach it.
    pub offset: u32,
    /// User address in the USERPTR model.
    pub userptr: u64,
    /// Exported descriptor in the DMABUF model, or `-1`.
    pub dmabuf_fd: i32,
    /// Bytes into the plane at which the payload starts.
    pub data_offset: u32,
    /// Frames backing the plane in the MMAP model, in page order. Refcounted
    /// kernel RAM: a user mapping of one takes a reference, so the queue
    /// freeing its own reference cannot free a page userspace still maps.
    pub frames: Vec<u64>,
    /// Does at least one live user mapping cover this plane?
    pub mapped: bool,
}

impl Plane {
    /// An unallocated plane of `length` bytes at mmap cookie `offset`.
    /// # C: O(1)
    pub fn new(length: u32, offset: u32) -> Self {
        Plane { length, bytesused: 0, offset, userptr: 0, dmabuf_fd: -1,
                data_offset: 0, frames: Vec::new(), mapped: false }
    }
}

/// One buffer of the queue.
#[derive(Clone, Debug)]
pub struct Buffer {
    pub index: u32,
    pub state: BufState,
    pub planes: Vec<Plane>,
    /// Nanoseconds since the monotonic epoch, stamped by the driver at
    /// completion. The queue never invents one: a timestamp the hardware did
    /// not produce is worse than none, because a program pacing on it cannot
    /// tell the difference.
    pub timestamp_ns: u64,
    /// Frame counter, also driver-maintained. A gap in it is how an
    /// application learns frames were dropped.
    pub sequence: u32,
    pub field: u32,
    /// Sticky flags the buffer carries across states: `PREPARED`, the
    /// key/predicted-frame markers, and `LAST`.
    pub flags: u32,
    /// Has the buffer been through `buf_prepare` since it was last dequeued?
    pub prepared: bool,
}

impl Buffer {
    /// A freshly allocated buffer, owned by userspace. # C: O(planes)
    pub fn new(index: u32, planes: Vec<Plane>) -> Self {
        Buffer { index, state: BufState::Dequeued, planes, timestamp_ns: 0,
                 sequence: 0, field: crate::uapi::flags::FIELD_NONE, flags: 0,
                 prepared: false }
    }
    /// Total payload the device reported across every plane. # C: O(planes)
    pub fn bytesused(&self) -> u32 {
        self.planes.iter().fold(0u32, |a, p| a.saturating_add(p.bytesused))
    }
    /// Is any plane of this buffer mapped by userspace? # C: O(planes)
    pub fn is_mapped(&self) -> bool { self.planes.iter().any(|p| p.mapped) }
}

/// Backing store for MMAP-model planes.
///
/// The queue asks for and returns whole pages of refcounted kernel RAM. It
/// never maps them itself: a mapping is established by the fault path, which
/// takes its own reference per page, so a plane freed here while userspace
/// still maps it stays alive until the last mapping goes.
pub trait PlaneAlloc: Send + Sync {
    /// Frames covering `bytes`, page-ordered, or `None` when memory is short.
    /// # C: O(pages)
    fn alloc(&self, bytes: u32) -> Option<Vec<u64>>;
    /// Drop this queue's reference on each frame. # C: O(pages)
    fn free(&self, frames: &[u64]);
    /// Bytes per frame the allocator hands out. # C: O(1)
    fn page_bytes(&self) -> u32 { 4096 }
}

/// Identity of the file description that claimed the queue. The reference
/// keys queue ownership on the open file, so a second `open(2)` of the same
/// device cannot free the buffers the first one is streaming with.
pub type Owner = u64;

/// Sizes the driver settled on for one `REQBUFS`/`CREATE_BUFS`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QueueSetup {
    /// Buffers to allocate, after the driver raised a too-small request to its
    /// own minimum.
    pub count: u32,
    pub num_planes: usize,
    /// Bytes per plane, index-parallel with `num_planes`.
    pub plane_sizes: [u32; crate::uapi::layout::MAX_PLANES],
}

/// Absolute cap on buffers in one queue (`VB2_MAX_FRAME`).
pub const MAX_BUFFERS: u32 = 32;

/// The buffer queue.
pub struct Queue {
    /// Buffer type this queue serves; a command naming another is `EINVAL`.
    pub buf_type: u32,
    /// Memory model the current allocation uses, zero when nothing is
    /// allocated.
    pub memory: u32,
    pub bufs: Vec<Buffer>,
    /// Buffers handed to the queue and not yet to the driver, in queue order.
    pub queued: VecDeque<u32>,
    /// Buffers the driver completed, in completion order. `DQBUF` takes from
    /// the front, so frames reach the application in the order captured.
    pub done: VecDeque<u32>,
    pub streaming: bool,
    /// Set when the device failed in a way that makes every further command on
    /// this queue meaningless until it is torn down.
    pub error: bool,
    /// Has the buffer carrying `V4L2_BUF_FLAG_LAST` already been dequeued? The
    /// next `DQBUF` then reports `EPIPE` rather than blocking forever.
    pub last_buffer_dequeued: bool,
    pub owner: Option<Owner>,
    /// Is some caller parked inside a blocking `DQBUF`? A second one is
    /// `EBUSY`, and a `REQBUFS` that would free the buffers underneath it is
    /// refused.
    pub waiting_in_dqbuf: bool,
    /// Buffers that must be queued before streaming may start.
    pub min_queued_buffers: u32,
    /// Largest allocation this queue admits.
    pub max_num_buffers: u32,
    /// `V4L2_BUF_FLAG_TIMESTAMP_*` and `TSTAMP_SRC_*` the driver stamps with.
    pub timestamp_flags: u32,
    /// Memory models the driver supports, as `V4L2_BUF_CAP_*` bits.
    pub supported_caps: u32,
    /// Next free mmap cookie, advanced one plane at a time so every plane in
    /// the device has a distinct offset.
    pub next_offset: u32,
}

impl Queue {
    /// An empty capture queue of `buf_type`. # C: O(1)
    pub fn new(buf_type: u32, supported_caps: u32, timestamp_flags: u32) -> Self {
        Queue {
            buf_type, memory: 0, bufs: Vec::new(), queued: VecDeque::new(),
            done: VecDeque::new(), streaming: false, error: false,
            last_buffer_dequeued: false, owner: None, waiting_in_dqbuf: false,
            min_queued_buffers: 1, max_num_buffers: MAX_BUFFERS,
            timestamp_flags, supported_caps, next_offset: 0,
        }
    }

    /// Are buffers allocated? # C: O(1)
    pub fn is_busy(&self) -> bool { !self.bufs.is_empty() }
    /// Number of allocated buffers. # C: O(1)
    pub fn num_buffers(&self) -> u32 { self.bufs.len() as u32 }
    /// Buffer at `index`, or `None`. # C: O(1)
    pub fn buffer(&self, index: u32) -> Option<&Buffer> { self.bufs.get(index as usize) }
    /// Mutable buffer at `index`. # C: O(1)
    pub fn buffer_mut(&mut self, index: u32) -> Option<&mut Buffer> { self.bufs.get_mut(index as usize) }
    /// Does any buffer carry a live user mapping? # C: O(buffers * planes)
    pub fn any_mapped(&self) -> bool { self.bufs.iter().any(|b| b.is_mapped()) }

    /// Plane a `mmap(2)` offset addresses, as `(buffer index, plane index)`.
    /// The cookie must name a plane exactly; a caller mapping from the middle
    /// of one gets nothing, because the fault path resolves pages relative to
    /// the plane base. # C: O(buffers * planes)
    pub fn plane_by_offset(&self, offset: u32) -> Option<(usize, usize)> {
        for (bi, buf) in self.bufs.iter().enumerate() {
            for (pi, plane) in buf.planes.iter().enumerate() {
                if plane.offset == offset { return Some((bi, pi)); }
            }
        }
        None
    }

    /// Does `owner` hold the queue, or is it free to claim? # C: O(1)
    pub fn owned_by(&self, who: Owner) -> bool {
        match self.owner { None => true, Some(o) => o == who }
    }
}

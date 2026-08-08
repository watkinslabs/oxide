// Resources registered against one ring, and the lookups the submission
// engine does through them.
//
// Every registered resource carries an optional tag. A tagged slot posts a
// completion carrying the tag when the resource in it is released — replaced
// by an update, or dropped by an unregister — which is how a caller learns
// that the kernel is done with the buffer or descriptor it handed over. That
// notification is what `IORING_FEAT_RSRC_TAGS` promises.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring_abi::restriction::Restrictions;

use super::personality::CredSnapshot;
use super::pin::PinnedRange;

/// One registered-buffer slot.
pub struct RegBuf {
    /// Shared so `IORING_REGISTER_CLONE_BUFFERS` hands a second ring the SAME
    /// pinned frames rather than pinning them twice.
    pub buf: Arc<PinnedRange>,
    pub tag: u64,
}

/// One buffer handed to the kernel through `IORING_OP_PROVIDE_BUFFERS`, to be
/// picked by a later `IOSQE_BUFFER_SELECT` submission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProvidedBuf {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
}

/// A caller-owned ring of provided buffers: the kernel reads entries out of
/// memory pinned at registration and advances its own head.
pub struct BufRing {
    pub mem: Arc<PinnedRange>,
    pub entries: u32,
    pub head: u32,
    /// Buffers are consumed incrementally rather than whole.
    pub incremental: bool,
}

/// A provided-buffer group: either buffers handed over one operation at a
/// time, or a ring the caller refills itself. Never both — a group is
/// registered one way or the other.
#[derive(Default)]
pub struct BufGroup {
    pub gid: u16,
    pub bufs: alloc::collections::VecDeque<ProvidedBuf>,
    pub ring: Option<BufRing>,
}

/// One registered-file slot; `file` is `None` for the sparse empty slot.
#[derive(Clone, Default)]
pub struct RegFile {
    pub file: Option<Arc<File>>,
    pub tag: u64,
}

#[derive(Default)]
pub struct IoUringReg {
    /// `None` = no buffer registration has been done, which is what lets
    /// `IORING_UNREGISTER_BUFFERS` answer ENXIO.
    pub buffers: Option<Vec<RegBuf>>,
    /// `None` = no file registration has been done.
    pub files: Option<Vec<RegFile>>,
    /// Completion eventfd — signalled on every CQE post.
    pub eventfd: Option<Arc<File>>,
    /// Registered as the async-only variant.
    pub eventfd_async: bool,
    /// Personalities, indexed by id-1; a `None` slot has been unregistered.
    pub personalities: Vec<Option<Arc<CredSnapshot>>>,
    /// Per-ring allow-lists installed before the ring was enabled.
    pub restrictions: Restrictions,
    /// `IORING_REGISTER_FILE_ALLOC_RANGE`: the half-open slot window automatic
    /// direct-descriptor allocation may use. `(0, 0)` = the whole table.
    pub alloc_range: (u32, u32),
    /// Provided-buffer groups, keyed by group id.
    pub bufs_groups: Vec<BufGroup>,
    /// The clock `IORING_REGISTER_CLOCK` selected for wait timeouts;
    /// `CLOCK_MONOTONIC` until a caller changes it.
    pub clockid: u32,
}

/// `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC: u32 = 1;
/// `CLOCK_BOOTTIME` — monotonic plus time spent suspended.
pub const CLOCK_BOOTTIME: u32 = 7;

impl IoUringReg {
    /// Registered-file table length, or `None` when none is registered.
    /// # C: O(1)
    pub fn files_len(&self) -> Option<u32> { self.files.as_ref().map(|f| f.len() as u32) }

    /// Registered-buffer table length, or `None` when none is registered.
    /// # C: O(1)
    pub fn buffers_len(&self) -> Option<u32> { self.buffers.as_ref().map(|b| b.len() as u32) }

    /// Allocate a personality id for `creds`, reusing an unregistered slot.
    /// Ids are 1-based because 0 in an SQE means "no personality".
    /// # C: O(N_personalities)
    pub fn add_personality(&mut self, creds: Arc<CredSnapshot>) -> Result<u32, Errno> {
        if let Some(i) = self.personalities.iter().position(|p| p.is_none()) {
            self.personalities[i] = Some(creds);
            return Ok(i as u32 + 1);
        }
        if self.personalities.try_reserve(1).is_err() { return Err(Errno::Enomem); }
        self.personalities.push(Some(creds));
        Ok(self.personalities.len() as u32)
    }

    /// # C: O(1)
    pub fn personality(&self, id: u32) -> Option<Arc<CredSnapshot>> {
        if id == 0 { return None; }
        self.personalities.get(id as usize - 1).and_then(|p| p.clone())
    }

    /// # C: O(1)
    pub fn remove_personality(&mut self, id: u32) -> Result<(), Errno> {
        if id == 0 { return Err(Errno::Einval); }
        match self.personalities.get_mut(id as usize - 1) {
            Some(slot) if slot.is_some() => { *slot = None; Ok(()) }
            _ => Err(Errno::Einval),
        }
    }
}

impl IoUringReg {
    /// Add `n` buffers of `len` bytes starting at `addr`, ids running from
    /// `bid`, to group `gid`. # C: O(n)
    pub fn provide_bufs(&mut self, gid: u16, addr: u64, len: u32, bid: u16, n: u32)
        -> Result<(), Errno>
    {
        if !self.bufs_groups.iter().any(|g| g.gid == gid) {
            if self.bufs_groups.try_reserve(1).is_err() { return Err(Errno::Enomem); }
            self.bufs_groups.push(BufGroup { gid, bufs: Default::default(), ring: None });
        }
        let g = self.bufs_groups.iter_mut().find(|g| g.gid == gid).ok_or(Errno::Enomem)?;
        if g.bufs.try_reserve(n as usize).is_err() { return Err(Errno::Enomem); }
        for i in 0..n {
            g.bufs.push_back(ProvidedBuf {
                addr: addr.wrapping_add(i as u64 * len as u64),
                len,
                bid: bid.wrapping_add(i as u16),
            });
        }
        Ok(())
    }

    /// Drop up to `n` buffers from group `gid`, oldest first. Returns how many
    /// went; an unknown group is ENOENT. # C: O(n)
    pub fn remove_bufs(&mut self, gid: u16, n: u32) -> Result<u32, Errno> {
        let g = self.bufs_groups.iter_mut().find(|g| g.gid == gid).ok_or(Errno::Enoent)?;
        let mut done = 0;
        while done < n && g.bufs.pop_front().is_some() { done += 1; }
        Ok(done)
    }

    /// Take the next buffer from group `gid`, from its ring if it has one.
    /// # C: O(N_groups)
    pub fn select_buf(&mut self, gid: u16) -> Result<ProvidedBuf, Errno> {
        let g = self.bufs_groups.iter_mut().find(|g| g.gid == gid).ok_or(Errno::Enobufs)?;
        match g.ring.as_mut() {
            Some(r) => r.next(),
            None => g.bufs.pop_front().ok_or(Errno::Enobufs),
        }
    }

    /// Put a selected buffer back — used when the operation that selected it
    /// never consumed it, so a failed op does not leak the caller's buffer.
    /// A ring group rewinds its head instead, since the entry is still there.
    /// # C: O(N_groups)
    pub fn unselect_buf(&mut self, gid: u16, b: ProvidedBuf) {
        if let Some(g) = self.bufs_groups.iter_mut().find(|g| g.gid == gid) {
            match g.ring.as_mut() {
                Some(r) => r.head = r.head.wrapping_sub(1),
                None => g.bufs.push_front(b),
            }
        }
    }

    /// Buffers still available in a group, for `IORING_REGISTER_PBUF_STATUS`.
    /// # C: O(N_groups)
    pub fn buf_group_len(&self, gid: u16) -> Option<u32> {
        self.bufs_groups.iter().find(|g| g.gid == gid).map(|g| match g.ring.as_ref() {
            Some(r) => r.available(),
            None => g.bufs.len() as u32,
        })
    }
}

/// The slot window automatic direct-descriptor allocation may use.
/// # C: O(1)
pub fn alloc_window(range: (u32, u32), len: u32) -> (u32, u32) {
    if range.1 == 0 { (0, len) } else { (range.0, core::cmp::min(range.0 + range.1, len)) }
}

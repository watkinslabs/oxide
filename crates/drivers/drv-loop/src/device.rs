//! The block device whose media is a file.
//!
//! The backing store is a trait rather than a `vfs::File` directly, for one
//! reason: every rule that matters here — where a device offset lands in the
//! file, what a read past the window does, what a write to a read-only device
//! returns, what a short backing read means — is then decided and tested
//! against a memory backing, with no filesystem, no mount and no disk. The
//! file implementation is a thin adapter over the same trait.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use sync::{Spinlock, TaskList as LoopLockClass};

use crate::config::Window;
use crate::size::{backing_offset, capacity_sectors, SECTOR_BYTES};
use crate::uapi::LO_FLAGS_READ_ONLY;

/// What a loop device reads and writes through.
///
/// A short read is NOT an error: a backing file may be sparse or may have been
/// truncated under the device, and the reference returns the bytes that exist
/// and zeroes the rest rather than failing the whole request.
pub trait Backing: Send + Sync {
    /// Current size of the backing store in bytes. Re-read rather than cached,
    /// because `LOOP_SET_CAPACITY` exists precisely to notice it changing.
    fn size_bytes(&self) -> u64;
    /// Read into `buf` at `off`, returning the bytes actually read.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize>;
    /// Write `buf` at `off`, returning the bytes actually written.
    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize>;
    /// Push the backing store's own dirty state to its media.
    fn flush(&self) -> KResult<()>;
    /// Whether this description may be written at all.
    fn writable(&self) -> bool;
}

/// State a bound loop device carries. Mutable through one lock, because a
/// `SET_STATUS` and an in-flight request must not see half of a window change.
struct Bound {
    backing: alloc::sync::Arc<dyn Backing>,
    window: Window,
    flags: u32,
    block_size: u32,
}

/// A `/dev/loopN`.
pub struct LoopDevice {
    number: u32,
    state: Spinlock<Option<Bound>, LoopLockClass>,
    /// Capacity in 512-byte sectors, republished whenever the window or the
    /// backing size changes so the block layer never has to take the lock.
    sectors: AtomicU64,
}

impl LoopDevice {
    /// An unbound device. It exists, reports zero capacity, and refuses I/O
    /// until something binds a backing store to it — which is exactly what an
    /// added-but-unconfigured `/dev/loopN` does. # C: O(1)
    pub fn new(number: u32) -> Self {
        Self { number, state: Spinlock::new(None), sectors: AtomicU64::new(0) }
    }

    /// # C: O(1)
    pub fn number(&self) -> u32 { self.number }

    /// # C: O(1)
    pub fn is_bound(&self) -> bool { self.state.lock().is_some() }

    /// Bind `backing` with `window`, `flags` and `block_size`, and publish the
    /// resulting capacity. `EBUSY` when already bound — the reference refuses
    /// rather than silently swapping the media under a mounted filesystem.
    /// # C: O(1)
    pub fn bind(&self, backing: alloc::sync::Arc<dyn Backing>, window: Window,
                flags: u32, block_size: u32) -> KResult<()> {
        let mut state = self.state.lock();
        if state.is_some() { return Err(BlockError::Ebusy); }
        let sectors = capacity_sectors(backing.size_bytes(), window.offset, window.sizelimit);
        *state = Some(Bound { backing, window, flags, block_size });
        self.sectors.store(sectors, Ordering::Release);
        Ok(())
    }

    /// Drop the backing store. `ENXIO` when nothing is bound, which is how a
    /// caller distinguishes "already clear" from "cleared it".
    /// # C: O(1)
    pub fn unbind(&self) -> KResult<()> {
        let mut state = self.state.lock();
        if state.take().is_none() { return Err(BlockError::Enxio); }
        self.sectors.store(0, Ordering::Release);
        Ok(())
    }

    /// Re-read the backing size and republish the capacity — `LOOP_SET_CAPACITY`.
    /// Returns the new sector count. # C: O(1)
    pub fn refresh_capacity(&self) -> KResult<u64> {
        let state = self.state.lock();
        let bound = state.as_ref().ok_or(BlockError::Enxio)?;
        let sectors = capacity_sectors(bound.backing.size_bytes(), bound.window.offset, bound.window.sizelimit);
        self.sectors.store(sectors, Ordering::Release);
        Ok(sectors)
    }

    /// Replace the window and flags — `LOOP_SET_STATUS`. The capacity is
    /// republished because a moved window resizes the device.
    /// # C: O(1)
    pub fn set_window(&self, window: Window, flags: u32) -> KResult<()> {
        let mut state = self.state.lock();
        let bound = state.as_mut().ok_or(BlockError::Enxio)?;
        bound.window = window;
        bound.flags = flags;
        let sectors = capacity_sectors(bound.backing.size_bytes(), window.offset, window.sizelimit);
        self.sectors.store(sectors, Ordering::Release);
        Ok(())
    }

    /// Current window, flags and block size, or `ENXIO` when unbound.
    /// # C: O(1)
    pub fn status(&self) -> KResult<(Window, u32, u32)> {
        let state = self.state.lock();
        let bound = state.as_ref().ok_or(BlockError::Enxio)?;
        Ok((bound.window, bound.flags, bound.block_size))
    }

    /// Set the logical block size. Callers validate the value first; this
    /// stores it and republishes nothing, since block size does not change
    /// how many bytes the device holds. # C: O(1)
    pub fn set_block_size(&self, bsize: u32) -> KResult<()> {
        let mut state = self.state.lock();
        let bound = state.as_mut().ok_or(BlockError::Enxio)?;
        bound.block_size = bsize;
        Ok(())
    }

    /// Read `len` bytes at device offset `pos`.
    ///
    /// Bytes the backing store does not have read as zero: a sparse or
    /// truncated file yields holes, not an I/O error.
    /// # C: O(len)
    fn read_bytes(&self, pos: u64, len: usize) -> KResult<Vec<u8>> {
        let state = self.state.lock();
        let bound = state.as_ref().ok_or(BlockError::Enxio)?;
        let file_bytes = bound.backing.size_bytes();
        let at = backing_offset(bound.window.offset, bound.window.sizelimit, file_bytes,
                                pos, len as u64).ok_or(BlockError::Eio)?;
        let mut buf = vec![0u8; len];
        let got = bound.backing.read_at(at, &mut buf)?;
        if got < len { buf[got..].fill(0); }
        Ok(buf)
    }

    /// Write `data` at device offset `pos`. `EIO` past the window; `EPERM`
    /// has no block-layer spelling, so a read-only device reports `EIO` here
    /// and the ioctl layer refuses the write earlier with the right errno.
    /// # C: O(len)
    fn write_bytes(&self, pos: u64, data: &[u8]) -> KResult<()> {
        let state = self.state.lock();
        let bound = state.as_ref().ok_or(BlockError::Enxio)?;
        if bound.flags & LO_FLAGS_READ_ONLY != 0 || !bound.backing.writable() {
            return Err(BlockError::Eio);
        }
        let file_bytes = bound.backing.size_bytes();
        let at = backing_offset(bound.window.offset, bound.window.sizelimit, file_bytes,
                                pos, data.len() as u64).ok_or(BlockError::Eio)?;
        let wrote = bound.backing.write_at(at, data)?;
        if wrote != data.len() { return Err(BlockError::Eio); }
        Ok(())
    }

    /// Byte offset of a request, or `EIO` if the arithmetic overflows.
    /// # C: O(1)
    fn request_span(&self, req: &BlockRequest) -> KResult<(u64, usize)> {
        let bytes = (req.len_blocks as u64).checked_mul(SECTOR_BYTES).ok_or(BlockError::Eio)?;
        let pos = req.start_block.checked_mul(SECTOR_BYTES).ok_or(BlockError::Eio)?;
        Ok((pos, bytes as usize))
    }
}

impl BlockDevice for LoopDevice {
    /// The device always addresses in 512-byte sectors whatever logical block
    /// size it advertises, so capacity arithmetic has one unit. # C: O(1)
    fn block_size(&self) -> u32 { SECTOR_BYTES as u32 }

    fn capacity_blocks(&self) -> u64 { self.sectors.load(Ordering::Acquire) }

    /// The topology, saying a write this device acknowledged may still be
    /// volatile when the backing uses buffered I/O. Direct-I/O and read-only
    /// bindings do not publish that fact; the flush is still forwarded to the
    /// backing whenever a caller requests one.
    /// # C: O(1)
    fn queue_limits(&self) -> KResult<block::QueueLimits> {
        let write_cache = self.state.lock().as_ref().is_some_and(|bound| {
            bound.backing.writable()
                && bound.flags & LO_FLAGS_READ_ONLY == 0
                && bound.flags & crate::uapi::LO_FLAGS_DIRECT_IO == 0
        });
        let mut limits = block::QueueLimits::for_logical_block_size(SECTOR_BYTES as u32)?;
        if write_cache { limits = limits.with_features(block::QueueFeatures::WRITE_CACHE); }
        Ok(limits)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        match req.op {
            BlockOp::Read => {
                let (pos, len) = self.request_span(req)?;
                req.buffer = self.read_bytes(pos, len)?;
                Ok(())
            }
            BlockOp::Write => {
                let (pos, len) = self.request_span(req)?;
                if req.buffer.len() < len { return Err(BlockError::Einval); }
                let data = req.buffer[..len].to_vec();
                self.write_bytes(pos, &data)
            }
            // Zeroing is an ordinary write of zeroes against a file: there is
            // no deallocation to ask for, so `no_unmap` changes nothing.
            BlockOp::WriteZeroes { .. } => {
                let (pos, len) = self.request_span(req)?;
                self.write_bytes(pos, &vec![0u8; len])
            }
            BlockOp::Flush => self.flush(),
            // Punching a hole in the backing file is a filesystem operation
            // this device does not perform, and the block layer only issues
            // it when `supports_discard` says so.
            BlockOp::Discard => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        let state = self.state.lock();
        let bound = state.as_ref().ok_or(BlockError::Enxio)?;
        bound.backing.flush()
    }
}

#[cfg(test)]
#[path = "device/tests.rs"]
mod tests;

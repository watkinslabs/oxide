// The two shared regions of one ring, and the inode that carries them.
//
// A rings region (SQ/CQ headers, the CQE array, the SQ index array) and a
// separate SQEs region. They cannot share a page: userspace maps the SQE array
// as its own mapping starting at the array's first byte, so an array parked at
// a non-zero offset inside the rings page would be read by the kernel and
// written by userspace at different addresses.

use alloc::sync::Arc;

use vfs::{Inode, InodeBuilder, InodeRef, FileOps, FileType, default_inode_ops, mk_mode, get_next_ino};
use vfs::File;

use crate::io_uring_abi::layout::{
    Geometry, MmapRegion, mmap_region, NO_SQ_ARRAY, REGION_BYTES,
    RING_CQES, RING_CQ_RING_ENTRIES, RING_CQ_RING_MASK,
    RING_SQ_RING_ENTRIES, RING_SQ_RING_MASK,
};
use crate::io_uring_abi::uapi::{CQE_SIZE, SQE_SIZE};

use super::ctx::IoUringInode;

/// io_uring's reserved inode-number range, owned by `vfs::pseudo_ino`. A ring's
/// number comes out of here; what makes a file a ring is the `IoUringInode` it
/// owns, not the number.
use vfs::pseudo_ino::IO_URING as INO_REGION;

/// One io_uring instance's memory — owns the rings frame and the SQEs frame.
pub struct IoUring {
    pub rings_pa: u64,
    pub rings_va: u64,
    pub sqes_pa: u64,
    pub sqes_va: u64,
    pub sq_entries: u32,
    pub cq_entries: u32,
    /// Byte offset of the SQ index array in the rings region, or `NO_SQ_ARRAY`
    /// for a ring built with `IORING_SETUP_NO_SQARRAY`.
    pub sq_array_off: u32,
    pub flags: u32,
}

impl IoUring {
    /// Allocate and seed both regions for an admitted geometry. # C: O(1)
    pub fn new(g: &Geometry) -> Option<Self> {
        // The geometry is admitted against REGION_BYTES; one frame per region.
        if g.rings_bytes > REGION_BYTES || g.sqes_bytes > REGION_BYTES { return None; }
        if REGION_BYTES as u64 > hal::PAGE_SIZE_BYTES { return None; }
        let rings_pa = pmm::setup::alloc_object_frame()?;
        let sqes_pa = match pmm::setup::alloc_object_frame() {
            Some(pa) => pa,
            None => {
                // SAFETY: rings_pa was just alloc_object_frame'd here and never published; release that single object reference.
                unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(rings_pa); }
                return None;
            }
        };
        let rings_va = rings_pa + pmm::user_as::hhdm_offset();
        let sqes_va = sqes_pa + pmm::user_as::hhdm_offset();
        for va in [rings_va, sqes_va] {
            hal::zerotrap::trap(va as *const u8, hal::PAGE_SIZE_BYTES as usize);
            // SAFETY: HHDM-mapped frame just allocated by this call, not yet published to any other CPU or to userspace.
            unsafe { core::ptr::write_bytes(va as *mut u8, 0, hal::PAGE_SIZE_BYTES as usize); }
        }
        let r = Self {
            rings_pa, rings_va, sqes_pa, sqes_va,
            sq_entries: g.sq_entries, cq_entries: g.cq_entries,
            sq_array_off: g.sq_array_off, flags: g.flags,
        };
        // Seed the constant ring_mask / ring_entries words before the ring
        // becomes visible to userspace.
        r.hdr_store(RING_SQ_RING_MASK, g.sq_entries - 1);
        r.hdr_store(RING_CQ_RING_MASK, g.cq_entries - 1);
        r.hdr_store(RING_SQ_RING_ENTRIES, g.sq_entries);
        r.hdr_store(RING_CQ_RING_ENTRIES, g.cq_entries);
        Some(r)
    }

    /// Address of a rings-region header word. # C: O(1)
    pub fn hdr_ptr(&self, off: u32) -> *mut u32 { (self.rings_va + off as u64) as *mut u32 }

    /// Read a rings-region header word. # C: O(1)
    pub fn hdr_load(&self, off: u32) -> u32 {
        // SAFETY: off is one of the layout constants, all inside the rings frame; the frame is HHDM-mapped for the ring's whole lifetime.
        unsafe { core::ptr::read_volatile(self.hdr_ptr(off)) }
    }

    /// Write a rings-region header word. # C: O(1)
    pub fn hdr_store(&self, off: u32, v: u32) {
        // SAFETY: off is one of the layout constants, all inside the rings frame; the ring spinlock serialises kernel writers.
        unsafe { core::ptr::write_volatile(self.hdr_ptr(off), v); }
    }

    /// Address of CQE `idx & (cq_entries - 1)`. # C: O(1)
    pub fn cqe_at(&self, idx: u32) -> u64 {
        self.rings_va + RING_CQES as u64 + (idx & (self.cq_entries - 1)) as u64 * CQE_SIZE as u64
    }

    /// Address of SQE `idx & (sq_entries - 1)` in the SQEs region. # C: O(1)
    pub fn sqe_at(&self, idx: u32) -> u64 {
        self.sqes_va + (idx & (self.sq_entries - 1)) as u64 * SQE_SIZE as u64
    }

    /// SQE index for SQ ring slot `head`: through the SQ index array, or the
    /// slot itself for an `IORING_SETUP_NO_SQARRAY` ring. # C: O(1)
    pub fn sq_index(&self, head: u32) -> u32 {
        let slot = head & (self.sq_entries - 1);
        if self.sq_array_off == NO_SQ_ARRAY { return slot; }
        let p = (self.rings_va + self.sq_array_off as u64 + slot as u64 * 4) as *const u32;
        // SAFETY: sq_array_off + sq_entries*4 was bounded by the geometry to the rings frame; slot is masked into range.
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Physical page + usable bytes for an `mmap(2)` offset on the ring fd, or
    /// `None` for an offset that selects no region. # C: O(1)
    pub fn region(&self, offset: u64) -> Option<(u64, u64)> {
        match mmap_region(offset) {
            MmapRegion::Rings   => Some((self.rings_pa, REGION_BYTES as u64)),
            MmapRegion::Sqes    => Some((self.sqes_pa, REGION_BYTES as u64)),
            MmapRegion::Invalid => None,
        }
    }
}

impl Drop for IoUring {
    /// Release both regions' object references. A live user mapping holds its
    /// own reference (`VmaBacking::KernelFrame`), so the frames survive until
    /// the last mapping is torn down. # C: O(1)
    fn drop(&mut self) {
        for pa in [self.rings_pa, self.sqes_pa] {
            if pa != 0 {
                // SAFETY: pa was alloc_object_frame'd in IoUring::new (one object reference); release exactly that reference.
                unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            }
        }
    }
}

/// Physical backing for `mmap(io_uring_fd)`. The caller (`009_mmap`) maps this
/// as a `kframe` (`VmaBacking::KernelFrame`), NOT a `PhysRange`: the regions
/// are refcounted RAM frames, so the mapping inc_ref's them and holds them
/// alive for the mapping's whole lifetime. A frame is freed only once BOTH the
/// fd is closed AND every user mapping is gone.
///
/// An offset that selects no region reports a zero-length region, so
/// `009_mmap`'s `len > region` test turns it into `EINVAL`. # C: O(1)
pub fn mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<(u64, u64)> {
    let iu = inode.private::<IoUringInode>()?;
    let g = iu.ring.lock();
    Some(g.region(offset).unwrap_or((g.rings_pa, 0)))
}

/// `file_operations` for an io_uring fd: the ring is consumed via
/// `io_uring_enter`/`mmap`, not `read`/`write`, so both are `Einval`.
/// # C: O(1)
struct IoUringFileOps;
impl FileOps for IoUringFileOps {
    /// The one vtable io_uring installs — ring identity compares against
    /// exactly this. # C: O(1)
    fn is_io_uring(&self) -> bool { true }
    /// This description has a readiness hook. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// Wrap ring state into a concrete `vfs::Inode`: `i_private` carries the
/// `IoUringInode`, the number comes from io_uring's reserved range. # C: O(1)
pub fn make_io_uring_inode(data: Arc<IoUringInode>) -> InodeRef {
    let ino = INO_REGION.at(get_next_ino() as u64);
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), Arc::new(IoUringFileOps))
        .size(hal::PAGE_SIZE_BYTES)
        .private(data)
        .build()
}

/// Recover the ring state behind an fd's inode. Identity and the errno for a
/// live fd that is not a ring both live in `crate::io_uring_identity`, which
/// is the one place all three callers ask. # C: O(1)
pub fn ring_of(file: &Arc<File>) -> Result<InodeRef, syscall::errno::Errno> {
    crate::io_uring_identity::admit_ring_fd(file)?;
    Ok(file.inode().clone())
}

/// The ring context behind an inode, as an owning handle. # C: O(1)
pub fn ring_ctx(inode: &InodeRef) -> Option<Arc<IoUringInode>> {
    Arc::clone(inode.i_private()).downcast::<IoUringInode>().ok()
}

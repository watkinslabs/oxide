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
    Geometry, MmapRegion, mmap_region, NO_SQ_ARRAY,
    RING_CQES, RING_CQ_RING_ENTRIES, RING_CQ_RING_MASK,
    RING_SQ_RING_ENTRIES, RING_SQ_RING_MASK,
};
use super::region::Region;
use crate::io_uring_abi::uapi::SQE_SIZE;

use super::ctx::IoUringInode;

/// io_uring's reserved inode-number range, owned by `vfs::pseudo_ino`. A ring's
/// number comes out of here; what makes a file a ring is the `IoUringInode` it
/// owns, not the number.
use vfs::pseudo_ino::IO_URING as INO_REGION;

/// One io_uring instance's memory — owns the rings region and the SQEs region.
pub struct IoUring {
    pub rings: Region,
    pub sqes: Region,
    pub sq_entries: u32,
    pub cq_entries: u32,
    /// Byte offset of the SQ index array in the rings region, or `NO_SQ_ARRAY`
    /// for a ring built with `IORING_SETUP_NO_SQARRAY`.
    pub sq_array_off: u32,
    pub flags: u32,
    /// Bytes one CQE occupies — see `layout::cqe_size`.
    pub cqe_size: u32,
}

impl IoUring {
    /// Allocate and seed both regions for an admitted geometry. # C: O(N_pages)
    pub fn new(g: &Geometry) -> Option<Self> {
        let rings = Region::alloc(g.rings_bytes)?;
        let sqes = Region::alloc(g.sqes_bytes)?;
        let r = Self {
            rings, sqes,
            sq_entries: g.sq_entries, cq_entries: g.cq_entries,
            sq_array_off: g.sq_array_off, flags: g.flags, cqe_size: g.cqe_size,
        };
        r.seed_constants();
        Some(r)
    }

    /// Publish the constant ring_mask / ring_entries words. Runs before the
    /// region is visible to userspace at setup, and on the new region during a
    /// resize. # C: O(1)
    pub fn seed_constants(&self) {
        self.hdr_store(RING_SQ_RING_MASK, self.sq_entries - 1);
        self.hdr_store(RING_CQ_RING_MASK, self.cq_entries - 1);
        self.hdr_store(RING_SQ_RING_ENTRIES, self.sq_entries);
        self.hdr_store(RING_CQ_RING_ENTRIES, self.cq_entries);
    }

    /// Direct-map address of the rings region. # C: O(1)
    pub fn rings_va(&self) -> u64 { self.rings.kva }
    /// Direct-map address of the SQEs region. # C: O(1)
    pub fn sqes_va(&self) -> u64 { self.sqes.kva }

    /// Address of a rings-region header word. # C: O(1)
    pub fn hdr_ptr(&self, off: u32) -> *mut u32 { (self.rings.kva + off as u64) as *mut u32 }

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
        self.rings.kva + RING_CQES as u64 + (idx & (self.cq_entries - 1)) as u64 * self.cqe_size as u64
    }

    /// Address of SQE `idx & (sq_entries - 1)` in the SQEs region. # C: O(1)
    pub fn sqe_at(&self, idx: u32) -> u64 {
        self.sqes.kva + (idx & (self.sq_entries - 1)) as u64 * SQE_SIZE as u64
    }

    /// SQE index for SQ ring slot `head`: through the SQ index array, or the
    /// slot itself for an `IORING_SETUP_NO_SQARRAY` ring. # C: O(1)
    pub fn sq_index(&self, head: u32) -> u32 {
        let slot = head & (self.sq_entries - 1);
        if self.sq_array_off == NO_SQ_ARRAY { return slot; }
        let p = (self.rings.kva + self.sq_array_off as u64 + slot as u64 * 4) as *const u32;
        // SAFETY: sq_array_off + sq_entries*4 was bounded by the geometry to the rings frame; slot is masked into range.
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Physical page + usable bytes for an `mmap(2)` offset on the ring fd, or
    /// `None` for an offset that selects no region. # C: O(1)
    pub fn region(&self, offset: u64) -> Option<(u64, u64)> {
        match mmap_region(offset) {
            MmapRegion::Rings   => Some((self.rings.base_pa, self.rings.map_bytes)),
            MmapRegion::Sqes    => Some((self.sqes.base_pa, self.sqes.map_bytes)),
            // Owned by the inode, not by this struct — routed in `mmap_backing`.
            MmapRegion::Param   => None,
            // Owned by the inode's instance table, not by this struct.
            MmapRegion::Zcrx(_) => None,
            MmapRegion::Invalid => None,
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
    // A registered memory region lives on the inode, not in `IoUring`. Only
    // the kernel-allocated arm is mappable; a caller-provided region reports a
    // zero-length region, and so does a ring that registered none.
    match mmap_region(offset) {
        MmapRegion::Param => {
            let g = iu.param_region.lock();
            return Some(g.as_ref().and_then(|r| r.mmap_backing()).unwrap_or((0, 0)));
        }
        // A refill queue lives on the instance the offset names; an offset
        // naming no instance reports a zero-length region, which `009_mmap`
        // turns into EINVAL.
        MmapRegion::Zcrx(id) => return Some(iu.zcrx_mmap_backing(id).unwrap_or((0, 0))),
        _ => {}
    }
    let g = iu.ring.lock();
    Some(g.region(offset).unwrap_or((g.rings.base_pa, 0)))
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

/// Cancel a ring's outstanding work when its last descriptor goes away.
///
/// The ring's submission-polling thread is ended here too: it exists only to
/// serve descriptors that no longer exist.
///
/// A request that is still armed holds a reference to the ring, so a ring with
/// an armed timeout or an armed poll would otherwise stay alive — and keep the
/// submitter's address space and descriptor table alive with it — until a
/// deadline or a peer decided otherwise. The submitter is already gone by
/// then, so there is nobody left to report to.
/// # C: O(N_inflight)
fn release_hook(inode: &InodeRef, _writable: bool, _dentry: &Arc<vfs::Dentry>) {
    // Cheap first: only inode numbers out of io_uring's own range can be
    // rings, and this hook is on every description's close path.
    if !INO_REGION.contains(inode.ino()) { return; }
    // An exported zero-copy receive instance travels on its own descriptor out
    // of the same number range. Closing it stops the descriptor keeping the
    // instance reachable; whether that closes a device queue is the instance's
    // own user count to decide, not this one descriptor's.
    if let Some(ifq) = super::zcrx::box_fd::ifq_of_inode(inode) { ifq.put_user(); return; }
    let Some(iu) = ring_ctx(inode) else { return };
    // Before the cancellations: a poll thread still draining the ring would
    // otherwise start work the cancel sweep has already walked past.
    crate::io_uring::sqpoll::finish(&iu);
    iu.cancel_all();
    // Unbinds every device receive queue: the binding holds the instance and
    // the instance holds the queue array, so nothing here is freed until the
    // cycle is broken explicitly.
    iu.zcrx_teardown();
}

/// Install the release hook once, at the first ring creation. # C: O(1)
pub fn install_release_hook() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) { return; }
    vfs::set_close_hook(release_hook);
}

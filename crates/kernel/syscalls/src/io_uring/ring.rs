// One io_uring instance: the two shared regions and the registration state.
//
// Linux `io_uring/io_uring.c io_allocate_scq_urings()` builds TWO regions and
// hands each out under its own `IORING_OFF_*` mmap offset:
//   rings region — SQ/CQ headers, the CQE array, the SQ index array
//                  (`IORING_OFF_SQ_RING`, and `IORING_OFF_CQ_RING` because
//                  oxide reports `IORING_FEAT_SINGLE_MMAP`)
//   SQEs region  — the SQE array (`IORING_OFF_SQES`)
// They cannot share a page: userspace mmaps `IORING_OFF_SQES` as its own
// mapping starting at the SQE array's first byte, so an SQE array parked at a
// non-zero offset inside the rings page would be read by the kernel and
// written by userspace at different addresses.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as RingLockClass};
use vfs::File;
use vfs::{Inode, InodeBuilder, InodeRef, FileOps, FileType, default_inode_ops, mk_mode, get_next_ino};

use crate::io_uring_abi::layout::{
    Geometry, MmapRegion, mmap_region, NO_SQ_ARRAY, REGION_BYTES,
    RING_CQES, RING_CQ_RING_ENTRIES, RING_CQ_RING_MASK,
    RING_SQ_RING_ENTRIES, RING_SQ_RING_MASK,
};
use crate::io_uring_abi::uapi::{CQE_SIZE, SQE_SIZE};

/// io_uring ino high-bits tag (`"IOUR"`), distinct from socket/ext4/pipe inodes.
pub const IO_URING_INO_TAG: u64 = 0x494F_5552_0000_0000;
/// Mask selecting the tag bits of an ino.
pub const INO_TAG_MASK: u64 = 0xFFFF_FFFF_0000_0000;

/// One io_uring instance — owns the rings frame and the SQEs frame.
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
    /// Allocate and seed both regions for an admitted geometry.
    /// # C: O(1)
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
        // Linux io_allocate_scq_urings(): seed the constant ring_mask /
        // ring_entries words before the ring becomes visible to userspace.
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
        // SAFETY: sq_array_off + sq_entries*4 was bounded by `rings_size` to the rings frame; slot is masked into range.
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

/// Resources registered against a ring via `io_uring_register(2)`. Linux keeps
/// these on `struct io_ring_ctx`; oxide mirrors that here under its own lock so
/// registration never contends the SQ/CQ ring lock.
#[derive(Default)]
pub struct IoUringReg {
    /// Fixed buffers: (user_base, len). Indexed by SQE `buf_index`. `None` =
    /// no `REGISTER_BUFFERS` done, which is what makes `UNREGISTER_BUFFERS`
    /// able to return `ENXIO`.
    pub buffers: Option<Vec<(u64, u64)>>,
    /// Fixed files: a `None` slot is the `-1` empty slot Linux allows. The
    /// outer `Option` = no `REGISTER_FILES` done.
    pub files: Option<Vec<Option<Arc<File>>>>,
    /// Completion eventfd — signalled (+1) on every CQE post.
    pub eventfd: Option<Arc<File>>,
    /// Registered via `IORING_REGISTER_EVENTFD_ASYNC`: Linux signals such an
    /// eventfd only for completions posted from async context. Every oxide
    /// completion is posted inline from the submitting task, so an async-only
    /// eventfd is correctly never signalled.
    pub eventfd_async: bool,
}

pub struct IoUringInode {
    pub ring: Spinlock<IoUring, RingLockClass>,
    pub reg:  Spinlock<IoUringReg, RingLockClass>,
}

impl IoUringInode {
    /// Build a ring from an admitted geometry. # C: O(1)
    pub fn new(g: &Geometry) -> Option<Arc<Self>> {
        let ring = IoUring::new(g)?;
        Some(Arc::new(Self {
            ring: Spinlock::new(ring),
            reg:  Spinlock::new(IoUringReg::default()),
        }))
    }

    /// Resolve SQE `buf_index` to the registered buffer's user range, then
    /// clamp the requested `[off, off+len)` window inside it. Linux: `EFAULT`
    /// if no such buffer index, or on an out-of-range window. # C: O(1)
    pub fn fixed_buf_window(&self, buf_index: u16, off: u64, len: u32) -> Result<(u64, u64), i64> {
        use syscall::errno::Errno;
        let g = self.reg.lock();
        let bufs = match g.buffers.as_ref() {
            Some(b) => b, None => return Err(-(Errno::Efault.as_i32() as i64)),
        };
        let (base, blen) = match bufs.get(buf_index as usize) {
            Some(&bl) => bl, None => return Err(-(Errno::Efault.as_i32() as i64)),
        };
        let want = len as u64;
        let end = match off.checked_add(want) { Some(e) => e, None => return Err(-(Errno::Efault.as_i32() as i64)) };
        if end > blen { return Err(-(Errno::Efault.as_i32() as i64)); }
        let addr = match base.checked_add(off) { Some(a) => a, None => return Err(-(Errno::Efault.as_i32() as i64)) };
        if !uaccess::access_ok(addr, want as usize) { return Err(-(Errno::Efault.as_i32() as i64)); }
        Ok((addr, want))
    }

    /// Resolve a fixed-file index (`IOSQE_FIXED_FILE`). Linux: `EBADF` if no
    /// files are registered, the index is out of range, or the slot is empty.
    /// # C: O(1)
    pub fn fixed_file(&self, idx: u32) -> Result<Arc<File>, i64> {
        use syscall::errno::Errno;
        let g = self.reg.lock();
        match g.files.as_ref().and_then(|f| f.get(idx as usize)).and_then(|s| s.clone()) {
            Some(f) => Ok(f),
            None    => Err(-(Errno::Ebadf.as_i32() as i64)),
        }
    }

    /// Signal the registered completion eventfd (+1), if one is registered and
    /// it is not the async-only variant. # C: O(1)
    pub fn signal_eventfd(&self) {
        let efd = { let g = self.reg.lock(); if g.eventfd_async { None } else { g.eventfd.clone() } };
        if let Some(f) = efd {
            let one = 1u64.to_ne_bytes();
            let _ = f.inode().write(0, &one);
        }
    }
}

/// Physical backing for `mmap(io_uring_fd)`. The caller (`009_mmap`) maps this
/// as a `kframe` (`VmaBacking::KernelFrame`), NOT a `PhysRange`: the regions
/// are refcounted RAM frames (`alloc_object_frame`), so the mapping inc_ref's
/// them and holds them alive for the mapping's whole lifetime. A frame is
/// freed only once BOTH the fd is closed (`IoUring::Drop`) AND every user
/// mapping is gone — Linux `vm_file`-reference semantics. Mapping it as a
/// PhysRange instead was a free-while-mapped UAF (state.md).
///
/// An offset that selects no region reports a zero-length region, so
/// `009_mmap`'s `len > region` test turns it into `EINVAL` — Linux
/// `io_uring_mmap` rejects an unknown offset the same way. # C: O(1)
pub fn mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<(u64, u64)> {
    let iu = inode.private::<IoUringInode>()?;
    let g = iu.ring.lock();
    Some(g.region(offset).unwrap_or((g.rings_pa, 0)))
}

/// `file_operations` for an io_uring fd: the ring is consumed via
/// `io_uring_enter`/`mmap`, not `read`/`write`, so both are `Einval` (Linux).
/// # C: O(1)
struct IoUringFileOps;
impl FileOps for IoUringFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// Wrap ring state into a concrete `vfs::Inode`: `i_private` carries the
/// `IoUringInode`, the ino is tagged `"IOUR"` | a process-wide anon ino.
/// # C: O(1)
pub fn make_io_uring_inode(data: Arc<IoUringInode>) -> InodeRef {
    let ino = IO_URING_INO_TAG | get_next_ino() as u64;
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), Arc::new(IoUringFileOps))
        .size(hal::PAGE_SIZE_BYTES)
        .private(data)
        .build()
}

/// Recover the ring state behind an fd's inode, verifying the io_uring ino
/// tag. Linux `io_uring_ctx_get_file()` answers `EOPNOTSUPP` — not `EINVAL` —
/// for an fd that is not an io_uring instance. # C: O(1)
pub fn ring_of(file: &Arc<File>) -> Result<InodeRef, syscall::errno::Errno> {
    use syscall::errno::Errno;
    if (file.inode().ino() & INO_TAG_MASK) != IO_URING_INO_TAG { return Err(Errno::Eopnotsupp); }
    Ok(file.inode().clone())
}

// One `IORING_REGISTER_MEM_REGION` region and its two backing shapes.
//
// A ring's regions (`region::Region`) are one contiguous refcounted run each,
// because userspace maps them and the `VmaBacking::KernelFrame` fault path
// resolves VMA offset `O` to `base_pa + O`. A memory region cannot always be
// that: the caller-provided form is a range out of the CALLER's address space,
// pinned page by page, and those pages are whatever the caller's mappings
// happened to be backed by. Forcing them contiguous is not an option — the
// memory already exists.
//
// So a region is one of two things, and only the kernel-allocated arm is
// mappable from the ring fd. The reference refuses `mmap` on a user-provided
// region for the same reason: the pages are already in the caller's map, and
// handing back a second mapping of them through a `KernelFrame` VMA would put
// two independent reference schemes on one frame.
//
// Both arms hold their pages for the region's whole life — the contiguous run
// through one object reference per page, the pinned range through one per
// frame — so a page dies only once the ring drops the region AND every user
// mapping of it is gone.

use syscall::errno::Errno;

use super::pin::PinnedRange;
use super::region::Region;

/// A registered memory region.
pub enum MemRegion {
    /// Kernel-allocated: a contiguous run this kernel owns, published to
    /// userspace at `IORING_MAP_OFF_PARAM_REGION`.
    Kernel(Region),
    /// Caller-provided: pages pinned out of the caller's address space, never
    /// mappable from the ring fd.
    User(PinnedRange),
}

impl MemRegion {
    /// Bytes the region spans. # C: O(1)
    pub fn size(&self) -> u64 {
        match self {
            MemRegion::Kernel(r) => r.map_bytes,
            MemRegion::User(p) => p.len,
        }
    }

    /// Read `out.len()` bytes from byte offset `off`. Both arms answer through
    /// a page walk, so no caller has to know which shape it holds.
    /// # C: O(out.len() / PAGE)
    pub fn read_at(&self, off: u64, out: &mut [u8]) -> Result<(), Errno> {
        match self {
            MemRegion::Kernel(r) => {
                let end = off.checked_add(out.len() as u64).ok_or(Errno::Efault)?;
                if end > r.map_bytes { return Err(Errno::Efault); }
                let src = r.at(off) as *const u8;
                // SAFETY: `r` is a contiguous run this ring owns, HHDM-mapped for its whole life; `off + out.len()` was just bounded by the run's mappable size.
                unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len()); }
                Ok(())
            }
            MemRegion::User(p) => p.read_at(off, out),
        }
    }

    /// Physical base and mappable length for `mmap(2)` on the ring fd, or
    /// `None` when this region is not mappable. # C: O(1)
    pub fn mmap_backing(&self) -> Option<alloc::sync::Arc<[u64]>> {
        match self {
            MemRegion::Kernel(r) => r.mmap_backing(),
            MemRegion::User(_) => None,
        }
    }
}

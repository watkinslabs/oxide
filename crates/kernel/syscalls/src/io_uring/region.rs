// One shared io_uring region: the physical memory behind a rings or SQEs
// mapping, and its lifetime.
//
// A region is a CONTIGUOUS refcounted run of `2^order` pages, each carrying
// one object reference for the region's whole life. Userspace maps it as a
// `VmaBacking::KernelFrame`, whose fault path resolves the page at VMA offset
// `O` to `base_pa + O` and takes one reference per installed PTE; munmap and
// address-space teardown drop those. A page therefore dies only once BOTH the
// ring released its object reference AND every user mapping is gone.
//
// It is never a `PhysRange`: that arm installs the PTE with no refcount and no
// mapcount, so closing the ring fd would free a page userspace still maps —
// the free-while-mapped UAF this file's shape exists to prevent.
//
// One buddy run rather than a page vector: `KernelFrame` has no page-vector
// form, so the order rounding is dead space (`scratch/known_issues.md`).
//
// A ring built `IORING_SETUP_NO_MMAP` does not own its memory at all — the
// CALLER supplied it, and it is whatever physical pages backed the caller's
// mapping. Such a region is a pinned range instead of a run: it is not
// contiguous, it is not mappable from the ring descriptor, and every access
// into it resolves one page at a time. Nothing else changes, because no ring
// object straddles a page (`io_uring_abi::user_ring::spans_one_page`).

use syscall::errno::Errno;

use crate::io_uring_abi::acct::{Charge, Ledgers, RingAcct};
use crate::io_uring_abi::layout::region_plan;

use super::pin::PinnedRange;

/// One region's memory: a run this kernel owns, or a range the caller does.
pub struct Region {
    /// First page of the run; the PA userspace maps at VMA offset zero. Zero
    /// for a caller-supplied region, which is never mapped from the ring.
    pub base_pa: u64,
    /// Direct-map alias the kernel reads and writes a kernel run through.
    kva: u64,
    /// Buddy order of the run. Zero for a caller-supplied region.
    order: u8,
    /// Page-aligned bytes userspace may map — the region's real size. The
    /// pages the order rounding adds past this are never exposed.
    pub map_bytes: u64,
    /// The caller's pages, for a region this kernel did not allocate. Holding
    /// them here is what keeps them pinned for the ring's whole life.
    user: Option<PinnedRange>,
    /// The per-user memory-lock charge an allocated run cost, given back when
    /// the run is. A caller-supplied region books its charge through the
    /// pinned range instead, so this is the empty token there — one region,
    /// one charge, whichever arm it took.
    _charge: Charge,
}

impl Region {
    /// Allocate and zero a region big enough for `bytes`, charging its pages
    /// to the ring's account. `None` covers both a refused charge and a
    /// refused allocation: every caller answers ENOMEM to either.
    ///
    /// The charge is the region's MAPPABLE size, not the buddy run the order
    /// rounding produced: the rounding is dead space this kernel never exposes
    /// (`scratch/known_issues.md`), and charging a user for it would make the
    /// ceiling depend on an allocator detail. # C: O(2^order)
    pub fn alloc(bytes: u32, acct: RingAcct) -> Option<Self> {
        let page = hal::PAGE_SIZE_BYTES;
        let plan = region_plan(bytes, page).ok()?;
        let charge = super::acct::charge_bytes(acct, plan.map_bytes).ok()?;
        let base_pa = pmm::setup::alloc_contig_object(pmm::Order(plan.order))?;
        let kva = base_pa + pmm::user_as::hhdm_offset();
        for i in 0..(1u64 << plan.order) {
            let va = kva + i * page;
            hal::zerotrap::trap(va as *const u8, page as usize);
            // SAFETY: HHDM alias of a run this call just allocated, not yet published to another CPU or to userspace.
            unsafe { core::ptr::write_bytes(va as *mut u8, 0, page as usize); }
        }
        Some(Self { base_pa, kva, order: plan.order, map_bytes: plan.map_bytes, user: None, _charge: charge })
    }

    /// Adopt `bytes` of the caller's memory at `base` as this region, pinning
    /// every page of it for the region's whole life.
    ///
    /// The pages are zeroed here, exactly as an allocated region is: a ring
    /// whose header words started as whatever the caller left in the memory
    /// would report a tail it never posted to. # C: O(bytes / PAGE)
    pub fn pin(base: u64, bytes: u32, acct: RingAcct) -> Result<Self, Errno> {
        let page = hal::PAGE_SIZE_BYTES;
        let plan = region_plan(bytes, page).map_err(|_| Errno::Einval)?;
        crate::io_uring_abi::user_ring::admit_addr(base, plan.map_bytes, page)?;
        // A region is the ring's memory even when the caller supplied the
        // pages, so it books the user account alone — the mm's pinned total is
        // for memory the kernel holds down for I/O, not for the ring itself.
        let user = PinnedRange::pin(base, plan.map_bytes, acct, Ledgers::User)?;
        let zero = alloc::vec![0u8; page as usize];
        let mut off = 0;
        while off < plan.map_bytes { user.write_at(off, &zero)?; off += page; }
        Ok(Self { base_pa: 0, kva: 0, order: 0, map_bytes: plan.map_bytes, user: Some(user), _charge: Charge::none() })
    }

    /// Direct-map address of `off` bytes into the region. Callers bound `off`
    /// by the geometry that sized the region, and every object they reach this
    /// way lies inside one page — which is what makes the per-page resolution
    /// of a caller-supplied region a plain address. # C: O(1)
    pub fn at(&self, off: u64) -> u64 {
        match &self.user {
            None => self.kva + off,
            // The offset was bounded by the geometry that sized this region,
            // so a miss here cannot happen; answering with the region's first
            // byte keeps a bug from becoming a wild pointer.
            Some(p) => p.kva_at(off).unwrap_or_else(|| p.kva_at(0).unwrap_or(0)),
        }
    }

    /// Physical base and mappable length for `mmap(2)` on the ring descriptor,
    /// or `None` for a caller-supplied region — those pages are already in the
    /// caller's address space, and a second mapping of them would put two
    /// independent reference schemes on one frame. # C: O(1)
    pub fn mmap_backing(&self) -> Option<(u64, u64)> {
        if self.user.is_some() { return None; }
        Some((self.base_pa, self.map_bytes))
    }
}

impl Drop for Region {
    /// Release the run's object references, one per page. A live user mapping
    /// holds its own per-page reference, so the pages outlive this drop until
    /// the last mapping is torn down. # C: O(2^order)
    fn drop(&mut self) {
        // A caller-supplied region owns no run; its pages are released by the
        // pinned range this struct holds.
        if self.user.is_some() { return; }
        for i in 0..(1u64 << self.order) {
            // SAFETY: base_pa came from alloc_contig_object, which seeds exactly one object reference per page in the run; this releases that one reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(self.base_pa + i * hal::PAGE_SIZE_BYTES); }
        }
    }
}

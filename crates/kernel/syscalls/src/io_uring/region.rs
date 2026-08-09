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
// Contiguity is oxide's, not the reference's: the reference allocates the
// region as an unordered page vector and reaches it through a kernel virtual
// mapping. `KernelFrame` has no page-vector form, so a region is one buddy
// run and the order rounding is dead space (`scratch/known_issues.md`).

use crate::io_uring_abi::layout::region_plan;

/// One region's physical run.
pub struct Region {
    /// First page of the run; the PA userspace maps at VMA offset zero.
    pub base_pa: u64,
    /// Direct-map alias the kernel reads and writes the region through.
    pub kva: u64,
    /// Buddy order of the run.
    pub order: u8,
    /// Page-aligned bytes userspace may map — the region's real size. The
    /// pages the order rounding adds past this are never exposed.
    pub map_bytes: u64,
}

impl Region {
    /// Allocate and zero a region big enough for `bytes`. # C: O(2^order)
    pub fn alloc(bytes: u32) -> Option<Self> {
        let page = hal::PAGE_SIZE_BYTES;
        let plan = region_plan(bytes, page).ok()?;
        let base_pa = pmm::setup::alloc_contig_object(pmm::Order(plan.order))?;
        let kva = base_pa + pmm::user_as::hhdm_offset();
        for i in 0..(1u64 << plan.order) {
            let va = kva + i * page;
            hal::zerotrap::trap(va as *const u8, page as usize);
            // SAFETY: HHDM alias of a run this call just allocated, not yet published to another CPU or to userspace.
            unsafe { core::ptr::write_bytes(va as *mut u8, 0, page as usize); }
        }
        Some(Self { base_pa, kva, order: plan.order, map_bytes: plan.map_bytes })
    }

    /// Address of `off` bytes into the region. Callers bound `off` by the
    /// geometry that sized the region. # C: O(1)
    pub fn at(&self, off: u64) -> u64 { self.kva + off }
}

impl Drop for Region {
    /// Release the run's object references, one per page. A live user mapping
    /// holds its own per-page reference, so the pages outlive this drop until
    /// the last mapping is torn down. # C: O(2^order)
    fn drop(&mut self) {
        for i in 0..(1u64 << self.order) {
            // SAFETY: base_pa came from alloc_contig_object, which seeds exactly one object reference per page in the run; this releases that one reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(self.base_pa + i * hal::PAGE_SIZE_BYTES); }
        }
    }
}

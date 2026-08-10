// The page supply an image is staged out of.
//
// A trait rather than a direct PMM call so the staging algorithm — which is
// the part with the interesting invariant (a source page is either its own
// destination or not a destination at all) — is exercised hosted against a
// backing whose physical addresses the test chooses. A test that cannot place
// a page AT a destination address cannot reach the swap path at all, and that
// path is where the algorithm can corrupt an image.

use crate::uapi::PAGE_SIZE;

/// Supplier of 4 KiB physical pages, plus the kernel mapping used to fill them.
pub trait Frames {
    /// Allocate one page; `None` when memory is exhausted.
    fn alloc(&mut self) -> Option<u64>;
    /// Release a page obtained from `alloc`.
    /// # Safety
    /// `pa` came from `alloc` on this supplier and is no longer referenced by
    /// any relocation entry or page list.
    unsafe fn free(&mut self, pa: u64);
    /// Kernel-writable pointer to `pa`, or `None` when it is not mapped.
    fn ptr(&self, pa: u64) -> Option<*mut u8>;
    /// Pages of usable RAM, for the "no image may claim half of memory" rule.
    fn total_ram_pages(&self) -> u64;
    /// Highest physical address a SOURCE page may sit at
    /// (`KEXEC_SOURCE_MEMORY_LIMIT`). Both arches this port builds place no
    /// restriction, so the default is the whole space.
    fn source_limit(&self) -> u64 { u64::MAX }
    /// Highest physical address a CONTROL page may sit at
    /// (`KEXEC_CONTROL_MEMORY_LIMIT`).
    fn control_limit(&self) -> u64 { u64::MAX }
    /// Usable-RAM ranges. The identity tables
    /// the trampoline runs under have to cover every one of them, because the
    /// relocation reads its source pages out of exactly this memory.
    fn ram_range_count(&self) -> usize { 0 }
    /// Range `i` as `[start, end)` physical bytes.
    fn ram_range(&self, i: usize) -> Option<(u64, u64)> { let _ = i; None }
    /// Firmware-owned physical ranges: the description tables a replacement
    /// kernel reads before it has built any mapping of its own. Outside usable
    /// RAM by construction, so the identity map has to be told about them
    /// separately or the first table read faults.
    fn firmware_range_count(&self) -> usize { 0 }
    /// Firmware range `i` as `[start, end)` physical bytes.
    fn firmware_range(&self, i: usize) -> Option<(u64, u64)> { let _ = i; None }
}

/// Fill `pa` with zeroes.
/// # C: O(PAGE_SIZE)
pub fn clear_page<F: Frames>(f: &F, pa: u64) {
    if let Some(p) = f.ptr(pa) {
        // SAFETY: `Frames::ptr` returns a kernel-mapped, page-sized, exclusively
        // owned staging page; the image owns `pa` for its whole lifetime.
        unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE as usize) };
    }
}

/// Copy a whole page from `src` to `dst`.
/// # C: O(PAGE_SIZE)
pub fn copy_page<F: Frames>(f: &F, dst: u64, src: u64) {
    if let (Some(d), Some(s)) = (f.ptr(dst), f.ptr(src)) {
        // SAFETY: both are distinct image-owned staging pages of PAGE_SIZE bytes,
        // mapped by the same backing; the image holds exclusive ownership of each.
        unsafe { core::ptr::copy_nonoverlapping(s, d, PAGE_SIZE as usize) };
    }
}

/// The running kernel's page supply: the buddy allocator plus the HHDM.
///
/// Pages are `alloc_raw_frame` grade — owned outright by the image, never a
/// user PTE and never refcounted through a struct page, and released with
/// `free_one_frame` when the image is dropped.
pub struct PmmFrames;

impl Frames for PmmFrames {
    /// # C: O(1) amortised
    fn alloc(&mut self) -> Option<u64> { pmm::setup::alloc_raw_frame() }
    /// # C: O(1) amortised
    unsafe fn free(&mut self, pa: u64) {
        // SAFETY: forwarded contract — `pa` came from `alloc_raw_frame` on this
        // supplier and the image has already dropped every reference to it.
        unsafe { pmm::setup::free_one_frame(pa) }
    }
    /// # C: O(1)
    fn ptr(&self, pa: u64) -> Option<*mut u8> { pmm::setup::frame_ptr(pa) }
    /// # C: O(MAX_ORDER); # Lk: Buddy
    fn total_ram_pages(&self) -> u64 {
        pmm::setup::pmm_static().map_or(0, |p| p.snapshot().managed_pages)
    }
    /// # C: O(1)
    fn ram_range_count(&self) -> usize { pmm::setup::usable_regions().len() }
    /// # C: O(1)
    fn ram_range(&self, i: usize) -> Option<(u64, u64)> {
        let r = pmm::setup::usable_regions().get(i)?;
        let start = r.start.0 * PAGE_SIZE;
        Some((start, start + r.len_pfn * PAGE_SIZE))
    }
    /// # C: O(1)
    fn firmware_range_count(&self) -> usize { pmm::setup::firmware_regions().len() }
    /// # C: O(1)
    fn firmware_range(&self, i: usize) -> Option<(u64, u64)> {
        let r = pmm::setup::firmware_regions().get(i)?;
        Some((r.start, r.end))
    }
}

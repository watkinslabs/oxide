//! Shared kernel Device-MMIO mapper.
//!
//! PCI/virtio/NVMe/AHCI probes all need BAR pages mapped into kernel VA space.
//! The VA allocator must be shared so independent drivers never splice
//! different MMIO pages at the same virtual address.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU64, Ordering};
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu;
#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu;

/// Kernel VA bump-allocator base for PCI BAR/device mappings. Disjoint from
/// `KERNEL_DEVICE_BASE` low-32 PA aliases and the aarch64 ECAM window.
const DEVICE_BAR_VA_BASE: u64 = 0xffff_fd00_0000_0000;
static DEVICE_BAR_VA_NEXT: AtomicU64 = AtomicU64::new(DEVICE_BAR_VA_BASE);

fn device_flags() -> PageFlags {
    PageFlags::READ | PageFlags::WRITE | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH
}

/// Map `n_pages` of 4K MMIO at physical address `pa` into fresh kernel VA
/// space and return the base VA.
///
/// # Safety
/// Caller must ensure `pa` names a real device MMIO region it owns, the MMU is
/// initialized, and `pa` is page-aligned.
/// # C: O(n_pages * page-table depth)
pub unsafe fn map_pages(pa: u64, n_pages: u64) -> u64 {
    let bytes = n_pages * 0x1000;
    let base = DEVICE_BAR_VA_NEXT.fetch_add(bytes, Ordering::AcqRel);
    for i in 0..n_pages {
        let va = base + i * 0x1000;
        let pa_i = pa + i * 0x1000;
        // SAFETY: upheld by this function's caller; each VA comes from the
        // global bump allocator and is used once for this mapping.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            <X86Mmu as MmuOps>::map(Va(va), Pa(pa_i), device_flags(), PageSize::P4K);
            #[cfg(target_arch = "aarch64")]
            <ArmMmu as MmuOps>::map(Va(va), Pa(pa_i), device_flags(), PageSize::P4K);
        }
    }
    base
}

/// Owned device-MMIO mapping. Drivers keep this with the hardware state and
/// unmap it only after remove has quiesced the device and released users.
pub struct Mapping {
    base_va: u64,
    n_pages: u64,
}

impl Mapping {
    /// Base VA of the mapped MMIO window. # C: O(1)
    pub fn base_va(&self) -> u64 { self.base_va }

    /// Tear down this MMIO window. Idempotent so probe-failure and remove
    /// paths can call it during reverse-order cleanup.
    /// # C: O(n_pages * page-table depth)
    pub fn unmap(&mut self) {
        if self.base_va == 0 {
            return;
        }
        let base = self.base_va;
        let n_pages = self.n_pages;
        self.base_va = 0;
        self.n_pages = 0;
        // SAFETY: `Mapping` owns this VA range; callers only unmap after the
        // hardware user has been quiesced and no future MMIO will be issued.
        unsafe { unmap_pages(base, n_pages); }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) { self.unmap(); }
}

/// Map `n_pages` of 4K MMIO and return an owned mapping handle.
///
/// # Safety
/// Same contract as `map_pages`.
/// # C: O(n_pages * page-table depth)
pub unsafe fn map_owned(pa: u64, n_pages: u64) -> Mapping {
    let base_va = unsafe { map_pages(pa, n_pages) };
    Mapping { base_va, n_pages }
}

/// Unmap `n_pages` of 4K MMIO starting at `base_va`.
///
/// # Safety
/// Caller must own the mapped VA range and guarantee no live user can issue
/// further MMIO through it.
/// # C: O(n_pages * page-table depth)
pub unsafe fn unmap_pages(base_va: u64, n_pages: u64) {
    for i in 0..n_pages {
        let va = base_va + i * 0x1000;
        // SAFETY: upheld by this function's caller; every VA is page-aligned
        // and belongs to the mapping being torn down.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            <X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            #[cfg(target_arch = "aarch64")]
            <ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
        }
    }
}

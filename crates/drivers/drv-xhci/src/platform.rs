//! Kernel-only owned mappings and DMA pages for one xHCI controller.

use core::ptr::{read_volatile, write_volatile};

use crate::regs::{geometry, Geometry, CAPLENGTH, DBOFF, HCSPARAMS1, RTSOFF};

const PAGE: u64 = 4096;

/// Convert a controller DMA physical page into its direct-map virtual alias.
/// # C: O(1)
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
}

/// One page of controller-owned, physically contiguous DMA memory.
pub struct DmaPage { pa: u64 }

impl DmaPage {
    /// Allocate and clear a page before it can be named in a controller register.
    /// # C: O(page bytes)
    pub fn allocate() -> Option<Self> {
        let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let va = hhdm().checked_add(pa)?;
        if va == 0 {
            // SAFETY: this fresh frame never reached a controller-visible pointer.
            unsafe { pmm::setup::free_contig(pa, pmm::Order(0)); }
            return None;
        }
        // SAFETY: `pa` is this page's fresh PMM allocation and no controller can
        // access it before the caller publishes its physical address later.
        unsafe { for byte in 0..PAGE { write_volatile((va + byte) as *mut u8, 0); } }
        Some(Self { pa })
    }

    /// Physical address suitable for 64-byte-aligned xHCI pointers. # C: O(1)
    pub fn pa(&self) -> u64 { self.pa }
}

impl Drop for DmaPage {
    fn drop(&mut self) {
        if self.pa != 0 {
            // SAFETY: DmaPage ownership requires its holder to quiesce the
            // controller before drop; this page is no longer DMA-reachable.
            unsafe { pmm::setup::free_contig(self.pa, pmm::Order(0)); }
            self.pa = 0;
        }
    }
}

/// Owned BAR0 mapping plus the validated controller register geometry.
pub struct Mmio { mapping: mmio_map::Mapping, geometry: Geometry, bytes: u64 }

impl Mmio {
    /// Map BAR0 and decode its capability block before exposing any registers.
    /// # Safety: `bar_pa..bar_pa+bar_bytes` is the caller-owned xHCI BAR0 range.
    /// # C: O(BAR pages)
    pub unsafe fn map(bar_pa: u64, bar_bytes: u64) -> Option<Self> {
        if bar_pa & (PAGE - 1) != 0 || bar_bytes < PAGE { return None; }
        let pages = bar_bytes.checked_add(PAGE - 1)?.checked_div(PAGE)?;
        // SAFETY: caller proves exclusive ownership of this page-aligned BAR range.
        let mapping = unsafe { mmio_map::map_owned(bar_pa, pages) };
        let base = mapping.base_va();
        // SAFETY: every dword is inside the first capability page of this owned mapping.
        let caplength = unsafe { read_volatile((base + CAPLENGTH) as *const u8) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let hcsparams1 = unsafe { read_volatile((base + HCSPARAMS1) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let dboff = unsafe { read_volatile((base + DBOFF) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let rtsoff = unsafe { read_volatile((base + RTSOFF) as *const u32) };
        let geometry = geometry(bar_bytes, caplength, hcsparams1, dboff, rtsoff)?;
        Some(Self { mapping, geometry, bytes: bar_bytes })
    }

    /// Controller geometry decoded from the live capability registers. # C: O(1)
    pub fn geometry(&self) -> Geometry { self.geometry }

    /// Read one aligned dword that geometry has proven lies in BAR0. # C: O(1)
    pub fn read32(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 || offset.checked_add(4)? > self.bytes { return None; }
        // SAFETY: bounds/alignment were validated against this live owned BAR mapping.
        Some(unsafe { read_volatile((self.mapping.base_va() + offset) as *const u32) })
    }

    /// Write one aligned dword that geometry has proven lies in BAR0. # C: O(1)
    pub fn write32(&self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) { return false; }
        // SAFETY: bounds/alignment were validated against this live owned BAR mapping.
        unsafe { write_volatile((self.mapping.base_va() + offset) as *mut u32, value); }
        true
    }
}

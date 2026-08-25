use super::*;

/// Owned AMD-Vi register aperture. It is mapped as device memory and may only
/// be enabled after its device and command tables are programmed.
pub struct AmdViRegisters { map: mmio_map::Mapping }
impl AmdViRegisters {
    /// Map a validated IVRS register aperture. # C: O(page-table depth * pages)
    pub unsafe fn map(mmio_pa: u64) -> Option<Self> {
        if mmio_pa & (PAGE_BYTES - 1) != 0 { return None; }
        // SAFETY: caller proved IVRS ownership of this aligned AMD-Vi aperture.
        Some(Self { map: unsafe { mmio_map::map_owned(mmio_pa, MMIO_BYTES / PAGE_BYTES) } })
    }
    /// Volatile 64-bit register read. # C: O(1)
    pub fn read64(&self, offset: u64) -> Option<u64> {
        if offset & 7 != 0 || offset >= MMIO_BYTES { return None; }
        // SAFETY: offset is aligned and inside this owned Device mapping.
        Some(unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u64) })
    }
    /// Volatile 64-bit register write. # C: O(1)
    pub fn write64(&self, offset: u64, value: u64) -> bool {
        if offset & 7 != 0 || offset >= MMIO_BYTES { return false; }
        // SAFETY: offset is aligned and inside this owned Device mapping.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u64, value) }; true
    }
}


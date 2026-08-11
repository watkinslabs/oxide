const PAGE_BYTES: u64 = 4096;
const MMIO_BYTES: u64 = PAGE_BYTES;
const RTADDR: u64 = 0x20;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1c;
const GCMD_SET_ROOT_TABLE: u32 = 1 << 30;
const GCMD_TRANSLATION_ENABLE: u32 = 1 << 31;
const GSTS_ROOT_TABLE_PRESENT: u32 = 1 << 30;
const GSTS_TRANSLATION_ENABLED: u32 = 1 << 31;
const POLL_LIMIT: usize = 1_000_000;
const ROOT_TABLE_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Owned VT-d register aperture used by the initial root-table transition.
pub struct VtdRegisters { map: mmio_map::Mapping }
impl VtdRegisters {
    /// Map one aligned firmware-owned VT-d aperture.
    ///
    /// # SAFETY
    /// `mmio_pa` must identify an exclusively owned aligned VT-d MMIO range.
    /// # C: O(page-table depth * pages)
    pub unsafe fn map(mmio_pa: u64) -> Option<Self> {
        if mmio_pa & (PAGE_BYTES - 1) != 0 { return None; }
        // SAFETY: caller validated this aligned VT-d register aperture from firmware.
        Some(Self { map: unsafe { mmio_map::map_owned(mmio_pa, 1) } })
    }
    /// Program the root table and wait until hardware acknowledges it. # C: O(poll limit)
    pub fn set_root_table(&self, root_pa: u64) -> bool {
        if root_pa & (PAGE_BYTES - 1) != 0 || root_pa & !ROOT_TABLE_MASK != 0 { return false; }
        if !self.write64(RTADDR, root_pa) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_SET_ROOT_TABLE) { return false; }
        self.wait_status(GSTS_ROOT_TABLE_PRESENT, true)
    }
    /// Enable DMA translation after a root/context tree has been acknowledged. # C: O(poll limit)
    pub fn enable_translation(&self) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_ROOT_TABLE_PRESENT == 0) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_TRANSLATION_ENABLE) { return false; }
        self.wait_status(GSTS_TRANSLATION_ENABLED, true)
    }
    fn wait_status(&self, bit: u32, wanted: bool) -> bool {
        for _ in 0..POLL_LIMIT {
            let Some(status) = self.read32(GSTS) else { return false; };
            if (status & bit != 0) == wanted { return true; }
            core::hint::spin_loop();
        }
        false
    }
    fn read32(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 || offset >= MMIO_BYTES { return None; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        Some(unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u32) })
    }
    fn write32(&self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 || offset >= MMIO_BYTES { return false; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u32, value) }; true
    }
    fn write64(&self, offset: u64, value: u64) -> bool {
        if offset & 7 != 0 || offset >= MMIO_BYTES { return false; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u64, value) }; true
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn root_table_requires_a_52_bit_page_aligned_physical_address() {
        assert_eq!(ROOT_TABLE_MASK & (PAGE_BYTES - 1), 0);
        assert_eq!(GCMD_SET_ROOT_TABLE, 1 << 30);
        assert_eq!(GCMD_TRANSLATION_ENABLE, 1 << 31);
    }
}

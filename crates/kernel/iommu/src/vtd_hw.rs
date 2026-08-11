const PAGE_BYTES: u64 = 4096;
const RTADDR: u64 = 0x20;
const CAP: u64 = 0x08;
const ECAP: u64 = 0x10;
const CCMD: u64 = 0x28;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1c;
const GCMD_SET_ROOT_TABLE: u32 = 1 << 30;
const GCMD_TRANSLATION_ENABLE: u32 = 1 << 31;
const GSTS_ROOT_TABLE_PRESENT: u32 = 1 << 30;
const GSTS_TRANSLATION_ENABLED: u32 = 1 << 31;
const CCMD_INVALIDATE: u64 = 1 << 63;
const CCMD_GLOBAL: u64 = 1 << 61;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_WRITE_DRAIN: u64 = 1 << 48;
const POLL_LIMIT: usize = 1_000_000;
const ROOT_TABLE_MASK: u64 = 0x000f_ffff_ffff_f000;
const ROOT_PRESENT: u64 = 1;
const CONTEXT_PRESENT: u64 = 1;
const CONTEXT_TRANSLATION_MULTI_LEVEL: u64 = 0;
const CONTEXT_ADDRESS_WIDTH_MASK: u64 = 0x7;
const CONTEXT_DOMAIN_ID_SHIFT: u64 = 8;

/// Hardware-format 16-byte VT-d root-table entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdRootEntry { words: [u64; 2] }
impl VtdRootEntry {
    /// Construct a present root entry for one page-aligned context table. # C: O(1)
    pub const fn context_table(context_pa: u64) -> Option<Self> {
        if context_pa & (PAGE_BYTES - 1) != 0 || context_pa & !ROOT_TABLE_MASK != 0 { return None; }
        Some(Self { words: [context_pa | ROOT_PRESENT, 0] })
    }
    /// Return the little-endian hardware words. # C: O(1)
    pub const fn words(self) -> [u64; 2] { self.words }
}

/// Hardware-format 16-byte VT-d legacy context-table entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdContextEntry { words: [u64; 2] }
impl VtdContextEntry {
    /// Construct a present multi-level translation context for one domain. # C: O(1)
    pub const fn translated(root_pa: u64, address_width: u8, domain_id: u16) -> Option<Self> {
        if root_pa & (PAGE_BYTES - 1) != 0 || root_pa & !ROOT_TABLE_MASK != 0 || address_width > CONTEXT_ADDRESS_WIDTH_MASK as u8 { return None; }
        let lo = CONTEXT_PRESENT | (CONTEXT_TRANSLATION_MULTI_LEVEL << 2) | root_pa;
        let hi = (address_width as u64 & CONTEXT_ADDRESS_WIDTH_MASK) | ((domain_id as u64) << CONTEXT_DOMAIN_ID_SHIFT);
        Some(Self { words: [lo, hi] })
    }
    /// Return the little-endian hardware words. # C: O(1)
    pub const fn words(self) -> [u64; 2] { self.words }
}

/// Owned VT-d register aperture used by the initial root-table transition.
pub struct VtdRegisters { map: mmio_map::Mapping, bytes: u64 }
impl VtdRegisters {
    /// Map the exact firmware-advertised VT-d register aperture.
    ///
    /// # SAFETY
    /// `mmio_pa` must identify an exclusively owned aligned VT-d MMIO range.
    /// # C: O(page-table depth * pages)
    pub unsafe fn map(mmio_pa: u64, pages: u64) -> Option<Self> {
        let bytes = pages.checked_mul(PAGE_BYTES)?;
        if mmio_pa & (PAGE_BYTES - 1) != 0 || pages == 0 { return None; }
        // SAFETY: caller validated this aligned VT-d register aperture from firmware.
        Some(Self { map: unsafe { mmio_map::map_owned(mmio_pa, pages) }, bytes })
    }
    /// Program the root table and wait until hardware acknowledges it. # C: O(poll limit)
    pub fn set_root_table(&self, root_pa: u64) -> bool {
        if root_pa & (PAGE_BYTES - 1) != 0 || root_pa & !ROOT_TABLE_MASK != 0 { return false; }
        if !self.write64(RTADDR, root_pa) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_SET_ROOT_TABLE) { return false; }
        self.wait_status(GSTS_ROOT_TABLE_PRESENT, true)
    }
    /// Return whether the hardware advertises this adjusted guest address width. # C: O(1)
    pub fn supports_address_width(&self, address_width: u8) -> bool {
        if address_width > 4 { return false; }
        self.read64(CAP).is_some_and(|cap| cap >> 8 & (1 << address_width) != 0)
    }
    /// Return whether the unit observes ordinary CPU stores to its page tables coherently. # C: O(1)
    pub fn cache_coherent(&self) -> bool { self.read64(ECAP).is_some_and(|ecap| ecap & 1 != 0) }
    /// Complete the global context and IOTLB invalidations required after root installation. # C: O(poll limit)
    pub fn invalidate_initial_tables(&self) -> bool {
        let Some(ecap) = self.read64(ECAP) else { return false; };
        if ecap >> 63 & 1 != 0 { return true; }
        if !self.write64(CCMD, CCMD_INVALIDATE | CCMD_GLOBAL) || !self.wait64_clear(CCMD, CCMD_INVALIDATE) { return false; }
        let iotlb = (ecap >> 8 & 0x3ff) * 16;
        if iotlb.checked_add(16).is_none_or(|end| end > self.bytes) { return false; }
        let write_drain = self.read64(CAP).is_some_and(|cap| cap >> 54 & 1 != 0);
        let command = IOTLB_INVALIDATE | IOTLB_GLOBAL | if write_drain { IOTLB_WRITE_DRAIN } else { 0 };
        if !self.write64(iotlb + 8, command) || !self.wait64_clear(iotlb + 8, IOTLB_INVALIDATE) { return false; }
        self.read64(iotlb + 8).is_some_and(|value| (value >> 57 & 0x3) == 1)
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
    fn wait64_clear(&self, offset: u64, bit: u64) -> bool {
        for _ in 0..POLL_LIMIT {
            let Some(value) = self.read64(offset) else { return false; };
            if value & bit == 0 { return true; }
            core::hint::spin_loop();
        }
        false
    }
    fn read32(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) { return None; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        Some(unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u32) })
    }
    fn write32(&self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) { return false; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u32, value) }; true
    }
    fn write64(&self, offset: u64, value: u64) -> bool {
        if offset & 7 != 0 || offset.checked_add(8).is_none_or(|end| end > self.bytes) { return false; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u64, value) }; true
    }
    fn read64(&self, offset: u64) -> Option<u64> {
        if offset & 7 != 0 || offset.checked_add(8).is_none_or(|end| end > self.bytes) { return None; }
        // SAFETY: offset is aligned and bounded within this device mapping.
        Some(unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u64) })
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn root_table_requires_a_52_bit_page_aligned_physical_address() {
        assert_eq!(ROOT_TABLE_MASK & (PAGE_BYTES - 1), 0);
        assert_eq!(GCMD_SET_ROOT_TABLE, 1 << 30);
        assert_eq!(GCMD_TRANSLATION_ENABLE, 1 << 31);
    }
    #[test] fn root_and_context_entries_preserve_hardware_layout() {
        let root = VtdRootEntry::context_table(0x1234_5000).unwrap();
        let context = VtdContextEntry::translated(0x2345_6000, 2, 7).unwrap();
        assert_eq!(core::mem::size_of::<VtdRootEntry>(), 16);
        assert_eq!(core::mem::size_of::<VtdContextEntry>(), 16);
        assert_eq!(root.words(), [0x1234_5001, 0]);
        assert_eq!(context.words(), [0x2345_6001, 0x702]);
        assert!(VtdContextEntry::translated(0x2345_6001, 2, 7).is_none());
    }
}

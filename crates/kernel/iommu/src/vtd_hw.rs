const PAGE_BYTES: u64 = 4096;
const RTADDR: u64 = 0x20;
const IQH: u64 = 0x80;
const IQT: u64 = 0x88;
const IQA: u64 = 0x90;
const CAP: u64 = 0x08;
const ECAP: u64 = 0x10;
const CCMD: u64 = 0x28;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1c;
const GCMD_SET_ROOT_TABLE: u32 = 1 << 30;
const GCMD_QUEUED_INVALIDATION_ENABLE: u32 = 1 << 26;
const GCMD_SET_INTERRUPT_REMAP_TABLE: u32 = 1 << 24;
const GCMD_INTERRUPT_REMAP_ENABLE: u32 = 1 << 25;
const GCMD_COMPATIBILITY_FORMAT_INTERRUPT: u32 = 1 << 23;
const GCMD_TRANSLATION_ENABLE: u32 = 1 << 31;
const GSTS_ROOT_TABLE_PRESENT: u32 = 1 << 30;
const GSTS_QUEUED_INVALIDATION_ENABLED: u32 = 1 << 26;
const GSTS_INTERRUPT_REMAP_TABLE_PRESENT: u32 = 1 << 24;
const GSTS_INTERRUPT_REMAP_ENABLED: u32 = 1 << 25;
const GSTS_COMPATIBILITY_FORMAT_INTERRUPT: u32 = 1 << 23;
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
const ECAP_QUEUED_INVALIDATION: u64 = 1 << 1;
const ECAP_INTERRUPT_REMAP: u64 = 1 << 3;
const ECAP_EXTENDED_INTERRUPT_MODE: u64 = 1 << 4;
const QI_DESC_BYTES: u64 = core::mem::size_of::<VtdQiDesc>() as u64;
const QI_DESC_COUNT: u16 = (PAGE_BYTES / QI_DESC_BYTES) as u16;

/// Hardware-format 16-byte VT-d queued-invalidation descriptor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdQiDesc { words: [u64; 2] }
impl VtdQiDesc {
    /// Build a global context-cache invalidation descriptor. # C: O(1)
    pub const fn global_context() -> Self { Self { words: [1, 0] } }
    /// Build a global IOTLB invalidation descriptor. # C: O(1)
    pub const fn global_iotlb() -> Self { Self { words: [(2u64) | (1 << 4), 0] } }
    /// Build a selective interrupt-entry-cache invalidation descriptor. # C: O(1)
    pub const fn interrupt_entry(index: u16, mask: u8) -> Self {
        Self { words: [4 | (1 << 4) | ((mask as u64 & 0x1f) << 27) | ((index as u64) << 32), 0] }
    }
    /// Return the little-endian hardware words. # C: O(1)
    #[cfg(test)]
    pub const fn words(self) -> [u64; 2] { self.words }
}

/// One permanent 256-entry queued-invalidation ring.  Its single page uses
/// IQA.QS=0, the VT-d encoding for 2^8 16-byte descriptors.
pub struct VtdQiQueue { pa: u64, hhdm_offset: u64, tail: u16 }
impl VtdQiQueue {
    /// Allocate and clear an IQA.QS=0 queue. # C: O(1)
    pub fn new(hhdm_offset: u64) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        // SAFETY: this page is permanently and exclusively owned as a VT-d QI ring.
        unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize); }
        Some(Self { pa, hhdm_offset, tail: 0 })
    }
    /// Physical IQA base. # C: O(1)
    pub const fn pa(&self) -> u64 { self.pa }
    fn publish(&mut self, descs: &[VtdQiDesc]) -> Option<u64> {
        if descs.is_empty() || descs.len() >= QI_DESC_COUNT as usize { return None; }
        let start = self.tail;
        for desc in descs {
            let slot = self.tail as u64;
            let va = self.hhdm_offset.checked_add(self.pa)?.checked_add(slot * QI_DESC_BYTES)? as *mut VtdQiDesc;
            // SAFETY: tail is always reduced modulo QI_DESC_COUNT and this QI page is exclusive.
            unsafe { core::ptr::write_volatile(va, *desc); }
            self.tail = (self.tail + 1) % QI_DESC_COUNT;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        Some(u64::from(self.tail) * QI_DESC_BYTES).filter(|_| start != self.tail)
    }
}

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
    /// Return whether ECAP advertises queued invalidation. # C: O(1)
    pub fn supports_queued_invalidation(&self) -> bool {
        self.read64(ECAP).is_some_and(|ecap| ecap & ECAP_QUEUED_INVALIDATION != 0)
    }
    /// Return whether this unit supports interrupt remapping. # C: O(1)
    pub fn supports_interrupt_remapping(&self) -> bool { self.read64(ECAP).is_some_and(|ecap| ecap & ECAP_INTERRUPT_REMAP != 0) }
    /// Return whether this unit supports x2APIC extended interrupt mode. # C: O(1)
    pub fn supports_extended_interrupt_mode(&self) -> bool { self.read64(ECAP).is_some_and(|ecap| ecap & ECAP_EXTENDED_INTERRUPT_MODE != 0) }
    /// Program IQA and enable queued invalidation. # C: O(poll limit)
    pub fn enable_queued_invalidation(&self, queue: &VtdQiQueue) -> bool {
        if !self.supports_queued_invalidation() || queue.pa() & (PAGE_BYTES - 1) != 0 { return false; }
        if !self.write64(IQA, queue.pa()) || !self.write64(IQH, 0) || !self.write64(IQT, 0) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_QUEUED_INVALIDATION_ENABLE) { return false; }
        self.wait_status(GSTS_QUEUED_INVALIDATION_ENABLED, true)
    }
    /// Program IRTA and wait for the hardware to latch it. # C: O(poll limit)
    pub fn set_interrupt_remap_table(&self, irta: u64) -> bool {
        if !self.supports_interrupt_remapping() || irta & 0xfff != 0xf { return false; }
        if !self.write64(0xb8, irta) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_SET_INTERRUPT_REMAP_TABLE) { return false; }
        self.wait_status(GSTS_INTERRUPT_REMAP_TABLE_PRESENT, true)
    }
    /// Enable IR and block compatibility-format messages. # C: O(poll limit)
    pub fn enable_interrupt_remapping(&self) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_INTERRUPT_REMAP_TABLE_PRESENT == 0) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_INTERRUPT_REMAP_ENABLE) || !self.wait_status(GSTS_INTERRUPT_REMAP_ENABLED, true) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command & !GCMD_COMPATIBILITY_FORMAT_INTERRUPT) { return false; }
        self.wait_status(GSTS_COMPATIBILITY_FORMAT_INTERRUPT, false)
    }
    /// Disable interrupt remapping after an unsuccessful boot-path transition.
    /// This follows Linux's `iommu_disable_irq_remapping()`: invalidate the
    /// interrupt-entry cache at the caller, then clear IRE and wait until the
    /// unit no longer reports remapping enabled. # C: O(poll limit)
    pub fn disable_interrupt_remapping(&self) -> bool {
        if !self.supports_interrupt_remapping() { return true; }
        let Some(status) = self.read32(GSTS) else { return false; };
        if status & GSTS_INTERRUPT_REMAP_ENABLED == 0 { return true; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command & !GCMD_INTERRUPT_REMAP_ENABLE) { return false; }
        self.wait_status(GSTS_INTERRUPT_REMAP_ENABLED, false)
    }
    /// Complete the global context and IOTLB invalidations required after root installation. # C: O(poll limit)
    pub fn invalidate_initial_tables(&self) -> bool {
        let Some(ecap) = self.read64(ECAP) else { return false; };
        if !self.write64(CCMD, CCMD_INVALIDATE | CCMD_GLOBAL) || !self.wait64_clear(CCMD, CCMD_INVALIDATE) { return false; }
        let iotlb = (ecap >> 8 & 0x3ff) * 16;
        if iotlb.checked_add(16).is_none_or(|end| end > self.bytes) { return false; }
        let write_drain = self.read64(CAP).is_some_and(|cap| cap >> 54 & 1 != 0);
        let command = IOTLB_INVALIDATE | IOTLB_GLOBAL | if write_drain { IOTLB_WRITE_DRAIN } else { 0 };
        if !self.write64(iotlb + 8, command) || !self.wait64_clear(iotlb + 8, IOTLB_INVALIDATE) { return false; }
        self.read64(iotlb + 8).is_some_and(|value| (value >> 57 & 0x3) == 1)
    }
    /// Complete global context and IOTLB invalidation after a live page-table change. # C: O(poll limit)
    pub fn invalidate_live_mapping(&self) -> bool { self.invalidate_initial_tables() }
    /// Submit global context and IOTLB invalidations to the enabled QI ring. # C: O(poll limit)
    pub fn invalidate_queued(&self, queue: &mut VtdQiQueue) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_QUEUED_INVALIDATION_ENABLED == 0) { return false; }
        let Some(tail) = queue.publish(&[VtdQiDesc::global_context(), VtdQiDesc::global_iotlb()]) else { return false; };
        if !self.write64(IQT, tail) { return false; }
        for _ in 0..POLL_LIMIT {
            if self.read64(IQH).is_some_and(|head| head == tail) { return true; }
            core::hint::spin_loop();
        }
        false
    }
    /// Invalidate one interrupt-entry-cache record after an IRTE publication. # C: O(poll limit)
    pub fn invalidate_interrupt_entry(&self, queue: &mut VtdQiQueue, index: u16) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_QUEUED_INVALIDATION_ENABLED == 0) { return false; }
        let Some(tail) = queue.publish(&[VtdQiDesc::interrupt_entry(index, 0)]) else { return false; };
        if !self.write64(IQT, tail) { return false; }
        for _ in 0..POLL_LIMIT {
            if self.read64(IQH).is_some_and(|head| head == tail) { return true; }
            core::hint::spin_loop();
        }
        false
    }
    /// Enable DMA translation after a root/context tree has been acknowledged. # C: O(poll limit)
    pub fn enable_translation(&self) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_ROOT_TABLE_PRESENT == 0) { return false; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command | GCMD_TRANSLATION_ENABLE) { return false; }
        self.wait_status(GSTS_TRANSLATION_ENABLED, true)
    }
    /// Disable DMA translation before discarding boot-owned root and context tables.
    /// This is the VT-d `iommu_disable_translation()` transition Linux performs
    /// while unwinding an unsuccessfully initialized DRHD. # C: O(poll limit)
    pub fn disable_translation(&self) -> bool {
        let Some(status) = self.read32(GSTS) else { return false; };
        if status & GSTS_TRANSLATION_ENABLED == 0 { return true; }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command & !GCMD_TRANSLATION_ENABLE) { return false; }
        self.wait_status(GSTS_TRANSLATION_ENABLED, false)
    }
    /// Drain and disable queued invalidation before its permanent ring is discarded.
    /// This follows Linux's `dmar_disable_qi()` and is deliberately best effort
    /// when called from a failed boot-path transition. # C: O(poll limit)
    pub fn disable_queued_invalidation(&self) -> bool {
        if !self.supports_queued_invalidation() { return true; }
        let Some(status) = self.read32(GSTS) else { return false; };
        if status & GSTS_QUEUED_INVALIDATION_ENABLED == 0 { return true; }
        for _ in 0..POLL_LIMIT {
            let (Some(head), Some(tail)) = (self.read64(IQH), self.read64(IQT)) else { return false; };
            if head == tail { break; }
            core::hint::spin_loop();
        }
        let Some(command) = self.read32(GCMD) else { return false; };
        if !self.write32(GCMD, command & !GCMD_QUEUED_INVALIDATION_ENABLE) { return false; }
        self.wait_status(GSTS_QUEUED_INVALIDATION_ENABLED, false)
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
    #[test] fn queued_invalidation_register_and_descriptor_layout_matches_vtd() {
        assert_eq!((IQH, IQT, IQA), (0x80, 0x88, 0x90));
        assert_eq!(GCMD_QUEUED_INVALIDATION_ENABLE, GSTS_QUEUED_INVALIDATION_ENABLED);
        assert_eq!(core::mem::size_of::<VtdQiDesc>(), 16);
        assert_eq!(VtdQiDesc::global_context().words(), [1, 0]);
        assert_eq!(VtdQiDesc::global_iotlb().words(), [0x12, 0]);
        assert_eq!(QI_DESC_COUNT, 256);
    }
}

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
const FSTS: u64 = 0x34;
const FECTL: u64 = 0x38;
const FEDATA: u64 = 0x3c;
const FEADDR: u64 = 0x40;
const FEUADDR: u64 = 0x44;
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
const IOTLB_READ_DRAIN: u64 = 1 << 49;
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
const CAP_WRITE_DRAIN: u64 = 1 << 54;
const CAP_READ_DRAIN: u64 = 1 << 55;
const CAP_ENHANCED_IRTA_POINTER: u64 = 1 << 63;
const FECTL_INTERRUPT_MASK: u32 = 1 << 31;
const FSTS_PRIMARY_OVERFLOW: u32 = 1 << 0;
const FSTS_PRIMARY_PENDING: u32 = 1 << 1;
const FSTS_PAGE_REQUEST_OVERFLOW: u32 = 1 << 7;
const FSTS_PRIMARY_INDEX_SHIFT: u32 = 8;
const FSTS_PRIMARY_INDEX_MASK: u32 = 0xff;
const FAULT_RECORD_VALID: u32 = 1 << 31;
const FAULT_RECORD_BYTES: u64 = 16;
const QI_DESC_BYTES: u64 = core::mem::size_of::<VtdQiDesc>() as u64;
const QI_DESC_COUNT: u16 = (PAGE_BYTES / QI_DESC_BYTES) as u16;
const QI_DONE: u32 = 2;

fn primary_fault_layout(cap: u64, aperture_bytes: u64) -> Option<(u64, u16)> {
    let base = ((cap >> 24) & 0x3ff).checked_mul(FAULT_RECORD_BYTES)?;
    let count = u16::try_from(((cap >> 40) & 0xff) + 1).ok()?;
    base.checked_add(u64::from(count).checked_mul(FAULT_RECORD_BYTES)?)
        .filter(|end| *end <= aperture_bytes).map(|_| (base, count))
}

/// Hardware-format 16-byte VT-d queued-invalidation descriptor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdQiDesc { words: [u64; 2] }
impl VtdQiDesc {
    /// Build a global context-cache invalidation descriptor. # C: O(1)
    pub const fn global_context() -> Self { Self { words: [1 | (1 << 4), 0] } }
    /// Build a global IOTLB invalidation descriptor. # C: O(1)
    pub const fn global_iotlb(read_drain: bool, write_drain: bool) -> Self {
        let drains = (read_drain as u64) << 7 | (write_drain as u64) << 6;
        Self { words: [(2u64) | (1 << 4) | drains, 0] }
    }
    /// Build a completion-writing wait descriptor for a synchronized submission. # C: O(1)
    pub const fn wait(status_pa: u64) -> Option<Self> {
        if status_pa & 3 != 0 || status_pa & !ROOT_TABLE_MASK != 0 { return None; }
        Some(Self { words: [(5u64) | (1 << 5) | ((QI_DONE as u64) << 32), status_pa] })
    }
    /// Build a global interrupt-entry-cache invalidation descriptor. # C: O(1)
    pub const fn global_interrupt_entry() -> Self { Self { words: [4, 0] } }
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
pub struct VtdQiQueue { pa: u64, status_pa: u64, hhdm_offset: u64, coherent: bool, tail: u16 }
impl VtdQiQueue {
    /// Allocate and clear an IQA.QS=0 queue. # C: O(1)
    pub fn new(hhdm_offset: u64, coherent: bool) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let status_pa = match pmm::setup::alloc_contig(pmm::Order(0)) {
            Some(pa) => pa,
            None => {
                // SAFETY: this queue has not published or shared its first owned frame.
                unsafe { pmm::setup::free_one_frame(pa); }
                return None;
            }
        };
        // SAFETY: this page is permanently and exclusively owned as a VT-d QI ring.
        unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize); }
        publish(hhdm_offset, pa, PAGE_BYTES, coherent);
        // SAFETY: this permanent page has one completion word owned by this serialized queue.
        unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(status_pa) as *mut u8, 0, PAGE_BYTES as usize); }
        publish(hhdm_offset, status_pa, PAGE_BYTES, coherent);
        Some(Self { pa, status_pa, hhdm_offset, coherent, tail: 0 })
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
            publish(self.hhdm_offset, self.pa + slot * QI_DESC_BYTES, QI_DESC_BYTES, self.coherent);
            self.tail = (self.tail + 1) % QI_DESC_COUNT;
        }
        Some(u64::from(self.tail) * QI_DESC_BYTES).filter(|_| start != self.tail)
    }
    /// Publish invalidations plus a wait completion record. # C: O(descriptors)
    pub fn submit_sync(&mut self, descs: &[VtdQiDesc]) -> Option<u64> {
        if descs.len().checked_add(1)? >= QI_DESC_COUNT as usize { return None; }
        // SAFETY: this queue owns the completion word and serializes every submission.
        unsafe { core::ptr::write_volatile(self.hhdm_offset.wrapping_add(self.status_pa) as *mut u32, 0); }
        publish(self.hhdm_offset, self.status_pa, core::mem::size_of::<u32>() as u64, self.coherent);
        let wait = VtdQiDesc::wait(self.status_pa)?;
        let start = self.tail;
        for desc in descs { self.publish(core::slice::from_ref(desc))?; }
        self.publish(core::slice::from_ref(&wait)).filter(|_| start != self.tail)
    }
    /// Return whether the wait descriptor has observed terminal completion. # C: O(1)
    pub fn completed(&self) -> bool {
        pmm::dma::invalidate_from_device(self.hhdm_offset.wrapping_add(self.status_pa), core::mem::size_of::<u32>());
        // SAFETY: this queue owns the completion word until the next serialized submission resets it.
        unsafe { core::ptr::read_volatile(self.hhdm_offset.wrapping_add(self.status_pa) as *const u32) == QI_DONE }
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
    /// Quiesce firmware-owned remapping state before replacement tables are
    /// programmed.
    ///
    /// Match Linux's VT-d teardown ordering: interrupt remapping must stop
    /// using the old IRTA, translation must stop using the old root/context
    /// tree, and queued invalidation must stop consuming the old IQA.  The
    /// PCI bootstrap has already disabled bus mastering for every requester.
    /// # C: O(poll limit)
    pub fn quiesce_firmware_state(&self) -> bool {
        self.disable_fault_interrupts()
            && self.disable_interrupt_remapping()
            && self.disable_translation()
            && self.disable_queued_invalidation()
    }
    /// Mask primary-fault delivery while table ownership changes. # C: O(1)
    pub fn disable_fault_interrupts(&self) -> bool {
        let Some(control) = self.read32(FECTL) else { return false; };
        self.write32(FECTL, control | FECTL_INTERRUPT_MASK)
    }
    /// Program and unmask the architected VT-d primary-fault MSI message. # C: O(1)
    pub fn enable_fault_interrupts(&self, address: u64, data: u32) -> bool {
        if !self.write32(FEADDR, address as u32) || !self.write32(FEUADDR, (address >> 32) as u32)
            || !self.write32(FEDATA, data) { return false; }
        let Some(control) = self.read32(FECTL) else { return false; };
        self.write32(FECTL, control & !FECTL_INTERRUPT_MASK)
    }
    /// Drain valid primary fault records and acknowledge their status bits. # C: O(fault records)
    pub fn drain_primary_faults(&self, visitor: &mut impl FnMut(crate::VtdFault)) -> bool {
        let (Some(cap), Some(status)) = (self.read64(CAP), self.read32(FSTS)) else { return false; };
        if status & FSTS_PRIMARY_PENDING == 0 { return true; }
        let Some((base, count)) = primary_fault_layout(cap, self.bytes) else { return false; };
        let mut index = ((status >> FSTS_PRIMARY_INDEX_SHIFT) & FSTS_PRIMARY_INDEX_MASK) as u16;
        if index >= count { return false; }
        for _ in 0..count {
            let Some(record) = base.checked_add(u64::from(index) * FAULT_RECORD_BYTES) else { return false; };
            let Some(word3) = self.read32(record + 12) else { return false; };
            if word3 & FAULT_RECORD_VALID == 0 { break; }
            let (Some(word0), Some(word1), Some(word2)) = (self.read32(record), self.read32(record + 4), self.read32(record + 8)) else { return false; };
            let fault = crate::VtdFault::from_words([word0, word1, word2, word3]);
            if !self.write32(record + 12, FAULT_RECORD_VALID) { return false; }
            visitor(fault);
            index = (index + 1) % count;
        }
        self.write32(FSTS, FSTS_PRIMARY_OVERFLOW | FSTS_PRIMARY_PENDING | FSTS_PAGE_REQUEST_OVERFLOW)
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
    pub fn supports_address_width(&self, address_width: u8) -> bool { self.read64(CAP).is_some_and(|cap| address_width_supported(cap, address_width)) }
    /// Select the widest supported second-level address width at or below `maximum`. # C: O(5)
    pub fn select_address_width(&self, maximum: u8) -> Option<u8> { self.read64(CAP).and_then(|cap| select_address_width(cap, maximum)) }
    /// Return the second-level superpage sizes the active unit advertises. # C: O(1)
    pub fn page_sizes(&self) -> crate::VtdPageSizes { self.read64(CAP).map_or(crate::VtdPageSizes::from_sllps(0), |cap| crate::VtdPageSizes::from_sllps(((cap >> 34) & 0xf) as u8)) }
    /// Return whether the unit observes ordinary CPU stores to its page tables coherently. # C: O(1)
    pub fn cache_coherent(&self) -> bool { self.read64(ECAP).is_some_and(|ecap| ecap & 1 != 0) }
    /// Return whether ECAP advertises queued invalidation. # C: O(1)
    pub fn supports_queued_invalidation(&self) -> bool {
        self.read64(ECAP).is_some_and(|ecap| ecap & ECAP_QUEUED_INVALIDATION != 0)
    }
    /// Return whether this unit supports interrupt remapping. # C: O(1)
    pub fn supports_interrupt_remapping(&self) -> bool { self.read64(ECAP).is_some_and(|ecap| ecap & ECAP_INTERRUPT_REMAP != 0) }
    /// Return whether the unit atomically switches IRTA without a global IEC flush. # C: O(1)
    pub fn supports_enhanced_irta_pointer(&self) -> bool { self.read64(CAP).is_some_and(|cap| cap & CAP_ENHANCED_IRTA_POINTER != 0) }
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
        let Some(cap) = self.read64(CAP) else { return false; };
        let command = IOTLB_INVALIDATE | IOTLB_GLOBAL
            | if cap & CAP_WRITE_DRAIN != 0 { IOTLB_WRITE_DRAIN } else { 0 }
            | if cap & CAP_READ_DRAIN != 0 { IOTLB_READ_DRAIN } else { 0 };
        if !self.write64(iotlb + 8, command) || !self.wait64_clear(iotlb + 8, IOTLB_INVALIDATE) { return false; }
        self.read64(iotlb + 8).is_some_and(|value| (value >> 57 & 0x3) == 1)
    }
    /// Complete global context and IOTLB invalidation after a live page-table change. # C: O(poll limit)
    pub fn invalidate_live_mapping(&self) -> bool { self.invalidate_initial_tables() }
    /// Submit global context and IOTLB invalidations to the enabled QI ring. # C: O(poll limit)
    pub fn invalidate_queued(&self, queue: &mut VtdQiQueue) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_QUEUED_INVALIDATION_ENABLED == 0) { return false; }
        let Some(cap) = self.read64(CAP) else { return false; };
        let Some(tail) = queue.submit_sync(&[VtdQiDesc::global_context(), VtdQiDesc::global_iotlb(cap & CAP_READ_DRAIN != 0, cap & CAP_WRITE_DRAIN != 0)]) else { return false; };
        if !self.write64(IQT, tail) { return false; }
        for _ in 0..POLL_LIMIT {
            if queue.completed() { return true; }
            core::hint::spin_loop();
        }
        false
    }
    /// Invalidate one interrupt-entry-cache record after an IRTE publication. # C: O(poll limit)
    pub fn invalidate_interrupt_entry(&self, queue: &mut VtdQiQueue, index: u16) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_QUEUED_INVALIDATION_ENABLED == 0) { return false; }
        let Some(tail) = queue.submit_sync(&[VtdQiDesc::interrupt_entry(index, 0)]) else { return false; };
        if !self.write64(IQT, tail) { return false; }
        for _ in 0..POLL_LIMIT {
            if queue.completed() { return true; }
            core::hint::spin_loop();
        }
        false
    }
    /// Invalidate the whole interrupt-entry cache after an IRTA replacement. # C: O(poll limit)
    pub fn invalidate_interrupt_entries(&self, queue: &mut VtdQiQueue) -> bool {
        if self.read32(GSTS).is_none_or(|status| status & GSTS_QUEUED_INVALIDATION_ENABLED == 0) { return false; }
        let Some(tail) = queue.submit_sync(&[VtdQiDesc::global_interrupt_entry()]) else { return false; };
        if !self.write64(IQT, tail) { return false; }
        for _ in 0..POLL_LIMIT {
            if queue.completed() { return true; }
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

fn address_width_bits(address_width: u8) -> Option<u8> { 30u8.checked_add(address_width.checked_mul(9)?) }
fn address_width_supported(cap: u64, address_width: u8) -> bool {
    if address_width > 4 || cap >> 8 & (1 << address_width) == 0 { return false; }
    let mgaw = ((cap >> 16) & 0x3f) as u8 + 1;
    address_width_bits(address_width).is_some_and(|bits| bits <= mgaw)
}
fn select_address_width(cap: u64, maximum: u8) -> Option<u8> {
    let mut width = maximum.min(4);
    loop {
        if address_width_supported(cap, width) { return Some(width); }
        if width == 0 { return None; }
        width -= 1;
    }
}

#[cfg(test)]
mod fault_tests {
    use super::*;

    #[test]
    fn primary_fault_layout_uses_capability_encoded_offset_and_count() {
        let cap = (0x120u64 << 24) | (3u64 << 40);
        assert_eq!(primary_fault_layout(cap, 0x2000), Some((0x1200, 4)));
        assert_eq!(primary_fault_layout(cap, 0x123f), None);
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
    #[test] fn second_level_layout_respects_mgaw_and_superpage_capability() {
        let cap = (1u64 << 9) | (38u64 << 16) | (1u64 << 34);
        assert_eq!(select_address_width(cap, 2), Some(1));
        assert!(!address_width_supported(cap, 2));
        assert_eq!(crate::VtdPageSizes::from_sllps(((cap >> 34) & 0xf) as u8), crate::VtdPageSizes::from_sllps(1));
    }
    #[test] fn queued_invalidation_register_and_descriptor_layout_matches_vtd() {
        assert_eq!((IQH, IQT, IQA), (0x80, 0x88, 0x90));
        assert_eq!(GCMD_QUEUED_INVALIDATION_ENABLE, GSTS_QUEUED_INVALIDATION_ENABLED);
        assert_eq!(core::mem::size_of::<VtdQiDesc>(), 16);
        assert_eq!(VtdQiDesc::global_context().words(), [1 | (1 << 4), 0]);
        assert_eq!(VtdQiDesc::global_iotlb(true, true).words(), [0xd2, 0]);
        assert_eq!(VtdQiDesc::global_iotlb(false, false).words(), [0x12, 0]);
        assert_eq!(VtdQiDesc::wait(0x1234_5000).unwrap().words(), [0x0000_0002_0000_0025, 0x1234_5000]);
        assert_eq!(VtdQiDesc::global_interrupt_entry().words(), [4, 0]);
        assert_eq!(QI_DESC_COUNT, 256);
    }
}
use crate::vtd_cache::publish;

/// AMD-Vi MMIO register offsets used by the initial translation path.
pub const DEVICE_TABLE: u64 = 0x0000;
pub const COMMAND_BUFFER: u64 = 0x0008;
pub const EVENT_LOG: u64 = 0x0010;
pub const CONTROL: u64 = 0x0018;
pub const COMMAND_HEAD: u64 = 0x2000;
pub const COMMAND_TAIL: u64 = 0x2008;
pub const EVENT_HEAD: u64 = 0x2010;
pub const EVENT_TAIL: u64 = 0x2018;
pub const CONTROL_IOMMU_ENABLE: u64 = 1 << 0;
pub const CONTROL_EVENT_ENABLE: u64 = 1 << 2;
pub const CONTROL_COMMAND_ENABLE: u64 = 1 << 12;
const MMIO_BYTES: u64 = 0x80000;
const PAGE_BYTES: u64 = 4096;
const DEVICE_TABLE_BYTES: u64 = 2 * 1024 * 1024;
const COMMAND_BUFFER_BYTES: u64 = 8192;
const EVENT_LOG_BYTES: u64 = 8192;
const DEVICE_TABLE_ORDER: u8 = 9;
const BUFFER_ORDER: u8 = 1;
const BUFFER_SIZE_ENCODING: u64 = 0x9 << 56;
const DTE_VALID: u64 = 1 << 0;
const DTE_TRANSLATION_VALID: u64 = 1 << 1;
const DTE_PAGE_MODE_SHIFT: u64 = 9;
const DTE_PAGE_MODE_MASK: u64 = 0x7 << DTE_PAGE_MODE_SHIFT;
const DTE_ROOT_MASK: u64 = 0x000f_ffff_ffff_f000;
const DTE_READ: u64 = 1 << 61;
const DTE_WRITE: u64 = 1 << 62;
const DTE_DOMAIN_MASK: u64 = 0xffff;

/// Hardware-format AMD-Vi device-table entry.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdViDte { words: [u64; 4] }
impl AmdViDte {
    /// Construct a translation-disabled entry that rejects DMA. # C: O(1)
    pub const fn blocked() -> Self { Self { words: [0; 4] } }
    /// Construct an identity-domain entry for a requester that must bypass paging. # C: O(1)
    pub const fn passthrough(domain_id: u16) -> Self {
        Self { words: [DTE_VALID | DTE_TRANSLATION_VALID | DTE_READ | DTE_WRITE, domain_id as u64, 0, 0] }
    }
    /// Construct a paging-domain entry with a 4K-aligned top-level page table. # C: O(1)
    pub const fn paging(root_pa: u64, page_mode: u8, domain_id: u16) -> Option<Self> {
        if root_pa & (PAGE_BYTES - 1) != 0 || root_pa & !DTE_ROOT_MASK != 0 || page_mode == 0 || page_mode > 7 { return None; }
        Some(Self { words: [DTE_VALID | DTE_TRANSLATION_VALID | ((page_mode as u64) << DTE_PAGE_MODE_SHIFT & DTE_PAGE_MODE_MASK)
            | (root_pa & DTE_ROOT_MASK) | DTE_READ | DTE_WRITE, domain_id as u64 & DTE_DOMAIN_MASK, 0, 0] })
    }
    /// Return the four little-endian hardware words. # C: O(1)
    pub const fn words(&self) -> [u64; 4] { self.words }
}

/// Permanent DMA-visible AMD-Vi tables. They remain allocated until the
/// owning unit is disabled and no requester can issue DMA through it.
pub struct AmdViTables { device_table_pa: u64, command_buffer_pa: u64, event_log_pa: u64 }
impl AmdViTables {
    /// Allocate and clear one full requester table plus command and event rings. # C: O(table bytes)
    pub fn allocate(hhdm_offset: u64) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let device_table_pa = pmm::setup::alloc_contig(pmm::Order(DEVICE_TABLE_ORDER))?;
        let Some(command_buffer_pa) = pmm::setup::alloc_contig(pmm::Order(BUFFER_ORDER)) else {
            // SAFETY: allocation was not published to hardware or any other owner.
            unsafe { pmm::setup::free_contig(device_table_pa, pmm::Order(DEVICE_TABLE_ORDER)); }
            return None;
        };
        let Some(event_log_pa) = pmm::setup::alloc_contig(pmm::Order(BUFFER_ORDER)) else {
            // SAFETY: neither allocation was published to hardware or any other owner.
            unsafe {
                pmm::setup::free_contig(command_buffer_pa, pmm::Order(BUFFER_ORDER));
                pmm::setup::free_contig(device_table_pa, pmm::Order(DEVICE_TABLE_ORDER));
            }
            return None;
        };
        // SAFETY: each direct-map span is a newly allocated exclusive PMM run.
        unsafe {
            core::ptr::write_bytes(hhdm_offset.wrapping_add(device_table_pa) as *mut u8, 0, DEVICE_TABLE_BYTES as usize);
            core::ptr::write_bytes(hhdm_offset.wrapping_add(command_buffer_pa) as *mut u8, 0, COMMAND_BUFFER_BYTES as usize);
            core::ptr::write_bytes(hhdm_offset.wrapping_add(event_log_pa) as *mut u8, 0, EVENT_LOG_BYTES as usize);
        }
        Some(Self { device_table_pa, command_buffer_pa, event_log_pa })
    }
    /// Construct table bases after validating permanent physical allocations. # C: O(1)
    pub const fn from_physical(device_table_pa: u64, command_buffer_pa: u64, event_log_pa: u64) -> Option<Self> {
        if device_table_pa & (DEVICE_TABLE_BYTES - 1) != 0 || command_buffer_pa & (PAGE_BYTES - 1) != 0 || event_log_pa & (PAGE_BYTES - 1) != 0 { return None; }
        Some(Self { device_table_pa, command_buffer_pa, event_log_pa })
    }
    /// Device-table base register value. # C: O(1)
    pub const fn device_table_register(&self) -> u64 { self.device_table_pa | ((DEVICE_TABLE_BYTES / PAGE_BYTES) - 1) }
    /// Command-ring base register value. # C: O(1)
    pub const fn command_buffer_register(&self) -> u64 { self.command_buffer_pa | BUFFER_SIZE_ENCODING }
    /// Event-log base register value. # C: O(1)
    pub const fn event_log_register(&self) -> u64 { self.event_log_pa | BUFFER_SIZE_ENCODING }
    const fn dte_byte_offset(requester: u16) -> u64 { requester as u64 * core::mem::size_of::<AmdViDte>() as u64 }
    unsafe fn write_initial_dte(&self, hhdm_offset: u64, requester: u16, dte: AmdViDte) {
        let base = hhdm_offset.wrapping_add(self.device_table_pa).wrapping_add(Self::dte_byte_offset(requester));
        let words = dte.words();
        // SAFETY: caller holds the disabled unit's exclusive device table before hardware can consume this DTE.
        unsafe {
            core::ptr::write_volatile(base as *mut u64, words[0]);
            core::ptr::write_volatile((base + 8) as *mut u64, words[1]);
            core::ptr::write_volatile((base + 16) as *mut u64, words[2]);
            core::ptr::write_volatile((base + 24) as *mut u64, words[3]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
}

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

/// Hardware activation state. Each transition corresponds to a required
/// completed ownership step; translation cannot precede attached domains.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViState { Discovered, Mapped, TablesProgrammed, DomainsAttached, Enabled }

pub struct AmdViUnit { pub mmio_pa: u64, pub segment: u16, state: AmdViState }
impl AmdViUnit {
    /// Construct a disabled unit from validated IVRS firmware data. # C: O(1)
    pub const fn new(mmio_pa: u64, segment: u16) -> Self {
        Self { mmio_pa, segment, state: AmdViState::Discovered }
    }
    /// Current activation state. # C: O(1)
    pub const fn state(&self) -> AmdViState { self.state }
    /// Advance after owned device MMIO mapping exists. # C: O(1)
    pub fn mapped(&mut self) -> bool { self.advance(AmdViState::Discovered, AmdViState::Mapped) }
    /// Install one DTE while translation remains disabled. # C: O(1)
    pub unsafe fn install_initial_dte(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, bdf: pci::Bdf, dte: AmdViDte) -> bool {
        if self.state != AmdViState::Mapped || bdf.segment != self.segment || hhdm_offset == 0 { return false; }
        if regs.read64(CONTROL).is_none_or(|control| control & CONTROL_IOMMU_ENABLE != 0) { return false; }
        // SAFETY: the state and register guard above prove this unit cannot consume its table yet.
        unsafe { tables.write_initial_dte(hhdm_offset, bdf.raw(), dte); }
        true
    }
    /// Program DMA-visible table bases and enable their command and event rings. # C: O(1)
    pub fn program_tables(&mut self, regs: &AmdViRegisters, tables: &AmdViTables) -> bool {
        if self.state != AmdViState::Mapped { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        if control & CONTROL_IOMMU_ENABLE != 0 { return false; }
        if !regs.write64(DEVICE_TABLE, tables.device_table_register()) || !regs.write64(COMMAND_BUFFER, tables.command_buffer_register()) || !regs.write64(EVENT_LOG, tables.event_log_register()) { return false; }
        if !regs.write64(COMMAND_HEAD, 0) || !regs.write64(COMMAND_TAIL, 0) || !regs.write64(EVENT_HEAD, 0) || !regs.write64(EVENT_TAIL, 0) { return false; }
        regs.write64(CONTROL, control | CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE)
            && self.advance(AmdViState::Mapped, AmdViState::TablesProgrammed)
    }
    /// Advance after every enabled requester has a domain DTE and invalidate completed. # C: O(1)
    pub fn domains_attached(&mut self) -> bool { self.advance(AmdViState::TablesProgrammed, AmdViState::DomainsAttached) }
    /// Enable hardware translation after every active requester has an invalidated DTE. # C: O(1)
    pub fn enable_translation(&mut self, regs: &AmdViRegisters) -> bool {
        if self.state != AmdViState::DomainsAttached { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        if control & (CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE) != (CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE) { return false; }
        regs.write64(CONTROL, control | CONTROL_IOMMU_ENABLE)
            && self.advance(AmdViState::DomainsAttached, AmdViState::Enabled)
    }
    fn advance(&mut self, from: AmdViState, to: AmdViState) -> bool {
        if self.state != from { return false; }
        self.state = to; true
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn translation_requires_programmed_and_attached_domains() {
        let mut u = AmdViUnit::new(0xfed8_0000, 3);
        assert_eq!(u.state(), AmdViState::Discovered); assert!(u.mapped());
        assert!(!u.domains_attached()); assert_eq!(u.state(), AmdViState::Mapped);
    }
    #[test] fn table_registers_require_aligned_permanent_memory() {
        let t = AmdViTables::from_physical(0x4000_0000, 0x5000_0000, 0x5000_2000).unwrap();
        assert_eq!(t.device_table_register(), 0x4000_01ff);
        assert_eq!(t.command_buffer_register(), 0x0900_0000_5000_0000);
        assert!(AmdViTables::from_physical(0x4000_1000, 0x5000_0000, 0x5000_2000).is_none());
    }
    #[test] fn device_table_entries_preserve_the_32_byte_hardware_layout() {
        assert_eq!(core::mem::size_of::<AmdViDte>(), 32);
        assert_eq!(AmdViDte::blocked().words(), [0; 4]);
        assert_eq!(AmdViDte::passthrough(7).words()[1], 7);
        let dte = AmdViDte::paging(0x1234_5000, 4, 9).unwrap();
        assert_eq!(dte.words()[0] & DTE_ROOT_MASK, 0x1234_5000);
        assert_eq!(dte.words()[1], 9);
        assert!(AmdViDte::paging(0x1234_5001, 4, 9).is_none());
        assert_eq!(AmdViTables::dte_byte_offset(0x1234), 0x1234 * 32);
    }
}

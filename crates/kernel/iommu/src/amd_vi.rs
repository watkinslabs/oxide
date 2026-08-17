/// AMD-Vi MMIO register offsets used by the initial translation path.
pub const DEVICE_TABLE: u64 = 0x0000;
pub const COMMAND_BUFFER: u64 = 0x0008;
pub const EVENT_LOG: u64 = 0x0010;
pub const CONTROL: u64 = 0x0018;
pub const EXT_FEATURES: u64 = 0x0030;
pub const COMMAND_HEAD: u64 = 0x2000;
pub const COMMAND_TAIL: u64 = 0x2008;
pub const EVENT_HEAD: u64 = 0x2010;
pub const EVENT_TAIL: u64 = 0x2018;
pub const STATUS: u64 = 0x2020;
pub const CONTROL_IOMMU_ENABLE: u64 = 1 << 0;
pub const CONTROL_EVENT_ENABLE: u64 = 1 << 2;
pub const CONTROL_EVENT_INTERRUPT_ENABLE: u64 = 1 << 3;
pub const CONTROL_COMPLETION_ENABLE: u64 = 1 << 4;
pub const CONTROL_COHERENT_ENABLE: u64 = 1 << 10;
pub const CONTROL_COMMAND_ENABLE: u64 = 1 << 12;
const CONTROL_GA_ENABLE: u64 = 1 << 17;
const CONTROL_XT_ENABLE: u64 = 1 << 50;
const CONTROL_PPR_LOG_ENABLE: u64 = 1 << 13;
const CONTROL_PPR_INTERRUPT_ENABLE: u64 = 1 << 14;
const CONTROL_GA_LOG_ENABLE: u64 = 1 << 28;
const CONTROL_GA_INTERRUPT_ENABLE: u64 = 1 << 29;
const CONTROL_IRT_CACHE_DISABLE: u64 = 1 << 59;
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
const COMMAND_TYPE_SHIFT: u32 = 28;
const COMMAND_COMPLETION_WAIT: u32 = 0x01;
const COMMAND_INVALIDATE_DTE: u32 = 0x02;
const COMMAND_INVALIDATE_IOMMU_PAGES: u32 = 0x03;
const COMMAND_INVALIDATE_IRT: u32 = 0x05;
const COMMAND_INVALIDATE_PAGES_SIZE: u64 = 1 << 0;
const COMMAND_INVALIDATE_PAGES_PDE: u64 = 1 << 1;
const COMMAND_INVALIDATE_ALL_PAGES_ADDRESS: u64 = 0x7fff_ffff_ffff_f000;
const COMMAND_DRAIN_POLL_LIMIT: usize = 1_000_000;
const COMMAND_COMPLETION_STORE: u32 = 1;
const DTE_IRQ_PHYS_ADDR_MASK: u64 = 0x000f_ffff_ffff_ffc0;
const DTE_IRQ_REMAP_INTCTL: u64 = 2 << 60;
const DTE_IRQ_REMAP_ENABLE: u64 = 1;
const DTE_INTTABLEN_MASK: u64 = 0xf << 1;
const DTE_INTTABLEN_512: u64 = 9 << 1;
const STATUS_EVENT_OVERFLOW: u64 = 1 << 0;
const STATUS_EVENT_RUNNING: u64 = 1 << 3;

const fn remap_enable_bits(mode: crate::AmdViIrMode) -> u64 {
    match mode {
        crate::AmdViIrMode::Legacy => 0,
        crate::AmdViIrMode::Extended => CONTROL_GA_ENABLE,
        crate::AmdViIrMode::ExtendedXt => CONTROL_GA_ENABLE | CONTROL_XT_ENABLE,
    }
}

/// Whether an AMD-Vi event-log overflow stopped hardware logging. # C: O(1)
pub const fn event_log_restart_needed(status: u64) -> bool {
    status & STATUS_EVENT_OVERFLOW != 0 && status & STATUS_EVENT_RUNNING == 0
}

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

/// Hardware-format 16-byte AMD-Vi command-ring element.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdViCommand { words: [u32; 4] }
impl AmdViCommand {
    /// Build a completion record write after all earlier ring commands. # C: O(1)
    pub const fn completion_wait(completion_pa: u64, sequence: u64) -> Option<Self> {
        if completion_pa & 7 != 0 || completion_pa & !DTE_ROOT_MASK != 0 || sequence == 0 { return None; }
        Some(Self { words: [(completion_pa as u32) | COMMAND_COMPLETION_STORE,
            ((completion_pa >> 32) as u32) | (COMMAND_COMPLETION_WAIT << COMMAND_TYPE_SHIFT),
            sequence as u32, (sequence >> 32) as u32] })
    }
    /// Build the requester-specific device-table invalidation command. # C: O(1)
    pub const fn invalidate_dte(requester: u16) -> Self {
        Self { words: [requester as u32, COMMAND_INVALIDATE_DTE << COMMAND_TYPE_SHIFT, 0, 0] }
    }
    /// Build a domain IOTLB invalidation for one aligned page range. # C: O(1)
    pub const fn invalidate_iova_pages(domain_id: u16, address: u64, last: u64, page_tables: bool) -> Option<Self> {
        if address & (PAGE_BYTES - 1) != 0 || last & (PAGE_BYTES - 1) != 0 || last < address { return None; }
        let encoded = invalidate_address(address, last);
        let flags = if page_tables { COMMAND_INVALIDATE_PAGES_PDE } else { 0 };
        Some(Self { words: [0, (domain_id as u32) | (COMMAND_INVALIDATE_IOMMU_PAGES << COMMAND_TYPE_SHIFT),
            (encoded as u32) | flags as u32, (encoded >> 32) as u32] })
    }
    /// Build an interrupt-table cache invalidation for one requester. # C: O(1)
    pub const fn invalidate_irt(requester: u16) -> Self {
        Self { words: [requester as u32, COMMAND_INVALIDATE_IRT << COMMAND_TYPE_SHIFT, 0, 0] }
    }
    /// Return the four little-endian command words. # C: O(1)
    pub const fn words(&self) -> [u32; 4] { self.words }
}

const fn invalidate_address(address: u64, last: u64) -> u64 {
    let address = address & !(PAGE_BYTES - 1);
    let differing = address ^ last;
    if differing == 0 { return address; }
    let size_log2 = 64 - differing.leading_zeros() as u64;
    if size_log2 > 52 { return COMMAND_INVALIDATE_ALL_PAGES_ADDRESS | COMMAND_INVALIDATE_PAGES_SIZE; }
    let rounded = if size_log2 > 13 { address | ((1u64 << (size_log2 - 1)) - PAGE_BYTES) } else { address };
    rounded | COMMAND_INVALIDATE_PAGES_SIZE
}

/// Permanent DMA-visible AMD-Vi tables. They remain allocated until the
/// owning unit is disabled and no requester can issue DMA through it.
pub struct AmdViTables {
    device_table_pa: u64,
    command_buffer_pa: u64,
    event_log_pa: u64,
    completion_pa: u64,
    command_tail: sync::Spinlock<u32, sync::Devices>,
    completion_sequence: sync::Spinlock<u64, sync::Devices>,
}
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
        let Some(completion_pa) = pmm::setup::alloc_contig(pmm::Order(0)) else {
            // SAFETY: these allocations remain private because table publication has not begun.
            unsafe {
                pmm::setup::free_contig(event_log_pa, pmm::Order(BUFFER_ORDER));
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
            core::ptr::write_bytes(hhdm_offset.wrapping_add(completion_pa) as *mut u8, 0, PAGE_BYTES as usize);
        }
        Some(Self { device_table_pa, command_buffer_pa, event_log_pa, completion_pa, command_tail: sync::Spinlock::new(0), completion_sequence: sync::Spinlock::new(0) })
    }
    /// Return tables that never became visible through an IOMMU register.
    ///
    /// # SAFETY
    /// The caller must prove no device table, command ring, event log, or
    /// completion record was published to hardware. # C: O(1)
    pub(crate) unsafe fn release_unpublished(self) {
        // SAFETY: the caller proves every allocation remained private.
        unsafe {
            pmm::setup::free_contig(self.completion_pa, pmm::Order(0));
            pmm::setup::free_contig(self.event_log_pa, pmm::Order(BUFFER_ORDER));
            pmm::setup::free_contig(self.command_buffer_pa, pmm::Order(BUFFER_ORDER));
            pmm::setup::free_contig(self.device_table_pa, pmm::Order(DEVICE_TABLE_ORDER));
        }
    }
    /// Construct table bases after validating permanent physical allocations. # C: O(1)
    pub const fn from_physical(device_table_pa: u64, command_buffer_pa: u64, event_log_pa: u64) -> Option<Self> {
        if device_table_pa & (DEVICE_TABLE_BYTES - 1) != 0 || command_buffer_pa & (PAGE_BYTES - 1) != 0 || event_log_pa & (PAGE_BYTES - 1) != 0 { return None; }
        Some(Self { device_table_pa, command_buffer_pa, event_log_pa, completion_pa: 0, command_tail: sync::Spinlock::new(0), completion_sequence: sync::Spinlock::new(0) })
    }
    /// Device-table base register value. # C: O(1)
    pub const fn device_table_register(&self) -> u64 { self.device_table_pa | ((DEVICE_TABLE_BYTES / PAGE_BYTES) - 1) }
    /// Command-ring base register value. # C: O(1)
    pub const fn command_buffer_register(&self) -> u64 { self.command_buffer_pa | BUFFER_SIZE_ENCODING }
    /// Event-log base register value. # C: O(1)
    pub const fn event_log_register(&self) -> u64 { self.event_log_pa | BUFFER_SIZE_ENCODING }
    /// Consume each event record visible to software and advance the hardware head. # C: O(events)
    pub fn drain_events(&self, regs: &AmdViRegisters, hhdm_offset: u64, visitor: &mut impl FnMut(crate::AmdViEvent)) -> bool {
        if hhdm_offset == 0 { return false; }
        let Some(mut head) = regs.read64(EVENT_HEAD).map(|value| value & (EVENT_LOG_BYTES - 1)) else { return false; };
        let Some(tail) = regs.read64(EVENT_TAIL).map(|value| value & (EVENT_LOG_BYTES - 1)) else { return false; };
        if head & 15 != 0 || tail & 15 != 0 { return false; }
        while head != tail {
            let base = hhdm_offset.wrapping_add(self.event_log_pa).wrapping_add(head);
            // SAFETY: head is a validated event-ring offset and the producer published this complete 16-byte record before advancing tail.
            let words = unsafe { [core::ptr::read_volatile(base as *const u32), core::ptr::read_volatile((base + 4) as *const u32), core::ptr::read_volatile((base + 8) as *const u32), core::ptr::read_volatile((base + 12) as *const u32)] };
            visitor(crate::AmdViEvent::from_words(words));
            head = (head + 16) & (EVENT_LOG_BYTES - 1);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        regs.write64(EVENT_HEAD, head) && self.restart_event_logging(regs)
    }
    /// Clear an overflowed log state and restore the event controls that were
    /// active before hardware stopped logging. # C: O(1)
    fn restart_event_logging(&self, regs: &AmdViRegisters) -> bool {
        let Some(status) = regs.read64(STATUS) else { return false; };
        if !event_log_restart_needed(status) { return true; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        if control & CONTROL_EVENT_ENABLE == 0 { return false; }
        let event_controls = CONTROL_EVENT_ENABLE | CONTROL_EVENT_INTERRUPT_ENABLE;
        if !regs.write64(CONTROL, control & !event_controls) { return false; }
        if !regs.write64(STATUS, STATUS_EVENT_OVERFLOW) { return false; }
        regs.write64(CONTROL, control)
    }
    const fn dte_byte_offset(requester: u16) -> u64 { requester as u64 * core::mem::size_of::<AmdViDte>() as u64 }
    unsafe fn write_initial_dte(&self, hhdm_offset: u64, requester: u16, dte: AmdViDte) {
        let base = hhdm_offset.wrapping_add(self.device_table_pa).wrapping_add(Self::dte_byte_offset(requester));
        let words = dte.words();
        // SAFETY: caller holds the disabled unit's exclusive device table before hardware can consume this DTE.
        unsafe {
            core::ptr::write_volatile((base + 16) as *mut u64, words[2]);
            core::ptr::write_volatile((base + 24) as *mut u64, words[3]);
            core::ptr::write_volatile((base + 8) as *mut u64, words[1]);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(base as *mut u64, words[0]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
    unsafe fn dte_word(&self, hhdm_offset: u64, requester: u16, word: u8) -> Option<u64> {
        if hhdm_offset == 0 || word >= 4 { return None; }
        let va = hhdm_offset.wrapping_add(self.device_table_pa)
            .wrapping_add(Self::dte_byte_offset(requester)).wrapping_add(u64::from(word) * 8);
        // SAFETY: caller owns this unit's DTE update and word was bounds checked.
        Some(unsafe { core::ptr::read_volatile(va as *const u64) })
    }
    unsafe fn write_dte_word(&self, hhdm_offset: u64, requester: u16, word: u8, value: u64) -> bool {
        if hhdm_offset == 0 || word >= 4 { return false; }
        let va = hhdm_offset.wrapping_add(self.device_table_pa)
            .wrapping_add(Self::dte_byte_offset(requester)).wrapping_add(u64::from(word) * 8);
        // SAFETY: caller owns this unit's live DTE update and word was bounds checked.
        unsafe { core::ptr::write_volatile(va as *mut u64, value); }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        true
    }
    unsafe fn queue_command(&self, regs: &AmdViRegisters, hhdm_offset: u64, command: AmdViCommand) -> bool {
        let mut tail = self.command_tail.lock();
        let Some(head) = regs.read64(COMMAND_HEAD) else { return false; };
        let next = (*tail + core::mem::size_of::<AmdViCommand>() as u32) & (COMMAND_BUFFER_BYTES as u32 - 1);
        if next == ((head as u32) & (COMMAND_BUFFER_BYTES as u32 - 1)) { return false; }
        let base = hhdm_offset.wrapping_add(self.command_buffer_pa).wrapping_add(*tail as u64);
        let words = command.words();
        // SAFETY: caller holds the command-ring ownership and `tail` reserves this 16-byte entry.
        unsafe {
            core::ptr::write_volatile(base as *mut u32, words[0]);
            core::ptr::write_volatile((base + 4) as *mut u32, words[1]);
            core::ptr::write_volatile((base + 8) as *mut u32, words[2]);
            core::ptr::write_volatile((base + 12) as *mut u32, words[3]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        if !regs.write64(COMMAND_TAIL, next as u64) { return false; }
        *tail = next;
        true
    }
    unsafe fn wait_for_completion(&self, regs: &AmdViRegisters, hhdm_offset: u64) -> bool {
        if self.completion_pa == 0 || hhdm_offset == 0 { return false; }
        let mut sequence = self.completion_sequence.lock();
        let Some(next) = sequence.checked_add(1) else { return false; };
        let Some(command) = AmdViCommand::completion_wait(self.completion_pa, next) else { return false; };
        // SAFETY: this table owns both the serialized ring and its completion record.
        if !unsafe { self.queue_command(regs, hhdm_offset, command) } { return false; }
        *sequence = next;
        let completion_va = hhdm_offset.wrapping_add(self.completion_pa) as *const u64;
        for _ in 0..COMMAND_DRAIN_POLL_LIMIT {
            // SAFETY: completion_va names this table's permanent aligned completion record.
            let completed = unsafe { core::ptr::read_volatile(completion_va) };
            if (completed.wrapping_sub(next) as i64) >= 0 { return true; }
            core::hint::spin_loop();
        }
        false
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
pub enum AmdViState { Discovered, Mapped, TablesProgrammed, DomainsAttached, Enabled, Disabled }

pub struct AmdViUnit { pub mmio_pa: u64, pub segment: u16, ir_mode: crate::AmdViIrMode, state: AmdViState }
impl AmdViUnit {
    /// Construct a disabled unit from validated IVRS firmware data. # C: O(1)
    pub const fn new(mmio_pa: u64, segment: u16, ir_mode: crate::AmdViIrMode) -> Self {
        Self { mmio_pa, segment, ir_mode, state: AmdViState::Discovered }
    }
    /// Selected remap-entry format. # C: O(1)
    pub const fn ir_mode(&self) -> crate::AmdViIrMode { self.ir_mode }
    /// Current activation state. # C: O(1)
    pub const fn state(&self) -> AmdViState { self.state }
    /// Advance after owned device MMIO mapping exists. # C: O(1)
    pub fn mapped(&mut self) -> bool { self.advance(AmdViState::Discovered, AmdViState::Mapped) }
    /// Quiesce firmware-owned translation before replacing DMA tables.
    ///
    /// This is Linux `iommu_disable()`'s ordering: command processing, then
    /// event/GA/PPR reporting, then translation and the IRTE cache control.
    /// PCI bus mastering is already quiesced by the caller. # C: O(1)
    pub fn quiesce_firmware(&self, regs: &AmdViRegisters) -> bool {
        if self.state != AmdViState::Mapped { return false; }
        for bit in FIRMWARE_QUIESCE_ORDER {
            let Some(control) = regs.read64(CONTROL) else { return false; };
            if !regs.write64(CONTROL, control & !bit) { return false; }
        }
        true
    }
    /// Install one DTE while translation remains disabled. # C: O(1)
    pub unsafe fn install_initial_dte(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, bdf: pci::Bdf, dte: AmdViDte) -> bool {
        if bdf.segment != self.segment { return false; }
        // SAFETY: this keeps the segment-checked BDF API over the raw requester write.
        unsafe { self.install_initial_requester(regs, tables, hhdm_offset, bdf.raw(), dte) }
    }
    unsafe fn install_initial_requester(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, requester: u16, dte: AmdViDte) -> bool {
        if !self.accepts_initial_dte() || hhdm_offset == 0 { return false; }
        if regs.read64(CONTROL).is_none_or(|control| control & CONTROL_IOMMU_ENABLE != 0) { return false; }
        // SAFETY: the state and register guard above prove this unit cannot consume its table yet.
        unsafe { tables.write_initial_dte(hhdm_offset, requester, dte); }
        true
    }
    /// Attach one AMD-Vi domain by installing its paging DTE for one requester. # C: O(1)
    pub unsafe fn install_initial_domain(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, bdf: pci::Bdf, domain: &crate::AmdViDomain, domain_id: u16) -> bool {
        let Some(dte) = domain.dte(domain_id) else { return false; };
        // SAFETY: forwarded to the checked initial-DTE operation for this domain's exact requester.
        if !unsafe { self.install_initial_dte(regs, tables, hhdm_offset, bdf, dte) } { return false; }
        let Some(alias) = firmware::acpi::amd_vi_alias_for_requester(bdf.segment, bdf.raw()) else { return true; };
        // SAFETY: the same disabled-unit guard applies to the alias requester in this IVHD unit.
        unsafe { self.install_initial_requester(regs, tables, hhdm_offset, alias, dte) }
    }
    /// Program DMA-visible table bases and enable their command and event rings. # C: O(1)
    pub fn program_tables(&mut self, regs: &AmdViRegisters, tables: &AmdViTables) -> bool {
        if self.state != AmdViState::Mapped { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        if control & CONTROL_IOMMU_ENABLE != 0 { return false; }
        if !regs.write64(DEVICE_TABLE, tables.device_table_register()) || !regs.write64(COMMAND_BUFFER, tables.command_buffer_register()) || !regs.write64(EVENT_LOG, tables.event_log_register()) { return false; }
        if !regs.write64(COMMAND_HEAD, 0) || !regs.write64(COMMAND_TAIL, 0) || !regs.write64(EVENT_HEAD, 0) || !regs.write64(EVENT_TAIL, 0) { return false; }
        regs.write64(CONTROL, control | CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_COMPLETION_ENABLE | CONTROL_COHERENT_ENABLE)
            && self.advance(AmdViState::Mapped, AmdViState::TablesProgrammed)
    }
    /// Queue a requester-DTE invalidation after its initial entry was written. # C: O(1)
    pub unsafe fn invalidate_initial_dte(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, bdf: pci::Bdf) -> bool {
        if self.state != AmdViState::TablesProgrammed || bdf.segment != self.segment || hhdm_offset == 0 { return false; }
        if regs.read64(CONTROL).is_none_or(|control| control & CONTROL_COMMAND_ENABLE == 0) { return false; }
        // SAFETY: tables owns the serialized command ring and the checked state has enabled it.
        unsafe { tables.queue_command(regs, hhdm_offset, AmdViCommand::invalidate_dte(bdf.raw())) }
    }
    /// Queue a domain-page invalidation after changing its IOVA PTEs. # C: O(1)
    pub unsafe fn invalidate_iova_pages(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64, domain_id: u16, address: u64, last: u64, page_tables: bool) -> bool {
        if self.state != AmdViState::TablesProgrammed && self.state != AmdViState::DomainsAttached && self.state != AmdViState::Enabled { return false; }
        if hhdm_offset == 0 || regs.read64(CONTROL).is_none_or(|control| control & CONTROL_COMMAND_ENABLE == 0) { return false; }
        let Some(command) = AmdViCommand::invalidate_iova_pages(domain_id, address, last, page_tables) else { return false; };
        // SAFETY: tables owns the serialized command ring and its command engine is enabled.
        unsafe { tables.queue_command(regs, hhdm_offset, command) }
    }
    /// Publish the requester's interrupt-table DTE field and invalidate its DTE cache. # C: O(poll limit)
    pub unsafe fn install_interrupt_table(&self, regs: &AmdViRegisters, tables: &AmdViTables,
        hhdm_offset: u64, bdf: pci::Bdf, table_pa: u64) -> bool {
        if self.state != AmdViState::Enabled || bdf.segment != self.segment || table_pa & 127 != 0 { return false; }
        // SAFETY: the state check above proved this unit is Enabled and owns `bdf`,
        // so `tables` holds the live device table; reading DTE word 2 read-modify-
        // writes only the interrupt-remap fields this requester owns.
        let Some(old) = (unsafe { tables.dte_word(hhdm_offset, bdf.raw(), 2) }) else { return false; };
        let value = (old & !(DTE_IRQ_PHYS_ADDR_MASK | DTE_IRQ_REMAP_INTCTL | DTE_INTTABLEN_MASK | DTE_IRQ_REMAP_ENABLE))
            | (table_pa & DTE_IRQ_PHYS_ADDR_MASK) | DTE_IRQ_REMAP_INTCTL | DTE_INTTABLEN_512 | DTE_IRQ_REMAP_ENABLE;
        // SAFETY: the enabled unit owns this requester's DTE and serializes its command ring.
        if !unsafe { tables.write_dte_word(hhdm_offset, bdf.raw(), 2, value) }
            // SAFETY: the DTE write above must be followed by a DTE-cache invalidation
            // on the same serialized command ring, which this Enabled unit owns.
            || !unsafe { tables.queue_command(regs, hhdm_offset, AmdViCommand::invalidate_dte(bdf.raw())) } { return false; }
        // SAFETY: the same tables own the completion record paired with the queued invalidation.
        unsafe { tables.wait_for_completion(regs, hhdm_offset) }
    }
    /// Invalidate a requester's interrupt-table cache after publishing an IRTE. # C: O(poll limit)
    pub unsafe fn invalidate_interrupt_table(&self, regs: &AmdViRegisters, tables: &AmdViTables,
        hhdm_offset: u64, bdf: pci::Bdf) -> bool {
        if self.state != AmdViState::Enabled || bdf.segment != self.segment { return false; }
        // SAFETY: caller published the IRTE in the DMA-visible table before this invalidation.
        if !unsafe { tables.queue_command(regs, hhdm_offset, AmdViCommand::invalidate_irt(bdf.raw())) } { return false; }
        // SAFETY: this table owns the completion record paired with the queued invalidation.
        unsafe { tables.wait_for_completion(regs, hhdm_offset) }
    }
    /// Wait for every queued invalidation to reach the command-ring head. # C: O(poll limit)
    pub unsafe fn wait_for_invalidations(&self, regs: &AmdViRegisters, tables: &AmdViTables, hhdm_offset: u64) -> bool {
        if self.state != AmdViState::TablesProgrammed && self.state != AmdViState::Enabled { return false; }
        // SAFETY: caller owns this disabled unit and its permanent completion record.
        unsafe { tables.wait_for_completion(regs, hhdm_offset) }
    }
    /// Advance only after hardware consumed every queued initial invalidation. # C: O(1)
    pub fn domains_attached_after_drain(&mut self) -> bool {
        if self.state != AmdViState::TablesProgrammed { return false; }
        self.advance(AmdViState::TablesProgrammed, AmdViState::DomainsAttached)
    }
    /// Enable hardware translation after every active requester has an invalidated DTE. # C: O(1)
    pub fn enable_translation(&mut self, regs: &AmdViRegisters) -> bool {
        if self.state != AmdViState::DomainsAttached { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        let required = CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_COMPLETION_ENABLE | CONTROL_COHERENT_ENABLE;
        if control & required != required { return false; }
        regs.write64(CONTROL, control | remap_enable_bits(self.ir_mode) | CONTROL_IOMMU_ENABLE)
            && self.advance(AmdViState::DomainsAttached, AmdViState::Enabled)
    }
    /// Enable event-log interrupts only after a PCI MSI handler owns delivery. # C: O(1)
    pub fn enable_event_interrupts(&self, regs: &AmdViRegisters) -> bool {
        if self.state != AmdViState::Enabled { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        if control & CONTROL_EVENT_ENABLE == 0 { return false; }
        regs.write64(CONTROL, control | CONTROL_EVENT_INTERRUPT_ENABLE)
    }
    /// Mask event-log interrupts while preserving active translation and logging. # C: O(1)
    pub fn disable_event_interrupts(&self, regs: &AmdViRegisters) -> bool {
        if self.state != AmdViState::Enabled { return false; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        regs.write64(CONTROL, control & !CONTROL_EVENT_INTERRUPT_ENABLE)
    }
    /// Undo this bootstrap's command/event/translation transition.
    ///
    /// This follows Linux's `iommu_disable()`: command processing and event
    /// logging are stopped before translation is cleared. It is valid for a
    /// partially prepared unit too, because a failed global boot transition
    /// must not leave an earlier unit consuming its private tables. # C: O(1)
    pub fn disable_bootstrap(&mut self, regs: &AmdViRegisters) -> bool {
        if self.state == AmdViState::Discovered || self.state == AmdViState::Disabled { return true; }
        let Some(control) = regs.read64(CONTROL) else { return false; };
        let disabled = control & !(CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_EVENT_INTERRUPT_ENABLE
            | CONTROL_COMPLETION_ENABLE | CONTROL_GA_ENABLE | CONTROL_XT_ENABLE | CONTROL_IOMMU_ENABLE);
        if !regs.write64(CONTROL, disabled) { return false; }
        self.state = AmdViState::Disabled;
        true
    }
    fn advance(&mut self, from: AmdViState, to: AmdViState) -> bool {
        if self.state != from { return false; }
        self.state = to; true
    }
    fn accepts_initial_dte(&self) -> bool {
        self.state == AmdViState::Mapped || self.state == AmdViState::TablesProgrammed
    }
}

// Exact `iommu_disable()` feature order from Linux
// drivers/iommu/amd/init.c. Separate writes preserve the hardware handoff.
const FIRMWARE_QUIESCE_ORDER: [u64; 9] = [
    CONTROL_COMMAND_ENABLE,
    CONTROL_EVENT_INTERRUPT_ENABLE,
    CONTROL_EVENT_ENABLE,
    CONTROL_GA_LOG_ENABLE,
    CONTROL_GA_INTERRUPT_ENABLE,
    CONTROL_PPR_LOG_ENABLE,
    CONTROL_PPR_INTERRUPT_ENABLE,
    CONTROL_IOMMU_ENABLE,
    CONTROL_IRT_CACHE_DISABLE,
];

#[cfg(test)] mod tests;

/// AMD-Vi MMIO register offsets used by the initial translation path.
pub const DEVICE_TABLE: u64 = 0x0000;
pub const COMMAND_BUFFER: u64 = 0x0008;
pub const EVENT_LOG: u64 = 0x0010;
pub const CONTROL: u64 = 0x0018;
pub const COMMAND_HEAD: u64 = 0x2000;
pub const COMMAND_TAIL: u64 = 0x2008;
pub const CONTROL_IOMMU_ENABLE: u64 = 1 << 0;
pub const CONTROL_COMMAND_ENABLE: u64 = 1 << 12;
const MMIO_BYTES: u64 = 0x80000;
const PAGE_BYTES: u64 = 4096;

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
    /// Advance after device/event/command table bases are programmed. # C: O(1)
    pub fn tables_programmed(&mut self) -> bool { self.advance(AmdViState::Mapped, AmdViState::TablesProgrammed) }
    /// Advance after every enabled requester has a domain DTE and invalidate completed. # C: O(1)
    pub fn domains_attached(&mut self) -> bool { self.advance(AmdViState::TablesProgrammed, AmdViState::DomainsAttached) }
    /// Advance only after translation hardware is enabled. # C: O(1)
    pub fn enabled(&mut self) -> bool { self.advance(AmdViState::DomainsAttached, AmdViState::Enabled) }
    fn advance(&mut self, from: AmdViState, to: AmdViState) -> bool {
        if self.state != from { return false; }
        self.state = to; true
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn translation_requires_programmed_and_attached_domains() {
        let mut u = AmdViUnit::new(0xfed8_0000, 3);
        assert!(!u.enabled()); assert!(u.mapped()); assert!(u.tables_programmed());
        assert!(!u.enabled()); assert!(u.domains_attached()); assert!(u.enabled());
    }
}

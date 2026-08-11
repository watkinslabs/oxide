/// AMD-Vi MMIO register offsets used by the initial translation path.
pub const DEVICE_TABLE: u64 = 0x0000;
pub const COMMAND_BUFFER: u64 = 0x0008;
pub const EVENT_LOG: u64 = 0x0010;
pub const CONTROL: u64 = 0x0018;
pub const COMMAND_HEAD: u64 = 0x2000;
pub const COMMAND_TAIL: u64 = 0x2008;
pub const CONTROL_IOMMU_ENABLE: u64 = 1 << 0;
pub const CONTROL_COMMAND_ENABLE: u64 = 1 << 12;

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

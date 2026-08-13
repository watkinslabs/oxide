//! AMD-Vi event-log record decoding.

/// Hardware-format 16-byte AMD-Vi event-log record.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdViEvent { words: [u32; 4] }

/// Classified AMD-Vi event-log type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViEventKind {
    Empty, IllegalDeviceTable, IoPageFault, DeviceTableHardware, PageTableHardware,
    IllegalCommand, CommandHardware, IotlbInvalidateTimeout, InvalidDeviceRequest,
    InvalidPageRequest, RmpPageFault, RmpHardware, Unknown(u8),
}

const EVENT_TYPE_SHIFT: u32 = 28;
const EVENT_TYPE_MASK: u32 = 0xf;
const EVENT_DEVICE_MASK: u32 = 0xffff;
const EVENT_DOMAIN_HIGH_MASK: u32 = 0xf0000;
const EVENT_DOMAIN_LOW_MASK: u32 = 0xffff;
const EVENT_FLAGS_SHIFT: u32 = 16;
const EVENT_FLAGS_MASK: u32 = 0xfff;
const EVENT_FLAG_INTERRUPT: u16 = 0x008;
const EVENT_FLAG_WRITE: u16 = 0x020;

impl AmdViEvent {
    /// Decode one little-endian event-log record read from DMA-visible memory. # C: O(1)
    pub const fn from_words(words: [u32; 4]) -> Self { Self { words } }
    /// Return the classified hardware event kind. # C: O(1)
    pub const fn kind(self) -> AmdViEventKind {
        match (self.words[1] >> EVENT_TYPE_SHIFT) & EVENT_TYPE_MASK {
            0 => AmdViEventKind::Empty, 1 => AmdViEventKind::IllegalDeviceTable,
            2 => AmdViEventKind::IoPageFault, 3 => AmdViEventKind::DeviceTableHardware,
            4 => AmdViEventKind::PageTableHardware, 5 => AmdViEventKind::IllegalCommand,
            6 => AmdViEventKind::CommandHardware, 7 => AmdViEventKind::IotlbInvalidateTimeout,
            8 => AmdViEventKind::InvalidDeviceRequest, 9 => AmdViEventKind::InvalidPageRequest,
            13 => AmdViEventKind::RmpPageFault, 14 => AmdViEventKind::RmpHardware,
            other => AmdViEventKind::Unknown(other as u8),
        }
    }
    /// Return the requester ID encoded by the event. # C: O(1)
    pub const fn requester(self) -> u16 { (self.words[0] & EVENT_DEVICE_MASK) as u16 }
    /// Return the event's AMD-Vi domain or PASID field. # C: O(1)
    pub const fn domain_or_pasid(self) -> u32 { (self.words[0] & EVENT_DOMAIN_HIGH_MASK) | (self.words[1] & EVENT_DOMAIN_LOW_MASK) }
    /// Return the faulting address or command address. # C: O(1)
    pub const fn address(self) -> u64 { (self.words[2] as u64) | ((self.words[3] as u64) << 32) }
    /// Return hardware event flags. # C: O(1)
    pub const fn flags(self) -> u16 { ((self.words[1] >> EVENT_FLAGS_SHIFT) & EVENT_FLAGS_MASK) as u16 }
    /// Return whether this record describes a DMA memory transaction. # C: O(1)
    pub const fn is_dma(self) -> bool { self.flags() & EVENT_FLAG_INTERRUPT == 0 }
    /// Return whether this record describes a write transaction. # C: O(1)
    pub const fn is_write(self) -> bool { self.flags() & EVENT_FLAG_WRITE != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_fault_decoding_preserves_requester_address_and_access_direction() {
        let event = AmdViEvent::from_words([0x000b_1234, 0x2020_0042, 0x89ab_cdef, 0x0123_4567]);
        assert_eq!(event.kind(), AmdViEventKind::IoPageFault); assert_eq!(event.requester(), 0x1234);
        assert_eq!(event.domain_or_pasid(), 0xb0042); assert_eq!(event.address(), 0x0123_4567_89ab_cdef);
        assert!(event.is_dma()); assert!(event.is_write());
    }
    #[test]
    fn unknown_and_interrupt_records_remain_observable() {
        let event = AmdViEvent::from_words([0, 0xf008_0000, 0, 0]);
        assert_eq!(event.kind(), AmdViEventKind::Unknown(15)); assert!(!event.is_dma()); assert!(!event.is_write());
    }
}

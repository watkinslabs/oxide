//! VT-d primary fault-record decoding.

/// One hardware-format VT-d primary fault record.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdFault { words: [u32; 4] }

const FAULT_REASON_MASK: u32 = 0xff;
const FAULT_TYPE_BIT: u32 = 1 << 30;
const FAULT_VALID_BIT: u32 = 1 << 31;
const FAULT_SOURCE_MASK: u32 = 0xffff;
const FAULT_PASID_SHIFT: u32 = 8;
const FAULT_PASID_MASK: u32 = 0x000f_ffff;
const FAULT_PASID_PRESENT: u32 = 1 << 31;
const PAGE_MASK: u64 = !0xfff;

impl VtdFault {
    /// Decode the four little-endian dwords of one primary fault record. # C: O(1)
    pub const fn from_words(words: [u32; 4]) -> Self { Self { words } }
    /// Return whether hardware marked this record valid. # C: O(1)
    pub const fn valid(self) -> bool { self.words[3] & FAULT_VALID_BIT != 0 }
    /// Return the hardware fault reason. # C: O(1)
    pub const fn reason(self) -> u8 { (self.words[3] & FAULT_REASON_MASK) as u8 }
    /// Return the requester's PCI source ID. # C: O(1)
    pub const fn requester(self) -> u16 { (self.words[2] & FAULT_SOURCE_MASK) as u16 }
    /// Return the page-aligned address reported by hardware. # C: O(1)
    pub const fn address(self) -> u64 { ((self.words[0] as u64) | ((self.words[1] as u64) << 32)) & PAGE_MASK }
    /// Return whether the transaction was a read request. # C: O(1)
    pub const fn is_read(self) -> bool { self.words[3] & FAULT_TYPE_BIT != 0 }
    /// Return the PASID when hardware marked it present. # C: O(1)
    pub const fn pasid(self) -> Option<u32> {
        if self.words[2] & FAULT_PASID_PRESENT != 0 {
            Some((self.words[3] >> FAULT_PASID_SHIFT) & FAULT_PASID_MASK)
        } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_fault_preserves_requester_address_direction_and_pasid() {
        let fault = VtdFault::from_words([0x89ab_cdef, 0x0123_4567, 0x8000_1234, 0xc012_3456]);
        assert!(fault.valid()); assert_eq!(fault.reason(), 0x56); assert_eq!(fault.requester(), 0x1234);
        assert_eq!(fault.address(), 0x0123_4567_89ab_c000); assert!(fault.is_read()); assert_eq!(fault.pasid(), Some(0x01234));
    }

    #[test]
    fn absent_pasid_is_not_invented() {
        let fault = VtdFault::from_words([0, 0, 0x1234, 0x8000_0001]);
        assert!(fault.valid()); assert!(!fault.is_read()); assert_eq!(fault.pasid(), None);
    }
}

//! Strict USB descriptor validation shared by physical xHCI enumeration.

/// USB device descriptor type. # C: O(1)
pub const DESC_DEVICE: u8 = 1;
/// Exact USB device descriptor byte length. # C: O(1)
pub const DEVICE_DESC_BYTES: usize = 18;

/// Parsed fixed USB device descriptor fields needed by enumeration. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor { pub vendor: u16, pub product: u16, pub device_class: u8, pub max_packet0: u8, pub configurations: u8 }

/// Parse one exact USB2 device descriptor. # C: O(1)
pub fn device_descriptor(bytes: &[u8]) -> Option<DeviceDescriptor> {
    if bytes.len() < DEVICE_DESC_BYTES || bytes[0] as usize != DEVICE_DESC_BYTES || bytes[1] != DESC_DEVICE { return None; }
    let max_packet0 = bytes[7];
    if !matches!(max_packet0, 8 | 16 | 32 | 64) || bytes[17] == 0 { return None; }
    Some(DeviceDescriptor { vendor: u16::from_le_bytes([bytes[8], bytes[9]]), product: u16::from_le_bytes([bytes[10], bytes[11]]), device_class: bytes[4], max_packet0, configurations: bytes[17] })
}

/// Build the standard IN GET_DESCRIPTOR(Device, index 0) EP0 TD. # C: O(1)
pub fn get_device_descriptor_trbs(buffer_pa: u64) -> Option<[crate::ring::Trb; 3]> {
    Some([
        crate::ring::Trb::setup_stage(0x80, 6, (DESC_DEVICE as u16) << 8, 0, DEVICE_DESC_BYTES as u16),
        crate::ring::Trb::data_stage(buffer_pa, DEVICE_DESC_BYTES as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_descriptor_requires_exact_header_and_ep0_geometry() {
        let mut bytes = [0u8; DEVICE_DESC_BYTES]; bytes[0] = 18; bytes[1] = DESC_DEVICE; bytes[7] = 64; bytes[8] = 0x34; bytes[9] = 0x12; bytes[10] = 0x78; bytes[11] = 0x56; bytes[17] = 1;
        assert_eq!(device_descriptor(&bytes), Some(DeviceDescriptor { vendor: 0x1234, product: 0x5678, device_class: 0, max_packet0: 64, configurations: 1 }));
        bytes[7] = 7; assert!(device_descriptor(&bytes).is_none());
    }
    #[test]
    fn device_descriptor_request_is_standard_in_control_td() {
        let td = get_device_descriptor_trbs(0x90_000).unwrap();
        assert_eq!(td[0].dword[0], 0x0100_0680);
        assert_eq!(td[1].dword[2], DEVICE_DESC_BYTES as u32);
        assert_eq!(td[2].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 5));
    }
}

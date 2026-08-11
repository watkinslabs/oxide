//! Strict USB descriptor validation shared by physical xHCI enumeration.

/// USB device descriptor type. # C: O(1)
pub const DESC_DEVICE: u8 = 1;
/// Exact USB device descriptor byte length. # C: O(1)
pub const DEVICE_DESC_BYTES: usize = 18;
/// USB configuration descriptor type. # C: O(1)
pub const DESC_CONFIGURATION: u8 = 2;
/// Exact USB configuration descriptor header byte length. # C: O(1)
pub const CONFIG_DESC_HEADER_BYTES: usize = 9;
/// Largest configuration descriptor accepted by the one-page enumeration buffer. # C: O(1)
pub const CONFIG_DESC_MAX_BYTES: usize = 4096;

/// Parsed fixed USB device descriptor fields needed by enumeration. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor { pub vendor: u16, pub product: u16, pub device_class: u8, pub max_packet0: u8, pub configurations: u8 }

/// Parsed fixed configuration-descriptor header. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationHeader { pub total_length: usize, pub value: u8, pub interfaces: u8 }

/// One Linux-compatible HID boot interrupt-IN interface. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HidBootInterface { pub configuration: u8, pub interface: u8, pub protocol: u8, pub endpoint: u8, pub max_packet: u16, pub interval: u8 }

/// Parse one exact USB2 device descriptor. # C: O(1)
pub fn device_descriptor(bytes: &[u8]) -> Option<DeviceDescriptor> {
    if bytes.len() < DEVICE_DESC_BYTES || bytes[0] as usize != DEVICE_DESC_BYTES || bytes[1] != DESC_DEVICE { return None; }
    let max_packet0 = bytes[7];
    if !matches!(max_packet0, 8 | 16 | 32 | 64) || bytes[17] == 0 { return None; }
    Some(DeviceDescriptor { vendor: u16::from_le_bytes([bytes[8], bytes[9]]), product: u16::from_le_bytes([bytes[10], bytes[11]]), device_class: bytes[4], max_packet0, configurations: bytes[17] })
}

/// Parse the first nine bytes needed for Linux's two-stage configuration fetch. # C: O(1)
pub fn configuration_header(bytes: &[u8]) -> Option<ConfigurationHeader> {
    if bytes.len() < CONFIG_DESC_HEADER_BYTES || bytes[0] != CONFIG_DESC_HEADER_BYTES as u8 || bytes[1] != DESC_CONFIGURATION { return None; }
    let total_length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if !(CONFIG_DESC_HEADER_BYTES..=CONFIG_DESC_MAX_BYTES).contains(&total_length) || bytes[4] == 0 || bytes[5] == 0 { return None; }
    Some(ConfigurationHeader { total_length, value: bytes[5], interfaces: bytes[4] })
}

/// Find the first alternate-setting-zero HID boot keyboard or mouse interrupt-IN endpoint. # C: O(descriptors)
pub fn hid_boot_interface(bytes: &[u8]) -> Option<HidBootInterface> {
    let header = configuration_header(bytes)?;
    if bytes.len() != header.total_length { return None; }
    let mut offset = CONFIG_DESC_HEADER_BYTES;
    let mut active = None;
    while offset < bytes.len() {
        if offset + 2 > bytes.len() { return None; }
        let length = bytes[offset] as usize;
        if length < 2 || offset.checked_add(length)? > bytes.len() { return None; }
        match bytes[offset + 1] {
            4 if length >= 9 => {
                active = (bytes[offset + 3] == 0 && bytes[offset + 5] == 3 && bytes[offset + 6] == 1 && matches!(bytes[offset + 7], 1 | 2))
                    .then_some((bytes[offset + 2], bytes[offset + 7]));
            }
            5 if length >= 7 => if let Some((interface, protocol)) = active {
                let endpoint = bytes[offset + 2];
                let max_packet = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]) & 0x07ff;
                if endpoint & 0x80 != 0 && endpoint & 0x0f != 0 && bytes[offset + 3] & 0x3 == 3 && max_packet != 0 && bytes[offset + 6] != 0 {
                    return Some(HidBootInterface { configuration: header.value, interface, protocol, endpoint, max_packet, interval: bytes[offset + 6] });
                }
            },
            _ => {}
        }
        offset += length;
    }
    None
}

/// Build the standard IN GET_DESCRIPTOR(Device, index 0) EP0 TD. # C: O(1)
pub fn get_device_descriptor_trbs(buffer_pa: u64) -> Option<[crate::ring::Trb; 3]> {
    Some([
        crate::ring::Trb::setup_stage(0x80, 6, (DESC_DEVICE as u16) << 8, 0, DEVICE_DESC_BYTES as u16),
        crate::ring::Trb::data_stage(buffer_pa, DEVICE_DESC_BYTES as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Build a standard IN GET_DESCRIPTOR(Configuration, index) EP0 TD. # C: O(1)
pub fn get_configuration_descriptor_trbs(buffer_pa: u64, index: u8, length: usize) -> Option<[crate::ring::Trb; 3]> {
    if !(CONFIG_DESC_HEADER_BYTES..=CONFIG_DESC_MAX_BYTES).contains(&length) { return None; }
    Some([
        crate::ring::Trb::setup_stage(0x80, 6, ((DESC_CONFIGURATION as u16) << 8) | u16::from(index), 0, length as u16),
        crate::ring::Trb::data_stage(buffer_pa, length as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Build standard OUT SET_CONFIGURATION with no data stage. # C: O(1)
pub fn set_configuration_trbs(value: u8) -> Option<[crate::ring::Trb; 2]> {
    (value != 0).then_some([
        crate::ring::Trb::setup_stage(0, 9, u16::from(value), 0, 0),
        crate::ring::Trb::status_stage(false),
    ])
}

/// Build HID class OUT SET_PROTOCOL(Boot) for one selected interface. # C: O(1)
pub fn set_hid_boot_protocol_trbs(interface: u8) -> [crate::ring::Trb; 2] {
    [
        crate::ring::Trb::setup_stage(0x21, 0x0b, 0, u16::from(interface), 0),
        crate::ring::Trb::status_stage(false),
    ]
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
    #[test]
    fn configuration_header_and_two_stage_request_are_strict() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 2, 0, 0x80, 50];
        assert_eq!(configuration_header(&bytes), Some(ConfigurationHeader { total_length: 34, value: 2, interfaces: 1 }));
        assert!(configuration_header(&[9, DESC_CONFIGURATION, 8, 0, 1, 2, 0, 0, 0]).is_none());
        let td = get_configuration_descriptor_trbs(0x90_000, 2, 34).unwrap();
        assert_eq!(td[0].dword[0], 0x0202_0680);
        assert_eq!(td[1].dword[2], 34);
        assert!(get_configuration_descriptor_trbs(0x90_000, 0, 8).is_none());
    }
    #[test]
    fn hid_boot_parser_selects_only_interrupt_in_keyboard_or_mouse() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0, 7, 5, 0x81, 3, 8, 0, 10];
        assert_eq!(hid_boot_interface(&bytes), Some(HidBootInterface { configuration: 1, interface: 0, protocol: 1, endpoint: 0x81, max_packet: 8, interval: 10 }));
        let mut non_boot = bytes; non_boot[15] = 2;
        assert!(hid_boot_interface(&non_boot).is_none());
    }
    #[test]
    fn set_configuration_is_a_no_data_out_control_td() {
        let td = set_configuration_trbs(1).unwrap();
        assert_eq!(td[0].dword, [0x0001_0900, 0, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6)]);
        assert_eq!(td[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 16) | (1 << 5));
        assert!(set_configuration_trbs(0).is_none());
    }
    #[test]
    fn hid_boot_protocol_is_a_class_interface_no_data_request() {
        let td = set_hid_boot_protocol_trbs(3);
        assert_eq!(td[0].dword, [0x0000_0b21, 3, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6)]);
        assert_eq!(td[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 16) | (1 << 5));
    }
}

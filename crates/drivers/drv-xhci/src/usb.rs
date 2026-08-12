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
/// USB hub descriptor type. # C: O(1)
pub const DESC_HUB: u8 = 0x29;
/// USB hub class code. # C: O(1)
pub const USB_CLASS_HUB: u8 = 9;
/// Hub descriptor bytes before the variable port-removability bitmaps. # C: O(1)
pub const HUB_DESC_HEADER_BYTES: usize = 7;
/// USB hub GET_DESCRIPTOR request type: IN, class, device. # C: O(1)
pub const HUB_GET_DESCRIPTOR_REQUEST_TYPE: u8 = 0xa0;

/// Validated USB 2 hub descriptor facts used to construct child topology.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HubDescriptor { pub ports: u8, pub power_good_ms: u16, pub tt_think_time: u8 }

/// Return the exact USB2 hub-descriptor length from its fixed header. # C: O(1)
pub fn hub_descriptor_length(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < HUB_DESC_HEADER_BYTES || bytes[1] != DESC_HUB || bytes[2] == 0 { return None; }
    let bitmap_bytes = (usize::from(bytes[2]).checked_add(1)?.checked_add(7)?) / 8;
    let minimum = HUB_DESC_HEADER_BYTES.checked_add(bitmap_bytes.checked_mul(2)?)?;
    let length = bytes[0] as usize;
    (length >= minimum && length <= CONFIG_DESC_MAX_BYTES).then_some(length)
}

/// Parse the fixed hub descriptor header and its mandatory removable-port maps.
/// # C: O(descriptor bytes)
pub fn hub_descriptor(bytes: &[u8]) -> Option<HubDescriptor> {
    if bytes.len() < HUB_DESC_HEADER_BYTES || bytes[1] != DESC_HUB { return None; }
    let length = hub_descriptor_length(bytes)?;
    let ports = bytes[2];
    if length > bytes.len() { return None; }
    let characteristics = u16::from_le_bytes([bytes[3], bytes[4]]);
    Some(HubDescriptor { ports, power_good_ms: u16::from(bytes[5]).checked_mul(2)?, tt_think_time: ((characteristics >> 5) & 0x3) as u8 })
}

/// Build an IN class-device GET_DESCRIPTOR(HUB) EP0 TD. # C: O(1)
pub fn get_hub_descriptor_trbs(buffer_pa: u64, length: usize) -> Option<[crate::ring::Trb; 3]> {
    if !(HUB_DESC_HEADER_BYTES..=CONFIG_DESC_MAX_BYTES).contains(&length) { return None; }
    Some([
        crate::ring::Trb::setup_stage(HUB_GET_DESCRIPTOR_REQUEST_TYPE, 6, (DESC_HUB as u16) << 8, 0, length as u16),
        crate::ring::Trb::data_stage(buffer_pa, length as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Parsed fixed USB device descriptor fields needed by enumeration. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor { pub vendor: u16, pub product: u16, pub device_class: u8, pub device_protocol: u8, pub max_packet0: u8, pub configurations: u8 }

/// Parsed fixed configuration-descriptor header. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationHeader { pub total_length: usize, pub value: u8, pub interfaces: u8 }

/// One Linux-compatible HID boot interrupt-IN interface. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HidBootInterface { pub configuration: u8, pub interface: u8, pub protocol: u8, pub endpoint: u8, pub max_packet: u16, pub interval: u8 }

/// One alternate-setting-zero USB hub status-change interrupt endpoint.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HubInterface { pub configuration: u8, pub interface: u8, pub endpoint: u8, pub max_packet: u16, pub interval: u8 }

/// Find the hub-class interrupt-IN endpoint that reports hub and port changes.
/// # C: O(descriptors)
pub fn hub_interface(bytes: &[u8]) -> Option<HubInterface> {
    let header = configuration_header(bytes)?;
    if bytes.len() != header.total_length { return None; }
    let mut offset = CONFIG_DESC_HEADER_BYTES;
    let mut active = None;
    while offset < bytes.len() {
        if offset + 2 > bytes.len() { return None; }
        let length = bytes[offset] as usize;
        if length < 2 || offset.checked_add(length)? > bytes.len() { return None; }
        match bytes[offset + 1] {
            4 if length >= 9 => active = (bytes[offset + 3] == 0 && bytes[offset + 5] == USB_CLASS_HUB).then_some(bytes[offset + 2]),
            5 if length >= 7 => if let Some(interface) = active {
                let endpoint = bytes[offset + 2];
                let max_packet = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]) & 0x07ff;
                if endpoint & 0x80 != 0 && endpoint & 0x0f != 0 && bytes[offset + 3] & 0x3 == 3 && max_packet != 0 && bytes[offset + 6] != 0 {
                    return Some(HubInterface { configuration: header.value, interface, endpoint, max_packet, interval: bytes[offset + 6] });
                }
            },
            _ => {}
        }
        offset += length;
    }
    None
}

/// Find one alternate-setting-zero transparent-SCSI Bulk-Only interface. # C: O(descriptors)
pub fn mass_storage_interface(bytes: &[u8]) -> Option<crate::storage::MassStorageInterface> {
    let header = configuration_header(bytes)?;
    if bytes.len() != header.total_length { return None; }
    let mut active = None;
    let mut bulk_in = None;
    let mut bulk_out = None;
    let mut offset = CONFIG_DESC_HEADER_BYTES;
    while offset < bytes.len() {
        if offset + 2 > bytes.len() { return None; }
        let length = bytes[offset] as usize;
        if length < 2 || offset.checked_add(length)? > bytes.len() { return None; }
        match bytes[offset + 1] {
            4 if length >= 9 => {
                active = (bytes[offset + 3] == 0 && bytes[offset + 5] == crate::storage::USB_CLASS_MASS_STORAGE
                    && bytes[offset + 6] == crate::storage::USB_SUBCLASS_SCSI && bytes[offset + 7] == crate::storage::USB_PROTOCOL_BULK_ONLY)
                    .then_some(bytes[offset + 2]);
                bulk_in = None;
                bulk_out = None;
            }
            5 if length >= 7 => if active.is_some() && bytes[offset + 3] & 0x3 == 2 {
                let endpoint = bytes[offset + 2];
                let packet = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]) & 0x07ff;
                if endpoint & 0x0f != 0 && packet != 0 {
                    if endpoint & 0x80 != 0 { bulk_in = Some((endpoint, packet)); }
                    else { bulk_out = Some((endpoint, packet)); }
                }
            },
            _ => {}
        }
        if let (Some(interface), Some((in_ep, in_packet)), Some((out_ep, out_packet))) = (active, bulk_in, bulk_out) {
            return Some(crate::storage::MassStorageInterface { configuration: header.value, interface, bulk_in: in_ep, bulk_in_packet: in_packet, bulk_out: out_ep, bulk_out_packet: out_packet });
        }
        offset += length;
    }
    None
}

/// Parse one exact USB2 device descriptor. # C: O(1)
pub fn device_descriptor(bytes: &[u8]) -> Option<DeviceDescriptor> {
    if bytes.len() < DEVICE_DESC_BYTES || bytes[0] as usize != DEVICE_DESC_BYTES || bytes[1] != DESC_DEVICE { return None; }
    let max_packet0 = bytes[7];
    if !matches!(max_packet0, 8 | 16 | 32 | 64) || bytes[17] == 0 { return None; }
    Some(DeviceDescriptor { vendor: u16::from_le_bytes([bytes[8], bytes[9]]), product: u16::from_le_bytes([bytes[10], bytes[11]]), device_class: bytes[4], device_protocol: bytes[6], max_packet0, configurations: bytes[17] })
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
        assert_eq!(device_descriptor(&bytes), Some(DeviceDescriptor { vendor: 0x1234, product: 0x5678, device_class: 0, device_protocol: 0, max_packet0: 64, configurations: 1 }));
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
    fn storage_parser_requires_transparent_scsi_bulk_in_and_out() {
        let bytes = [9, DESC_CONFIGURATION, 32, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x02, 2, 0, 2, 0, 7, 5, 0x81, 2, 0, 2, 0];
        assert_eq!(mass_storage_interface(&bytes), Some(crate::storage::MassStorageInterface { configuration: 1, interface: 2, bulk_in: 0x81, bulk_in_packet: 512, bulk_out: 2, bulk_out_packet: 512 }));
        let mut wrong_protocol = bytes; wrong_protocol[16] = 0x62;
        assert!(mass_storage_interface(&wrong_protocol).is_none());
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
    #[test]
    fn hub_descriptor_and_class_request_keep_port_geometry_strict() {
        let descriptor = [9, DESC_HUB, 4, 0x20, 0, 10, 0, 0, 0];
        assert_eq!(hub_descriptor(&descriptor), Some(HubDescriptor { ports: 4, power_good_ms: 20, tt_think_time: 1 }));
        assert!(hub_descriptor(&[7, DESC_HUB, 4, 0, 0, 10, 0]).is_none());
        let td = get_hub_descriptor_trbs(0x90_000, 9).unwrap();
        assert_eq!(td[0].dword, [0x2900_06a0, 9 << 16, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6) | (3 << 16)]);
        assert_eq!(td[1].dword[2], 9);
    }
    #[test]
    fn hub_interface_requires_class_interrupt_in_status_endpoint() {
        let bytes = [9, DESC_CONFIGURATION, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, USB_CLASS_HUB, 0, 0, 0, 7, 5, 0x81, 3, 2, 0, 12];
        assert_eq!(hub_interface(&bytes), Some(HubInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 2, interval: 12 }));
    }
}

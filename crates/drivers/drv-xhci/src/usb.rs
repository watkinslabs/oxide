//! Strict USB descriptor validation shared by physical xHCI enumeration.

extern crate alloc;

use alloc::string::String;
use usb_core::control::{self, ControlSetup};

fn setup_stage(setup: ControlSetup) -> crate::ring::Trb {
    crate::ring::Trb::setup_stage(setup.request_type, setup.request, setup.value, setup.index, setup.length)
}

#[path = "usb/hub.rs"]
mod hub;
pub use hub::{
    get_hub_descriptor_trbs, get_hub_port_status_trbs, get_mass_storage_max_lun_trbs,
    hub_descriptor, hub_descriptor_length, hub_port_changed, hub_port_feature_trbs,
    hub_port_status, hub_status_bitmap, HubDescriptor, HubPortStatus, HubStatusBitmap,
};

/// USB device descriptor type. # C: O(1)
pub use usb_core::control::DESC_DEVICE;
/// Exact USB device descriptor byte length. # C: O(1)
pub const DEVICE_DESC_BYTES: usize = 18;
/// USB configuration descriptor type. # C: O(1)
pub use usb_core::control::DESC_CONFIGURATION;
/// USB string descriptor type. # C: O(1)
pub const DESC_STRING: u8 = 3;
/// Exact USB configuration descriptor header byte length. # C: O(1)
pub const CONFIG_DESC_HEADER_BYTES: usize = 9;
/// Largest configuration descriptor accepted by the one-page enumeration buffer. # C: O(1)
pub const CONFIG_DESC_MAX_BYTES: usize = 4096;
/// Maximum report descriptor fitting the xHCI-owned enumeration page. # C: O(1)
pub const HID_REPORT_DESC_MAX_BYTES: usize = 4096;
/// USB's maximum string descriptor transfer length. # C: O(1)
pub const STRING_DESC_MAX_BYTES: usize = 255;
/// USB hub descriptor type. # C: O(1)
pub use usb_core::control::DESC_HUB;
/// USB hub class code. # C: O(1)
pub const USB_CLASS_HUB: u8 = 9;
/// Hub descriptor bytes before the variable port-removability bitmaps. # C: O(1)
pub const HUB_DESC_HEADER_BYTES: usize = 7;
/// Hub-port status reply length. # C: O(1)
pub const HUB_PORT_STATUS_BYTES: usize = 4;
/// Hub-port power feature selector. # C: O(1)
pub const HUB_PORT_FEATURE_POWER: u16 = 8;
/// Hub-port reset feature selector. # C: O(1)
pub const HUB_PORT_FEATURE_RESET: u16 = 4;
/// Hub-port connection-change feature selector. # C: O(1)
pub const HUB_PORT_FEATURE_C_CONNECTION: u16 = 16;
/// Hub-port reset-complete change selector. # C: O(1)
pub const HUB_PORT_FEATURE_C_RESET: u16 = 20;
/// Hub-port connection-present status bit. # C: O(1)
pub const HUB_PORT_STATUS_CONNECTION: u16 = 1;
/// Hub-port enable status bit. # C: O(1)
pub const HUB_PORT_STATUS_ENABLE: u16 = 2;
/// Hub-port reset-in-progress status bit. # C: O(1)
pub const HUB_PORT_STATUS_RESET: u16 = 16;
/// Hub-port connection-change status bit. # C: O(1)
pub const HUB_PORT_CHANGE_CONNECTION: u16 = 1;
/// Hub-port reset-complete change bit. # C: O(1)
pub const HUB_PORT_CHANGE_RESET: u16 = 16;
/// Largest USB2 hub change bitmap: bit zero plus 255 downstream ports. # C: O(1)
pub const HUB_STATUS_MAX_BYTES: usize = 32;
/// Bulk-Only Transport GET_MAX_LUN response length. # C: O(1)
pub const MASS_STORAGE_MAX_LUN_BYTES: usize = 1;


/// Parsed fixed USB device descriptor fields needed by enumeration. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor { pub vendor: u16, pub product: u16, pub device_class: u8, pub device_protocol: u8, pub max_packet0: u8, pub serial_index: u8, pub configurations: u8 }

/// Parsed fixed configuration-descriptor header. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationHeader { pub total_length: usize, pub value: u8, pub interfaces: u8 }

/// One Linux-compatible HID boot interrupt-IN interface. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HidBootInterface { pub configuration: u8, pub interface: u8, pub protocol: u8, pub endpoint: u8, pub max_packet: u16, pub interval: u8 }
/// Generic descriptor-driven HID interrupt-IN interface. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HidInterface { pub configuration: u8, pub interface: u8, pub endpoint: u8, pub max_packet: u16, pub interval: u8, pub report_bytes: usize }

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

/// Parse one exact USB device descriptor.
///
/// `bMaxPacketSize0` remains in its wire encoding: USB 3.x uses `9` for a
/// 512-byte EP0 packet, while USB 2.0 carries the packet count directly.
/// # C: O(1)
pub fn device_descriptor(bytes: &[u8]) -> Option<DeviceDescriptor> {
    if bytes.len() < DEVICE_DESC_BYTES || bytes[0] as usize != DEVICE_DESC_BYTES || bytes[1] != DESC_DEVICE { return None; }
    let max_packet0 = bytes[7];
    if !matches!(max_packet0, 8 | 9 | 16 | 32 | 64) || bytes[17] == 0 { return None; }
    Some(DeviceDescriptor { vendor: u16::from_le_bytes([bytes[8], bytes[9]]), product: u16::from_le_bytes([bytes[10], bytes[11]]), device_class: bytes[4], device_protocol: bytes[6], max_packet0, serial_index: bytes[16], configurations: bytes[17] })
}

/// Decode one exact USB UTF-16LE string descriptor into a UTF-8 string. # C: O(bytes)
pub fn string_descriptor(bytes: &[u8]) -> Option<String> {
    let length = usize::from(*bytes.first()?);
    if !(2..=STRING_DESC_MAX_BYTES).contains(&length) || length % 2 != 0 || bytes.len() < length || bytes[1] != DESC_STRING { return None; }
    let mut text = String::new();
    let units = bytes[2..length].chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]]));
    for scalar in core::char::decode_utf16(units) { text.push(scalar.ok()?); }
    (!text.is_empty()).then_some(text)
}

/// Decode a descriptor's EP0 packet field against its xHCI port speed. USB
/// 2.0 carries literal values; SuperSpeed's `9` expands to 512 bytes. # C: O(1)
pub fn ep0_packet_size(speed: u8, descriptor_value: u8) -> Option<u16> {
    match speed {
        1 => matches!(descriptor_value, 8 | 16 | 32 | 64).then_some(u16::from(descriptor_value)),
        2 => (descriptor_value == 8).then_some(8),
        3 => (descriptor_value == 64).then_some(64),
        4 | 5 if descriptor_value == 9 => Some(1u16 << descriptor_value),
        4 | 5 => None,
        _ => None,
    }
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

/// Find a HID interface, its report-descriptor length, and interrupt-IN endpoint.
/// # C: O(descriptors)
pub fn hid_interface(bytes: &[u8]) -> Option<HidInterface> {
    let header = configuration_header(bytes)?; if bytes.len() != header.total_length { return None; }
    let mut offset = CONFIG_DESC_HEADER_BYTES; let mut active = None; let mut report_bytes = None;
    while offset < bytes.len() {
        if offset + 2 > bytes.len() { return None; } let length = bytes[offset] as usize;
        if length < 2 || offset.checked_add(length)? > bytes.len() { return None; }
        match bytes[offset + 1] {
            4 if length >= 9 => { active = (bytes[offset + 3] == 0 && bytes[offset + 5] == 3).then_some(bytes[offset + 2]); report_bytes = None; }
            0x21 if active.is_some() && length >= 9 && bytes[offset + 5] != 0 && bytes[offset + 6] == 0x22 => { let size = u16::from_le_bytes([bytes[offset + 7], bytes[offset + 8]]) as usize; if !(1..=HID_REPORT_DESC_MAX_BYTES).contains(&size) { return None; } report_bytes = Some(size); }
            5 if length >= 7 => if let (Some(interface), Some(report_bytes)) = (active, report_bytes) { let endpoint = bytes[offset + 2]; let max_packet = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]) & 0x07ff; if endpoint & 0x80 != 0 && endpoint & 0x0f != 0 && bytes[offset + 3] & 3 == 3 && max_packet != 0 && bytes[offset + 6] != 0 { return Some(HidInterface { configuration: header.value, interface, endpoint, max_packet, interval: bytes[offset + 6], report_bytes }); } },
            _ => {}
        }
        offset += length;
    }
    None
}

/// Build the standard IN GET_DESCRIPTOR(Device, index 0) EP0 TD. # C: O(1)
pub fn get_device_descriptor_trbs(buffer_pa: u64) -> Option<[crate::ring::Trb; 3]> {
    Some([
        setup_stage(control::get_device_descriptor(DEVICE_DESC_BYTES as u16)),
        crate::ring::Trb::data_stage(buffer_pa, DEVICE_DESC_BYTES as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Build a standard IN GET_DESCRIPTOR(String) request using the primary
/// language ID. The returned UTF-16LE descriptor is decoded by
/// [`string_descriptor`]. # C: O(1)
pub fn get_string_descriptor_trbs(buffer_pa: u64, index: u8) -> Option<[crate::ring::Trb; 3]> {
    if index == 0 { return None; }
    let setup = ControlSetup { request_type: 0x80, request: 6, value: u16::from_le_bytes([index, DESC_STRING]), index: 0x0409, length: STRING_DESC_MAX_BYTES as u16 };
    Some([setup_stage(setup), crate::ring::Trb::data_stage(buffer_pa, STRING_DESC_MAX_BYTES as u32, true)?, crate::ring::Trb::status_stage(true)])
}

/// Build a standard IN GET_DESCRIPTOR(Configuration, index) EP0 TD. # C: O(1)
pub fn get_configuration_descriptor_trbs(buffer_pa: u64, index: u8, length: usize) -> Option<[crate::ring::Trb; 3]> {
    if !(CONFIG_DESC_HEADER_BYTES..=CONFIG_DESC_MAX_BYTES).contains(&length) { return None; }
    Some([
        setup_stage(control::get_configuration_descriptor(index, length as u16)),
        crate::ring::Trb::data_stage(buffer_pa, length as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Build HID interface GET_DESCRIPTOR(Report) into the descriptor DMA page. # C: O(1)
pub fn get_hid_report_descriptor_trbs(buffer_pa: u64, interface: u8, length: usize) -> Option<[crate::ring::Trb; 3]> {
    if !(1..=HID_REPORT_DESC_MAX_BYTES).contains(&length) { return None; }
    Some([setup_stage(control::get_hid_report_descriptor(interface, length as u16)), crate::ring::Trb::data_stage(buffer_pa, length as u32, true)?, crate::ring::Trb::status_stage(true)])
}

/// Build HID class SET_IDLE(report=0, duration=0) for one interface. # C: O(1)
pub fn set_hid_idle_trbs(interface: u8) -> [crate::ring::Trb; 2] {
    [
        setup_stage(control::set_hid_idle(interface)),
        crate::ring::Trb::status_stage(false),
    ]
}

/// Build standard OUT SET_CONFIGURATION with no data stage. # C: O(1)
pub fn set_configuration_trbs(value: u8) -> Option<[crate::ring::Trb; 2]> {
    control::set_configuration(value).map(|setup| [
        setup_stage(setup),
        crate::ring::Trb::status_stage(false),
    ])
}

/// Build HID class OUT SET_PROTOCOL(Boot) for one selected interface. # C: O(1)
pub fn set_hid_boot_protocol_trbs(interface: u8) -> [crate::ring::Trb; 2] {
    [
        setup_stage(control::set_hid_boot_protocol(interface)),
        crate::ring::Trb::status_stage(false),
    ]
}

#[cfg(test)]
#[path = "usb/tests/usb.rs"]
mod tests;

//! Strict USB descriptor validation shared by physical xHCI enumeration.

use usb_core::control::{self, ControlSetup};

fn setup_stage(setup: ControlSetup) -> crate::ring::Trb {
    crate::ring::Trb::setup_stage(setup.request_type, setup.request, setup.value, setup.index, setup.length)
}

/// USB device descriptor type. # C: O(1)
pub use usb_core::control::DESC_DEVICE;
/// Exact USB device descriptor byte length. # C: O(1)
pub const DEVICE_DESC_BYTES: usize = 18;
/// USB configuration descriptor type. # C: O(1)
pub use usb_core::control::DESC_CONFIGURATION;
/// Exact USB configuration descriptor header byte length. # C: O(1)
pub const CONFIG_DESC_HEADER_BYTES: usize = 9;
/// Largest configuration descriptor accepted by the one-page enumeration buffer. # C: O(1)
pub const CONFIG_DESC_MAX_BYTES: usize = 4096;
/// Maximum report descriptor fitting the xHCI-owned enumeration page. # C: O(1)
pub const HID_REPORT_DESC_MAX_BYTES: usize = 4096;
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

/// A validated, fixed-size hub interrupt status bitmap. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HubStatusBitmap { bytes: [u8; HUB_STATUS_MAX_BYTES], length: u8 }

impl HubStatusBitmap {
    /// Status-byte slice, including hub bit zero. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes[..usize::from(self.length)] }
}

/// Decoded USB2 hub-port status and change fields. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HubPortStatus { pub status: u16, pub change: u16 }

impl HubPortStatus {
    /// Whether a downstream device is electrically connected. # C: O(1)
    pub const fn connected(self) -> bool { self.status & HUB_PORT_STATUS_CONNECTION != 0 }
    /// Whether the hub reports a connection-state transition. # C: O(1)
    pub const fn connection_changed(self) -> bool { self.change & HUB_PORT_CHANGE_CONNECTION != 0 }
    /// Whether the downstream port is enabled after reset. # C: O(1)
    pub const fn enabled(self) -> bool { self.status & HUB_PORT_STATUS_ENABLE != 0 }
    /// Whether reset remains in progress. # C: O(1)
    pub const fn resetting(self) -> bool { self.status & HUB_PORT_STATUS_RESET != 0 }
    /// Whether the hub latched reset completion. # C: O(1)
    pub const fn reset_changed(self) -> bool { self.change & HUB_PORT_CHANGE_RESET != 0 }
    /// xHCI slot-speed field synthesized from USB2 hub port status. # C: O(1)
    pub const fn xhci_portsc(self) -> u32 {
        let speed = if self.status & 0x0200 != 0 { 2 } else if self.status & 0x0400 != 0 { 3 } else { 1 };
        speed << 10
    }
}

/// Test whether one downstream port is named in a hub interrupt status bitmap. # C: O(1)
pub fn hub_port_changed(bitmap: &[u8], port: u8) -> Option<bool> {
    if port == 0 { return None; }
    let bit = usize::from(port);
    let byte = bit / 8;
    if byte >= bitmap.len() { return None; }
    Some(bitmap[byte] & (1 << (bit % 8)) != 0)
}

/// Validate an exact hub interrupt bitmap for the descriptor's port count. # C: O(status bytes)
pub fn hub_status_bitmap(bytes: &[u8], ports: u8) -> Option<HubStatusBitmap> {
    let length = (usize::from(ports).checked_add(8)? / 8).max(1);
    if length > HUB_STATUS_MAX_BYTES || bytes.len() != length { return None; }
    let mut bitmap = HubStatusBitmap { bytes: [0; HUB_STATUS_MAX_BYTES], length: length as u8 };
    bitmap.bytes[..length].copy_from_slice(bytes);
    Some(bitmap)
}

/// Parse one exact little-endian hub-port status reply. # C: O(1)
pub fn hub_port_status(bytes: &[u8]) -> Option<HubPortStatus> {
    if bytes.len() != HUB_PORT_STATUS_BYTES { return None; }
    Some(HubPortStatus { status: u16::from_le_bytes([bytes[0], bytes[1]]), change: u16::from_le_bytes([bytes[2], bytes[3]]) })
}

/// Build an IN class-port GET_STATUS EP0 TD. # C: O(1)
pub fn get_hub_port_status_trbs(buffer_pa: u64, port: u8) -> Option<[crate::ring::Trb; 3]> {
    let setup = control::get_hub_port_status(port, HUB_PORT_STATUS_BYTES as u16)?;
    Some([setup_stage(setup), crate::ring::Trb::data_stage(buffer_pa, HUB_PORT_STATUS_BYTES as u32, true)?, crate::ring::Trb::status_stage(true)])
}

/// Build a class-port SET_FEATURE or CLEAR_FEATURE EP0 TD. # C: O(1)
pub fn hub_port_feature_trbs(port: u8, feature: u16, set: bool) -> Option<[crate::ring::Trb; 2]> {
    Some([setup_stage(control::hub_port_feature(port, feature, set)?), crate::ring::Trb::status_stage(false)])
}

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
        setup_stage(control::get_hub_descriptor(length as u16)),
        crate::ring::Trb::data_stage(buffer_pa, length as u32, true)?,
        crate::ring::Trb::status_stage(true),
    ])
}

/// Build the Bulk-Only Transport GET_MAX_LUN request for one interface. # C: O(1)
pub fn get_mass_storage_max_lun_trbs(buffer_pa: u64, interface: u8) -> Option<[crate::ring::Trb; 3]> {
    Some([
        setup_stage(control::get_mass_storage_max_lun(interface)),
        crate::ring::Trb::data_stage(buffer_pa, MASS_STORAGE_MAX_LUN_BYTES as u32, true)?,
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
    fn generic_hid_interface_and_report_request_are_exact() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22, 52, 0, 7, 5, 0x81, 3, 8, 0, 10];
        assert_eq!(hid_interface(&bytes), Some(HidInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 8, interval: 10, report_bytes: 52 }));
        let td = get_hid_report_descriptor_trbs(0x90_000, 0, 52).unwrap();
        assert_eq!(td[0].dword[0], 0x2200_0681);
        assert_eq!(td[1].dword[2], 52);
        let idle = set_hid_idle_trbs(3);
        assert_eq!(idle[0].dword[0], 0x0000_0a21);
        assert_eq!(idle[0].dword[1], 3);
        assert_eq!(idle[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 5) | (1 << 16));
    }
    #[test]
    fn storage_parser_requires_transparent_scsi_bulk_in_and_out() {
        let bytes = [9, DESC_CONFIGURATION, 32, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x02, 2, 0, 2, 0, 7, 5, 0x81, 2, 0, 2, 0];
        assert_eq!(mass_storage_interface(&bytes), Some(crate::storage::MassStorageInterface { configuration: 1, interface: 2, bulk_in: 0x81, bulk_in_packet: 512, bulk_out: 2, bulk_out_packet: 512 }));
        let mut wrong_protocol = bytes; wrong_protocol[16] = 0x62;
        assert!(mass_storage_interface(&wrong_protocol).is_none());
        let max_lun = get_mass_storage_max_lun_trbs(0x90_000, 2).unwrap();
        assert_eq!(max_lun[0].dword, [0x0000_fea1, 2 | ((MASS_STORAGE_MAX_LUN_BYTES as u32) << 16), 8,
            (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6) | (3 << 16)]);
        assert_eq!(max_lun[1].dword[2], MASS_STORAGE_MAX_LUN_BYTES as u32);
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
    fn hub_port_control_uses_class_port_recipients_and_exact_status_bytes() {
        assert_eq!(hub_port_status(&[1, 0, 1, 0]), Some(HubPortStatus { status: 1, change: 1 }));
        assert!(hub_port_status(&[0; 3]).is_none());
        let status = get_hub_port_status_trbs(0x90_000, 2).unwrap();
        assert_eq!(status[0].dword[0], 0x0000_00a3);
        assert_eq!(status[0].dword[1], 2 | ((HUB_PORT_STATUS_BYTES as u32) << 16));
        let power = hub_port_feature_trbs(2, HUB_PORT_FEATURE_POWER, true).unwrap();
        assert_eq!(power[0].dword[0], 0x0008_0323);
        assert_eq!(hub_port_changed(&[0b0000_0010], 1), Some(true));
        assert_eq!(hub_port_changed(&[0b0000_0010], 2), Some(false));
        assert_eq!(hub_port_changed(&[0], 8), None);
        let reset = hub_port_status(&[0x13, 4, 16, 0]).unwrap();
        assert!(reset.connected() && reset.enabled() && reset.resetting() && reset.reset_changed());
        assert_eq!(reset.xhci_portsc(), 3 << 10);
    }
    #[test]
    fn hub_interrupt_bitmap_is_exact_and_covers_bit_zero_through_last_port() {
        let bitmap = hub_status_bitmap(&[0b0000_0001, 0b0000_0010], 9).unwrap();
        assert_eq!(bitmap.bytes(), &[0b0000_0001, 0b0000_0010]);
        assert_eq!(hub_port_changed(bitmap.bytes(), 9), Some(true));
        assert!(hub_status_bitmap(&[0], 9).is_none());
        assert!(hub_status_bitmap(&[0; HUB_STATUS_MAX_BYTES + 1], u8::MAX).is_none());
    }
    #[test]
    fn hub_interface_requires_class_interrupt_in_status_endpoint() {
        let bytes = [9, DESC_CONFIGURATION, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, USB_CLASS_HUB, 0, 0, 0, 7, 5, 0x81, 3, 2, 0, 12];
        assert_eq!(hub_interface(&bytes), Some(HubInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 2, interval: 12 }));
    }
}

use super::*;

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

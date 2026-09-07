//! Raw-input ordinals: device enumeration, device information, the registered
//! usage list and the per-message raw record.

use ipc::win32_window::rawinput::*;

pub(crate) const GET_RAW_INPUT_BUFFER: u64 = 0x143d;
pub(crate) const GET_RAW_INPUT_DATA: u64 = 0x143e;
pub(crate) const GET_RAW_INPUT_DEVICE_INFO: u64 = 0x143f;
pub(crate) const GET_RAW_INPUT_DEVICE_LIST: u64 = 0x1440;
pub(crate) const GET_REGISTERED_RAW_INPUT_DEVICES: u64 = 0x1442;
pub(crate) const REGISTER_RAW_INPUT_DEVICES: u64 = 0x14fa;

/// Every raw-input query answers this when it refuses.
pub(crate) const REFUSED: u64 = u32::MAX as u64;

/// Encode one `RAWINPUTDEVICELIST`. # C: O(1)
pub(crate) fn encode_device(device: RawDevice) -> [u8; RAWINPUTDEVICELIST_BYTES] {
    let mut bytes = [0u8; RAWINPUTDEVICELIST_BYTES];
    bytes[0..8].copy_from_slice(&device.handle.to_le_bytes());
    bytes[8..12].copy_from_slice(&device.kind.to_le_bytes());
    bytes
}

/// Encode one `RAWINPUTDEVICE`. # C: O(1)
pub(crate) fn encode_registration(entry: RawRegistration) -> [u8; RAWINPUTDEVICE_BYTES] {
    let mut bytes = [0u8; RAWINPUTDEVICE_BYTES];
    bytes[0..2].copy_from_slice(&entry.usage_page.to_le_bytes());
    bytes[2..4].copy_from_slice(&entry.usage.to_le_bytes());
    bytes[4..8].copy_from_slice(&entry.flags.to_le_bytes());
    bytes[8..16].copy_from_slice(&entry.target.map_or(0u64, |id| id.raw() as u64).to_le_bytes());
    bytes
}

/// Decode one `RAWINPUTDEVICE`. # C: O(1)
pub(crate) fn decode_registration(bytes: &[u8; RAWINPUTDEVICE_BYTES]) -> RawRegistration {
    let target = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    RawRegistration {
        usage_page: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
        usage: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        flags: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        target: u32::try_from(target).ok().and_then(ipc::win32_window::WindowId::from_raw),
    }
}

/// Devices a batch may register at once, bounding the record read from user
/// space.
pub(crate) const MAX_BATCH: usize = 64;

/// How many entries a listing writes and whether the caller's buffer was big
/// enough. A null buffer only reports the count. # C: O(1)
pub(crate) fn listing_plan(buffer: u64, capacity: u32, available: usize) -> (usize, bool) {
    if buffer == 0 { return (0, true); }
    (available.min(capacity as usize), capacity as usize >= available)
}

/// A device-information query answers the units or bytes the command needs,
/// which is the name length for a name request and the record size for an
/// information request. # C: O(1)
pub(crate) fn device_info_length(command: u32, handle: u64) -> Option<u32> {
    match command {
        // The reported name length counts the terminator.
        RIDI_DEVICENAME => device_path(handle).map(|path| path.len() as u32 + 1),
        RIDI_DEVICEINFO => device_info(handle).map(|_| RID_DEVICE_INFO_BYTES as u32),
        // No collection describes a mouse or keyboard, so the preparsed data
        // is empty rather than absent.
        RIDI_PREPARSEDDATA => device_info(handle).map(|_| 0),
        _ => None,
    }
}

#[cfg(target_os = "oxide-kernel")]
#[path = "rawinput_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "rawinput_raw/tests.rs"]
mod tests;

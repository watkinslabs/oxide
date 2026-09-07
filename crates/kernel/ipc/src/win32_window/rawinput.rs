//! Raw input: the device inventory a process enumerates, and the usage
//! registrations that decide which raw messages reach it.

use alloc::vec::Vec;
use super::WindowId;

pub const RIM_TYPEMOUSE: u32 = 0;
pub const RIM_TYPEKEYBOARD: u32 = 1;
pub const RIM_TYPEHID: u32 = 2;

pub const RIDI_PREPARSEDDATA: u32 = 0x2000_0005;
pub const RIDI_DEVICENAME: u32 = 0x2000_0007;
pub const RIDI_DEVICEINFO: u32 = 0x2000_000b;

pub const RID_INPUT: u32 = 0x1000_0003;
pub const RID_HEADER: u32 = 0x1000_0005;

pub const RIDEV_REMOVE: u32 = 0x0000_0001;
pub const RIDEV_NOLEGACY: u32 = 0x0000_0030;
pub const RIDEV_INPUTSINK: u32 = 0x0000_0100;
pub const RIDEV_DEVNOTIFY: u32 = 0x0000_2000;

/// `RAWINPUTDEVICE` on the 64-bit client ABI: two usage words, the flags, then
/// the aligned target window handle.
pub const RAWINPUTDEVICE_BYTES: usize = 16;
/// `RAWINPUTDEVICELIST`: the device handle then the aligned type word.
pub const RAWINPUTDEVICELIST_BYTES: usize = 16;
/// `RID_DEVICE_INFO`: size and type words plus the widest device union arm.
pub const RID_DEVICE_INFO_BYTES: usize = 32;
/// `RAWINPUTHEADER` on the 64-bit client ABI.
pub const RAWINPUTHEADER_BYTES: usize = 24;

/// Devices are handed fixed handles: the desktop presents one mouse and one
/// keyboard, and a handle never names a window.
pub const MOUSE_HANDLE: u64 = 1;
pub const KEYBOARD_HANDLE: u64 = 2;

const MAX_REGISTRATIONS: usize = 64;

/// One entry of the enumerated device inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawDevice { pub handle: u64, pub kind: u32 }

/// One usage registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRegistration { pub usage_page: u16, pub usage: u16, pub flags: u32, pub target: Option<WindowId> }

/// Device inventory the raw-input queries enumerate. # C: O(1)
pub fn devices() -> [RawDevice; 2] {
    [RawDevice { handle: MOUSE_HANDLE, kind: RIM_TYPEMOUSE },
     RawDevice { handle: KEYBOARD_HANDLE, kind: RIM_TYPEKEYBOARD }]
}

/// Device interface path one handle reports, as UTF-16 units without a
/// terminator. # C: O(1)
pub fn device_path(handle: u64) -> Option<&'static [u16]> {
    const MOUSE: &[u16] = &[0x5c,0x5c,0x3f,0x5c,0x57,0x49,0x4e,0x45,0x23,0x4d,0x4f,0x55,0x53,0x45]; // \\?\WINE#MOUSE
    const KEYBOARD: &[u16] = &[0x5c,0x5c,0x3f,0x5c,0x57,0x49,0x4e,0x45,0x23,0x4b,0x42,0x44]; // \\?\WINE#KBD
    match handle { MOUSE_HANDLE => Some(MOUSE), KEYBOARD_HANDLE => Some(KEYBOARD), _ => None }
}

/// The `RID_DEVICE_INFO` bytes one device reports. The mouse presents five
/// buttons with no sample rate and no horizontal wheel; the keyboard presents
/// the enhanced 101-key layout with twelve function keys and three indicators.
/// # C: O(1)
pub fn device_info(handle: u64) -> Option<[u8; RID_DEVICE_INFO_BYTES]> {
    let kind = match handle { MOUSE_HANDLE => RIM_TYPEMOUSE, KEYBOARD_HANDLE => RIM_TYPEKEYBOARD, _ => return None };
    let mut bytes = [0u8; RID_DEVICE_INFO_BYTES];
    let mut put = |offset: usize, value: u32| bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    put(0, RID_DEVICE_INFO_BYTES as u32);
    put(4, kind);
    let fields: &[u32] = if kind == RIM_TYPEMOUSE { &[1, 5, 0, 0] } else { &[0, 0, 1, 12, 3, 101] };
    for (index, value) in fields.iter().enumerate() { put(8 + index * 4, *value); }
    Some(bytes)
}

/// Registered usages for one process, kept sorted by usage page then usage.
#[derive(Default)]
pub struct RawRegistrations { entries: Vec<RawRegistration> }

/// Why a registration request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawInputError { InvalidParameter, NoMemory, InsufficientBuffer }

impl RawRegistrations {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: Vec::new() } }
    /// # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// # C: O(N_registrations)
    pub fn entries(&self) -> &[RawRegistration] { &self.entries }

    /// Admit a whole batch before applying any of it: an input-sink request
    /// with no target window, and a removal that still names one, are refused.
    /// # C: O(N_batch * N_registrations)
    pub fn register(&mut self, batch: &[RawRegistration]) -> Result<(), RawInputError> {
        for device in batch {
            if device.flags & RIDEV_INPUTSINK != 0 && device.target.is_none() { return Err(RawInputError::InvalidParameter); }
            if device.flags & RIDEV_REMOVE != 0 && device.target.is_some() { return Err(RawInputError::InvalidParameter); }
        }
        if self.entries.is_empty() && batch.is_empty() { return Ok(()); }
        self.entries.try_reserve(batch.len()).map_err(|_| RawInputError::NoMemory)?;
        for device in batch { self.apply(*device)?; }
        Ok(())
    }

    /// # C: O(N_registrations)
    fn apply(&mut self, device: RawRegistration) -> Result<(), RawInputError> {
        let position = self.entries.iter().position(|entry|
            (entry.usage_page, entry.usage) >= (device.usage_page, device.usage));
        let at = position.unwrap_or(self.entries.len());
        let matches = self.entries.get(at).is_some_and(|entry|
            entry.usage_page == device.usage_page && entry.usage == device.usage);
        if device.flags & RIDEV_REMOVE != 0 {
            if matches { self.entries.remove(at); }
            return Ok(());
        }
        if matches { self.entries[at] = device; return Ok(()); }
        if self.entries.len() >= MAX_REGISTRATIONS { return Err(RawInputError::NoMemory); }
        self.entries.insert(at, device);
        Ok(())
    }
}

impl super::WindowManager {
    /// # C: O(1)
    pub fn raw_input_devices(&self) -> &[RawRegistration] { self.raw_input.entries() }
    /// # C: O(N_batch * N_registrations)
    pub fn register_raw_input(&mut self, batch: &[RawRegistration]) -> Result<(), RawInputError> {
        self.raw_input.register(batch)
    }
}

#[cfg(test)]
#[path = "tests/rawinput.rs"]
mod tests;

//! `DEVMODEW` and `DISPLAY_DEVICEW` field offsets and codecs. Only the display
//! fields are read or written; the printer fields belong to a printer driver.

/// Size of the `DEVMODEW` record a display query fills.
pub(crate) const DEVMODE_BYTES: usize = 220;
/// Offsets into `DEVMODEW`.
pub(crate) const DEVMODE_DEVICE_NAME: usize = 0;
pub(crate) const DEVMODE_NAME_CHARS: usize = 32;
pub(crate) const DEVMODE_SPEC_VERSION: usize = 64;
pub(crate) const DEVMODE_SIZE: usize = 68;
pub(crate) const DEVMODE_DRIVER_EXTRA: usize = 70;
pub(crate) const DEVMODE_FIELDS: usize = 72;
pub(crate) const DEVMODE_POSITION: usize = 76;
pub(crate) const DEVMODE_DISPLAY_ORIENTATION: usize = 84;
pub(crate) const DEVMODE_LOG_PIXELS: usize = 166;
pub(crate) const DEVMODE_BITS_PER_PEL: usize = 168;
pub(crate) const DEVMODE_PELS_WIDTH: usize = 172;
pub(crate) const DEVMODE_PELS_HEIGHT: usize = 176;
pub(crate) const DEVMODE_DISPLAY_FLAGS: usize = 180;
pub(crate) const DEVMODE_DISPLAY_FREQUENCY: usize = 184;
/// `DEVMODEW.dmSpecVersion` for a current record.
pub(crate) const DM_SPECVERSION: u16 = 0x0401;

/// `dmFields` bits a display mode sets.
pub(crate) const DM_BITSPERPEL: u32 = 0x0004_0000;
pub(crate) const DM_PELSWIDTH: u32 = 0x0008_0000;
pub(crate) const DM_PELSHEIGHT: u32 = 0x0010_0000;
pub(crate) const DM_DISPLAYFLAGS: u32 = 0x0020_0000;
pub(crate) const DM_DISPLAYFREQUENCY: u32 = 0x0040_0000;
pub(crate) const DM_POSITION: u32 = 0x0000_0020;
pub(crate) const DM_DISPLAYORIENTATION: u32 = 0x0000_0080;
pub(crate) const DISPLAY_MODE_FIELDS: u32 = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT
    | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY | DM_POSITION | DM_DISPLAYORIENTATION;

/// Size of the `DISPLAY_DEVICEW` record a device query fills.
pub(crate) const DISPLAY_DEVICE_BYTES: usize = 840;
pub(crate) const DISPLAY_DEVICE_NAME: usize = 4;
pub(crate) const DISPLAY_DEVICE_STRING: usize = 68;
pub(crate) const DISPLAY_DEVICE_STATE_FLAGS: usize = 324;
pub(crate) const DISPLAY_DEVICE_ID: usize = 328;
pub(crate) const DISPLAY_DEVICE_KEY: usize = 584;
pub(crate) const DISPLAY_DEVICE_STRING_CHARS: usize = 128;

/// `DISPLAY_DEVICE_ATTACHED_TO_DESKTOP`, `_PRIMARY_DEVICE` and `_VGA_COMPATIBLE`.
pub(crate) const DISPLAY_DEVICE_ATTACHED_TO_DESKTOP: u32 = 0x0000_0001;
pub(crate) const DISPLAY_DEVICE_PRIMARY_DEVICE: u32 = 0x0000_0004;
pub(crate) const DISPLAY_DEVICE_VGA_COMPATIBLE: u32 = 0x0000_0010;

/// One display mode a source can produce.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DisplayMode { pub width: u32, pub height: u32, pub bits: u32, pub frequency: u32, pub dpi: u32 }

/// Write a UTF-16 name into a fixed-width field, always NUL terminated.
/// # C: O(N_chars)
pub(crate) fn put_wide(bytes: &mut [u8], offset: usize, chars: usize, text: &[u16]) {
    for index in 0..chars {
        let value = if index + 1 < chars { text.get(index).copied().unwrap_or(0) } else { 0 };
        let at = offset + index * 2;
        if at + 2 <= bytes.len() { bytes[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
    }
}

/// Fill the display fields of a `DEVMODEW` the caller supplied. The caller's
/// `dmSize` decides how much of the record it can read back. # C: O(1)
pub(crate) fn encode_mode(bytes: &mut [u8; DEVMODE_BYTES], name: &[u16], mode: DisplayMode) {
    put_wide(bytes, DEVMODE_DEVICE_NAME, DEVMODE_NAME_CHARS, name);
    let put16 = |bytes: &mut [u8; DEVMODE_BYTES], offset: usize, value: u16| bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |bytes: &mut [u8; DEVMODE_BYTES], offset: usize, value: u32| bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    put16(bytes, DEVMODE_SPEC_VERSION, DM_SPECVERSION);
    put16(bytes, DEVMODE_SIZE, DEVMODE_BYTES as u16);
    put16(bytes, DEVMODE_DRIVER_EXTRA, 0);
    put32(bytes, DEVMODE_FIELDS, DISPLAY_MODE_FIELDS);
    put32(bytes, DEVMODE_POSITION, 0);
    put32(bytes, DEVMODE_POSITION + 4, 0);
    put32(bytes, DEVMODE_DISPLAY_ORIENTATION, 0);
    put16(bytes, DEVMODE_LOG_PIXELS, mode.dpi as u16);
    put32(bytes, DEVMODE_BITS_PER_PEL, mode.bits);
    put32(bytes, DEVMODE_PELS_WIDTH, mode.width);
    put32(bytes, DEVMODE_PELS_HEIGHT, mode.height);
    put32(bytes, DEVMODE_DISPLAY_FLAGS, 0);
    put32(bytes, DEVMODE_DISPLAY_FREQUENCY, mode.frequency);
}

/// Read the display fields a mode request names. A field the request does not
/// claim in `dmFields` reads as zero, which means "keep the current value".
/// # C: O(1)
pub(crate) fn decode_mode(bytes: &[u8; DEVMODE_BYTES]) -> (u32, u32, u32, u32) {
    let dword = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let fields = dword(DEVMODE_FIELDS);
    let claimed = |bit: u32, offset: usize| if fields & bit != 0 { dword(offset) } else { 0 };
    (claimed(DM_PELSWIDTH, DEVMODE_PELS_WIDTH), claimed(DM_PELSHEIGHT, DEVMODE_PELS_HEIGHT),
     claimed(DM_BITSPERPEL, DEVMODE_BITS_PER_PEL), claimed(DM_DISPLAYFREQUENCY, DEVMODE_DISPLAY_FREQUENCY))
}

/// Fill a `DISPLAY_DEVICEW`. # C: O(1)
pub(crate) fn encode_device(bytes: &mut [u8; DISPLAY_DEVICE_BYTES], name: &[u16], string: &[u16],
    id: &[u16], key: &[u16], state: u32) {
    put_wide(bytes, DISPLAY_DEVICE_NAME, DEVMODE_NAME_CHARS, name);
    put_wide(bytes, DISPLAY_DEVICE_STRING, DISPLAY_DEVICE_STRING_CHARS, string);
    bytes[DISPLAY_DEVICE_STATE_FLAGS..DISPLAY_DEVICE_STATE_FLAGS + 4].copy_from_slice(&state.to_le_bytes());
    put_wide(bytes, DISPLAY_DEVICE_ID, DISPLAY_DEVICE_STRING_CHARS, id);
    put_wide(bytes, DISPLAY_DEVICE_KEY, DISPLAY_DEVICE_STRING_CHARS, key);
}

#[cfg(test)]
#[path = "../tests/devmode.rs"]
mod tests;

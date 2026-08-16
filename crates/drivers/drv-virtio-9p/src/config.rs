// The virtio-9p device configuration: the mount tag a `mount -t 9p <tag>`
// names the device by.
//
// Pure over a byte source so the parse is testable without a device: a tag read
// one byte short, or one that runs past the buffer, silently selects the wrong
// share or none at all.

extern crate alloc;
use alloc::string::String;

/// Longest tag this driver will accept. A device is free to declare a longer
/// one; a tag that cannot be held is a device this driver does not bind rather
/// than a truncated name that would match the wrong mount.
pub const MAX_TAG_LEN: usize = 256;

/// Byte offset of `tag_len` in the device configuration.
pub const CFG_OFF_TAG_LEN: u64 = 0;
/// Byte offset of the tag bytes.
pub const CFG_OFF_TAG: u64 = 2;

/// Why a device configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagError {
    /// The device declared a zero-length tag; nothing could ever name it.
    Empty,
    /// The tag is longer than this driver will hold.
    TooLong,
    /// The tag is not valid UTF-8, so it cannot be compared against a mount
    /// source string without a lossy conversion that could alias two devices.
    NotUtf8,
    /// The tag contains a byte that cannot appear in a device name.
    BadByte,
}

/// Decode a mount tag from the raw configuration bytes.
///
/// The tag is NOT necessarily NUL-terminated: when it fills the declared
/// length there is no terminator, and treating the bytes as a C string would
/// read past the field. `tag_len` is therefore authoritative and a NUL is only
/// an early end. # C: O(len)
pub fn parse_tag(tag_len: u16, bytes: &[u8]) -> Result<String, TagError> {
    let declared = tag_len as usize;
    if declared == 0 { return Err(TagError::Empty); }
    if declared > MAX_TAG_LEN || declared > bytes.len() { return Err(TagError::TooLong); }
    let field = &bytes[..declared];
    let end = field.iter().position(|b| *b == 0).unwrap_or(declared);
    let name = &field[..end];
    if name.is_empty() { return Err(TagError::Empty); }
    // A newline would break every line-oriented consumer of a device name, and
    // a control byte in a mount source is never legitimate.
    if name.iter().any(|b| *b < 0x20 || *b == 0x7f) { return Err(TagError::BadByte); }
    core::str::from_utf8(name).map(String::from).map_err(|_| TagError::NotUtf8)
}

/// Read the tag from a mapped device-configuration region.
///
/// # SAFETY: `cfg_va` must be the transport-mapped virtio device configuration
/// address for a live virtio-9p device, readable for at least
/// `CFG_OFF_TAG + tag_len` bytes; the caller keeps the mapping alive across
/// this call.
///
/// # C: O(tag_len)
pub unsafe fn read_tag(cfg_va: u64) -> Result<String, TagError> {
    if cfg_va == 0 { return Err(TagError::Empty); }
    // SAFETY: transport-mapped device configuration address; the two bytes of
    // `tag_len` are the first field of the region and always present.
    let lo = unsafe { core::ptr::read_volatile((cfg_va + CFG_OFF_TAG_LEN) as *const u8) };
    // SAFETY: same region, the second byte of the same `tag_len` field.
    let hi = unsafe { core::ptr::read_volatile((cfg_va + CFG_OFF_TAG_LEN + 1) as *const u8) };
    let tag_len = u16::from_le_bytes([lo, hi]);
    let declared = tag_len as usize;
    if declared == 0 { return Err(TagError::Empty); }
    if declared > MAX_TAG_LEN { return Err(TagError::TooLong); }
    let mut buf = [0u8; MAX_TAG_LEN];
    for (i, slot) in buf.iter_mut().take(declared).enumerate() {
        // SAFETY: `i < declared <= MAX_TAG_LEN` and the device declared
        // `tag_len` readable bytes at `CFG_OFF_TAG`, so this stays inside the
        // configuration region the transport mapped.
        *slot = unsafe { core::ptr::read_volatile((cfg_va + CFG_OFF_TAG + i as u64) as *const u8) };
    }
    parse_tag(tag_len, &buf[..declared])
}

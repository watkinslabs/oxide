// The virtiofs device configuration: the mount tag a `mount -t virtiofs <tag>`
// names the share by.
//
// Pure over the raw bytes so the parse is testable without a device.

extern crate alloc;
use alloc::string::String;

use crate::consts::{CFG_OFF_NUM_REQUEST_QUEUES, CFG_OFF_TAG, CFG_TAG_LEN};

/// Why a device configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagError {
    /// The tag field is all NUL; nothing could ever name the share.
    Empty,
    /// The tag is not valid UTF-8, so it cannot be compared against a mount
    /// source without a lossy conversion that could alias two shares.
    NotUtf8,
    /// The tag contains a byte that cannot appear in a mount source.
    BadByte,
}

/// Decode the mount tag from the fixed-width configuration field.
///
/// The field is NUL-PADDED, not NUL-terminated: a tag that fills all 36 bytes
/// has no terminator, and treating the field as a C string would read into the
/// queue-count that follows it. The field width is therefore the bound and a
/// NUL is only an early end. # C: O(1)
pub fn parse_tag(field: &[u8]) -> Result<String, TagError> {
    let n = field.len().min(CFG_TAG_LEN);
    let field = &field[..n];
    let end = field.iter().position(|b| *b == 0).unwrap_or(n);
    let name = &field[..end];
    if name.is_empty() { return Err(TagError::Empty); }
    if name.iter().any(|b| *b < 0x20 || *b == 0x7f) { return Err(TagError::BadByte); }
    core::str::from_utf8(name).map(String::from).map_err(|_| TagError::NotUtf8)
}

/// Read the tag and the request-queue count from a mapped configuration region.
///
/// # SAFETY: `cfg_va` must be the transport-mapped virtio device configuration
/// address for a live virtio-fs device, readable for at least
/// `CFG_OFF_NUM_REQUEST_QUEUES + 4` bytes, and the caller keeps the mapping
/// alive across this call.
///
/// # C: O(1)
pub unsafe fn read_config(cfg_va: u64) -> Result<(String, u32), TagError> {
    if cfg_va == 0 { return Err(TagError::Empty); }
    let mut field = [0u8; CFG_TAG_LEN];
    for (i, slot) in field.iter_mut().enumerate() {
        // SAFETY: `i < CFG_TAG_LEN`, and the tag field is the first 36 bytes of
        // the configuration region the transport mapped for this device.
        *slot = unsafe { core::ptr::read_volatile((cfg_va + CFG_OFF_TAG + i as u64) as *const u8) };
    }
    let tag = parse_tag(&field)?;
    let mut nq = [0u8; 4];
    for (i, slot) in nq.iter_mut().enumerate() {
        // SAFETY: same mapped region; the queue count is the four bytes
        // immediately after the tag field.
        *slot = unsafe {
            core::ptr::read_volatile((cfg_va + CFG_OFF_NUM_REQUEST_QUEUES + i as u64) as *const u8)
        };
    }
    Ok((tag, u32::from_le_bytes(nq)))
}

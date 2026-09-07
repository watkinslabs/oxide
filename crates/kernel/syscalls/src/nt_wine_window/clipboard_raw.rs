//! Clipboard ordinal decoding and result encoding. Every clipboard decision
//! lives in the window-station store; this module only decodes arguments.

pub(crate) const ADD_FORMAT_LISTENER: u64 = 0x131a;
pub(crate) const CHANGE_CLIPBOARD_CHAIN: u64 = 0x1341;
pub(crate) const COUNT_FORMATS: u64 = 0x135b;
pub(crate) const EMPTY_CLIPBOARD: u64 = 0x13a4;
pub(crate) const ENUM_FORMATS: u64 = 0x13be;
pub(crate) const GET_DATA: u64 = 0x13dc;
pub(crate) const GET_FORMAT_NAME: u64 = 0x13dd;
pub(crate) const GET_OWNER: u64 = 0x13df;
pub(crate) const GET_SEQUENCE_NUMBER: u64 = 0x13e0;
pub(crate) const GET_VIEWER: u64 = 0x13e1;
pub(crate) const GET_OPEN_WINDOW: u64 = 0x1422;
pub(crate) const GET_PRIORITY_FORMAT: u64 = 0x1433;
pub(crate) const GET_UPDATED_FORMATS: u64 = 0x1457;
pub(crate) const IS_FORMAT_AVAILABLE: u64 = 0x148f;
pub(crate) const REMOVE_FORMAT_LISTENER: u64 = 0x151b;
pub(crate) const SET_DATA: u64 = 0x1541;
pub(crate) const SET_VIEWER: u64 = 0x1542;

/// `struct get_clipboard_params`: the caller's buffer, its size, the size the
/// data actually needs, the sequence number and the data-only flag.
pub(crate) const GET_PARAMS_DATA: u64 = 0;
pub(crate) const GET_PARAMS_SIZE: u64 = 8;
pub(crate) const GET_PARAMS_DATA_SIZE: u64 = 16;
pub(crate) const GET_PARAMS_SEQNO: u64 = 24;
pub(crate) const GET_PARAMS_DATA_ONLY: u64 = 28;

/// `struct set_clipboard_params`: the bytes, their size, the cache-only flag
/// and the sequence number the cache entry claims.
pub(crate) const SET_PARAMS_DATA: u64 = 0;
pub(crate) const SET_PARAMS_SIZE: u64 = 8;
pub(crate) const SET_PARAMS_CACHE_ONLY: u64 = 16;
pub(crate) const SET_PARAMS_SEQNO: u64 = 20;

/// Largest single format transfer admitted, so a hostile size cannot ask the
/// kernel to copy an unbounded user buffer.
pub(crate) const MAX_FORMAT_BYTES: u64 = 64 * 1024 * 1024;

/// The list a priority query walks is bounded by the count Windows itself can
/// express through the call's INT parameter.
pub(crate) const MAX_PRIORITY_FORMATS: usize = 4096;

/// Whether one ordinal belongs to the clipboard family. # C: O(1)
pub(crate) const fn claims(ordinal: u64) -> bool {
    matches!(ordinal, ADD_FORMAT_LISTENER | CHANGE_CLIPBOARD_CHAIN | COUNT_FORMATS | EMPTY_CLIPBOARD
        | ENUM_FORMATS | GET_DATA | GET_FORMAT_NAME | GET_OWNER | GET_SEQUENCE_NUMBER | GET_VIEWER
        | GET_OPEN_WINDOW | GET_PRIORITY_FORMAT | GET_UPDATED_FORMATS | IS_FORMAT_AVAILABLE
        | REMOVE_FORMAT_LISTENER | SET_DATA | SET_VIEWER)
}

/// How many format identifiers a caller's buffer can hold, and whether the
/// request is answerable at all. A request with a buffer but no place to
/// report the count is refused. # C: O(1)
pub(crate) fn updated_formats_capacity(buffer: u64, size: u32, out_size: u64) -> Option<usize> {
    if out_size == 0 { return None; }
    if buffer == 0 { return Some(0); }
    Some(size as usize)
}

/// Whether a stored format fits the caller's buffer. A caller that asked for
/// no bytes is only measuring. # C: O(1)
pub(crate) const fn fits(stored: usize, capacity: u64) -> bool { capacity == 0 || stored as u64 <= capacity }

#[cfg(target_os = "oxide-kernel")]
#[path = "clipboard_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/clipboard_raw.rs"]
mod tests;

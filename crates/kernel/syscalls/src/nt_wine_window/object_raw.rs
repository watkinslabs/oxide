//! Raw object-query admission; canonical owner supplies all logical bytes.
pub(crate) const EXT_GET_OBJECT_W: u64 = 0x11c7;
pub(crate) const GET_DC_OBJECT: u64 = 0x11f0;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const LOGFONTW_SIZE: u32 = 92;
pub(crate) const ENUMLOGFONTEXW_SIZE: u32 = 348;
pub(crate) const ENUMLOGFONTEXDVW_SIZE: u32 = 420;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FontCreateError { NullInput, InvalidSize }

impl FontCreateError {
    /// A null input fails without changing last error; invalid size sets error 87. # C: O(1)
    pub(crate) fn last_error(self) -> Option<u32> {
        match self { Self::NullInput => None, Self::InvalidSize => Some(ERROR_INVALID_PARAMETER) }
    }
}

/// Only the three concrete logical-font structure sizes are admitted. # C: O(1)
pub(crate) fn valid_hfont_create_size(size: u32) -> bool {
    matches!(size, LOGFONTW_SIZE | ENUMLOGFONTEXW_SIZE | ENUMLOGFONTEXDVW_SIZE)
}

/// Preserve null-input precedence before size validation and before any usercopy. # C: O(1)
pub(crate) fn validate_hfont_create(logfont: u64, size: u32) -> Result<(), FontCreateError> {
    if logfont == 0 { return Err(FontCreateError::NullInput); }
    if !valid_hfont_create_size(size) { return Err(FontCreateError::InvalidSize); }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Query { pub handle: u64, pub count: i32, pub output: u64 }

/// Decode the three raw arguments, preserving the signed 32-bit count. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Query> {
    if ordinal != EXT_GET_OBJECT_W || args.len() < 3 { return None; }
    Some(Query { handle: args[0], count: args[1] as i32, output: args[2] })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "object_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "object_raw/tests.rs"]
mod tests;

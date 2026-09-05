//! Hosted-testable ABI policy for `ProcessCommandLineInformation`.

pub(crate) const CLASS: u32 = 60;
pub(crate) const HEADER_BYTES: usize = 16;
pub(crate) const TERMINATOR_BYTES: usize = 2;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// Validate the source `UNICODE_STRING` owned by the NT process parameters.
/// # C: O(1)
pub(crate) fn source_bytes(length: u16, maximum: u16, buffer: u64) -> Result<usize, u64> {
    let length = length as usize;
    let maximum = maximum as usize;
    if length & 1 != 0 || maximum < length.saturating_add(TERMINATOR_BYTES)
        || (length != 0 && buffer == 0) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Some(length).filter(|bytes| *bytes <= u16::MAX as usize - TERMINATOR_BYTES).ok_or(STATUS_INVALID_PARAMETER)
}

/// Return the output size including the `UNICODE_STRING` and terminator.
/// # C: O(1)
pub(crate) const fn required_bytes(string_bytes: usize) -> Option<usize> {
    match HEADER_BYTES.checked_add(string_bytes) {
        Some(bytes) => bytes.checked_add(TERMINATOR_BYTES),
        None => None,
    }
}

/// Encode the native 64-bit output header; the caller appends UTF-16 data.
/// # C: O(1)
pub(crate) fn encode_header(string_bytes: usize, buffer: u64) -> Option<[u8; HEADER_BYTES]> {
    if string_bytes > u16::MAX as usize - TERMINATOR_BYTES { return None; }
    let mut out = [0u8; HEADER_BYTES];
    out[0..2].copy_from_slice(&(string_bytes as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&((string_bytes + TERMINATOR_BYTES) as u16).to_ne_bytes());
    out[8..16].copy_from_slice(&buffer.to_ne_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_requires_even_bounded_utf16_and_a_buffer() {
        assert_eq!(source_bytes(6, 8, 0x1000), Ok(6));
        assert_eq!(source_bytes(5, 8, 0x1000), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(source_bytes(6, 7, 0x1000), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(source_bytes(2, 4, 0), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn output_layout_includes_native_header_and_terminator() {
        assert_eq!(required_bytes(12), Some(30));
        let out = encode_header(12, 0x7fff_1234).unwrap();
        assert_eq!(u16::from_ne_bytes(out[0..2].try_into().unwrap()), 12);
        assert_eq!(u16::from_ne_bytes(out[2..4].try_into().unwrap()), 14);
        assert_eq!(u64::from_ne_bytes(out[8..16].try_into().unwrap()), 0x7fff_1234);
        assert!(out[4..8].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn positive_control_rejects_unterminated_source_capacity() {
        assert!(source_bytes(8, 8, 0x1000).is_err());
    }
}

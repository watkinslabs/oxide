//! Pure NT process-parameter decoding rules shared by the kernel adapter and
//! hosted tests. User-memory copying remains in the target-gated caller.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use alloc::{string::String, vec::Vec};

/// Decode a UTF-16 field after its user-memory bounds have been checked.
/// # C: O(N)
pub fn decode_utf16(units: &[u16]) -> Option<String> { String::from_utf16(units).ok() }

/// Parse the Windows environment convention: NUL-separated `NAME=VALUE`
/// records terminated by an additional NUL. # C: O(N)
pub fn parse_environment(units: &[u16]) -> Option<Vec<(String, String)>> {
    let end = units.windows(2).position(|pair| pair == [0, 0])?;
    let mut result = Vec::new();
    for item in units[..end].split(|unit| *unit == 0) {
        if item.is_empty() { continue; }
        let text = decode_utf16(item)?;
        let equal = text.find('=')?;
        if equal == 0 { return None; }
        result.push((text[..equal].into(), text[equal + 1..].into()));
    }
    Some(result)
}

/// Convert normalized process-parameter pointers back to offsets from the record.
/// # C: O(1)
pub fn denormalize_pointer_offsets(base: u64, pointers: [u64; 8]) -> Option<[u64; 8]> {
    let mut result = [0; 8];
    for (index, pointer) in pointers.into_iter().enumerate() {
        result[index] = if pointer == 0 { 0 } else { pointer.checked_sub(base)? };
    }
    Some(result)
}

#[cfg(test)]
#[path = "tests/nt_process_parameters.rs"]
mod tests;

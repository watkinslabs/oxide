//! Bounded Win32 process-environment views owned by the PEB/TEB builder.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WideCopyResult {
    Complete { copied: usize, terminated: bool },
    Truncated { copied: usize },
}

/// Apply the `GetModuleFileNameW` destination-buffer contract to a module
/// name whose terminator is not part of its descriptor length.
/// # C: O(source length)
pub fn bounded_module_name(source: &[u16], capacity: usize) -> WideCopyResult {
    let copied = source.len().min(capacity);
    if copied < source.len() { return WideCopyResult::Truncated { copied }; }
    WideCopyResult::Complete { copied, terminated: copied < capacity }
}

/// Locate the complete double-NUL-terminated process environment block.
/// # C: O(block length)
pub fn environment_block_length(block: &[u16]) -> Option<usize> {
    if block.len() < 2 { return None; }
    for index in 1..block.len() {
        if block[index - 1] == 0 && block[index] == 0 { return Some(index + 1); }
    }
    None
}

/// Find one environment value in the canonical UTF-16 block representation.
/// Empty values are valid and are returned as an empty slice.
/// # C: O(block length)
pub fn environment_value<'a>(block: &'a [u16], name: &[u16]) -> Option<&'a [u16]> {
    let length = environment_block_length(block)?;
    let mut start = 0;
    while start + 1 < length {
        let end = block[start..length].iter().position(|&unit| unit == 0).map(|offset| start + offset)?;
        if end == start { return None; }
        if let Some(value) = pe::ntdll::environment_entry_value(&block[start..end], name) { return Some(value); }
        start = end + 1;
    }
    None
}

/// Copy a block after validating its lifecycle terminator, preserving the
/// exact bytes supplied by the PEB owner.
/// # C: O(block length)
pub fn clone_environment_block(block: &[u16]) -> Option<Vec<u16>> {
    let length = environment_block_length(block)?;
    Some(block[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_copy_only_terminates_when_capacity_has_room() {
        assert_eq!(bounded_module_name(&[b'C' as u16, b':' as u16], 3),
            WideCopyResult::Complete { copied: 2, terminated: true });
        assert_eq!(bounded_module_name(&[b'C' as u16, b':' as u16], 2),
            WideCopyResult::Complete { copied: 2, terminated: false });
        assert_eq!(bounded_module_name(&[b'C' as u16, b':' as u16], 1),
            WideCopyResult::Truncated { copied: 1 });
        assert_eq!(bounded_module_name(&[b'C' as u16], 0), WideCopyResult::Truncated { copied: 0 });
    }

    #[test]
    fn malformed_environment_is_rejected_before_lookup() {
        assert_eq!(environment_block_length(&[]), None);
        assert_eq!(environment_block_length(&[0]), None);
        assert_eq!(environment_block_length(&[b'A' as u16, 0]), None);
        assert_eq!(clone_environment_block(&[b'A' as u16, 0]), None);
    }

    #[test]
    fn environment_lookup_preserves_empty_values_and_lifecycle_copy() {
        let block = [b'T' as u16, b'E' as u16, b'M' as u16, b'P' as u16, b'=' as u16, 0,
            b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16, b'=' as u16,
            b'C' as u16, 0, 0];
        assert_eq!(environment_value(&block, &[b'T' as u16, b'E' as u16, b'M' as u16, b'P' as u16]), Some(&[][..]));
        assert_eq!(environment_value(&block, &[b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16]), Some(&[b'C' as u16][..]));
        assert_eq!(clone_environment_block(&block), Some(block.to_vec()));
        assert_eq!(environment_value(&block[..5], &[b'T' as u16]), None);
    }
}

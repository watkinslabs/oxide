//! Canonical case-insensitive PE module-name matching.

/// Compare narrow catalog names after removing a path and an optional `.dll` suffix.
/// # C: O(name length)
pub fn matches_ascii(wanted: &[u8], current: &[u8]) -> bool {
    let wanted = trim_ascii_suffix(ascii_basename(wanted));
    let current = trim_ascii_suffix(ascii_basename(current));
    !wanted.is_empty() && wanted.len() == current.len()
        && wanted.iter().zip(current).all(|(left, right)| left.eq_ignore_ascii_case(right))
}

/// Compare UTF-16LE module names after removing a path and an optional `.dll` suffix.
/// # C: O(name length)
pub fn matches_utf16(wanted: &[u8], current: &[u8]) -> bool {
    let wanted = trim_wide_suffix(wide_basename(wanted));
    let current = trim_wide_suffix(wide_basename(current));
    !wanted.is_empty() && wanted.len() == current.len()
        && wanted.chunks_exact(2).zip(current.chunks_exact(2)).all(|(left, right)| {
            left[1] == right[1] && left[0].eq_ignore_ascii_case(&right[0])
        })
}

fn ascii_basename(value: &[u8]) -> &[u8] {
    let mut start = 0;
    for (index, byte) in value.iter().enumerate() { if *byte == b'\\' || *byte == b'/' { start = index + 1; } }
    &value[start..]
}

fn wide_basename(value: &[u8]) -> &[u8] {
    if value.len() & 1 != 0 { return &[]; }
    let mut start = 0;
    for index in (0..value.len()).step_by(2) {
        if (value[index] == b'\\' || value[index] == b'/') && value[index + 1] == 0 { start = index + 2; }
    }
    &value[start..]
}

fn trim_ascii_suffix(value: &[u8]) -> &[u8] {
    let suffix = b".dll";
    if value.len() >= suffix.len() && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
        &value[..value.len() - suffix.len()]
    } else { value }
}

fn trim_wide_suffix(value: &[u8]) -> &[u8] {
    let suffix = &[b'.', 0, b'd', 0, b'l', 0, b'l', 0][..];
    if value.len() >= suffix.len() && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
        &value[..value.len() - suffix.len()]
    } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    fn wide(value: &[u8]) -> Vec<u8> { value.iter().flat_map(|byte| [*byte, 0]).collect() }

    #[test]
    fn narrow_matching_has_one_path_and_suffix_rule() {
        assert!(matches_ascii(b"C:\\Windows\\user32.dll", b"USER32"));
        assert!(!matches_ascii(b"user32.dll.bak", b"user32.dll"));
    }
    #[test]
    fn wide_matching_rejects_odd_or_non_dll_names() {
        assert!(matches_utf16(&wide(b"user32"), &wide(b"USER32.dll")));
        assert!(!matches_utf16(b"user32", &wide(b"user32.dll")));
        assert!(!matches_utf16(&wide(b"user32.dll.bak"), &wide(b"user32.dll")));
    }
}

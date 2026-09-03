//! Windows loader module-name normalization shared by NT ABI consumers.

/// Compare a requested DLL name with a loaded base name.
///
/// Loader requests may be path-qualified and may omit the conventional
/// `.dll` suffix. Both forms identify the same loaded module; other suffixes
/// remain distinct.
pub fn matches_module_name(wanted: &[u8], current: &[u8]) -> bool {
    let wanted = without_dll(basename(wanted));
    let current = without_dll(basename(current));
    !wanted.is_empty() && wanted.len() == current.len()
        && wanted.chunks_exact(2).zip(current.chunks_exact(2)).all(|(left, right)| {
            left[1] == right[1] && left[0].to_ascii_lowercase() == right[0].to_ascii_lowercase()
        })
}

fn basename(value: &[u8]) -> &[u8] {
    if value.len() & 1 != 0 { return &[]; }
    let mut start = 0;
    for index in (0..value.len()).step_by(2) {
        if (value[index] == b'\\' || value[index] == b'/') && value[index + 1] == 0 { start = index + 2; }
    }
    &value[start..]
}

fn without_dll(value: &[u8]) -> &[u8] {
    if value.len() >= 8 && value[value.len() - 8..].eq_ignore_ascii_case(&[b'.', 0, b'd', 0, b'l', 0, b'l', 0]) {
        &value[..value.len() - 8]
    } else { value }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use super::matches_module_name;

    fn wide(value: &[u8]) -> Vec<u8> {
        value.iter().flat_map(|byte| [*byte, 0]).collect()
    }

    #[test]
    fn matches_case_insensitive_names_with_or_without_dll_suffix() {
        assert!(matches_module_name(&wide(b"USER32"), &wide(b"user32.dll")));
        assert!(matches_module_name(&wide(b"user32.dll"), &wide(b"USER32")));
    }

    #[test]
    fn matches_path_qualified_requests_by_loaded_base_name() {
        assert!(matches_module_name(&wide(b"C:\\\\Windows\\System32\\user32.dll"), &wide(b"user32.dll")));
        assert!(matches_module_name(&wide(b"C:/Windows/System32/user32"), &wide(b"user32.dll")));
    }

    #[test]
    fn rejects_other_extensions_and_malformed_utf16() {
        assert!(!matches_module_name(&wide(b"user32.dll.bak"), &wide(b"user32.dll")));
        assert!(!matches_module_name(b"user32.dll", &wide(b"user32.dll")));
        assert!(!matches_module_name(&wide(b"user32x"), &wide(b"user32.dll")));
    }
}

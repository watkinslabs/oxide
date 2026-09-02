//! Pure path rules for the NT object-directory adapter.

use alloc::string::String;

/// Fixed-layout offsets used by one DIRECTORY_BASIC_INFORMATION record.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRecordLayout {
    pub record_len: usize,
    pub name_offset: usize,
    pub type_offset: usize,
}

/// Plan the variable-length record without touching user memory. # C: O(1)
pub fn record_layout(name_bytes: usize, type_bytes: usize) -> Option<DirectoryRecordLayout> {
    if name_bytes > (u16::MAX - 2) as usize || type_bytes > (u16::MAX - 2) as usize
        || name_bytes & 1 != 0 || type_bytes & 1 != 0 { return None; }
    let end = 32usize.checked_add(name_bytes)?.checked_add(2)?
        .checked_add(type_bytes)?.checked_add(2)?;
    Some(DirectoryRecordLayout { record_len: end.checked_add(3)? & !3,
        name_offset: 32, type_offset: 32 + name_bytes + 2 })
}

/// Normalize an NT object path without consulting the namespace. # C: O(N)
pub fn normalize_path(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('\\') || path.contains('/') { return None; }
    if path == "\\" { return Some("\\".into()); }
    let mut result = String::from("\\");
    for component in path.split('\\').skip(1) {
        if component.is_empty() || component == "." || component == ".." { return None; }
        if result.len() > 1 { result.push('\\'); }
        result.push_str(component);
    }
    Some(result)
}

/// Join an OBJECT_ATTRIBUTES root directory with its relative name. # C: O(N)
pub fn join_path(root: Option<&str>, name: &str) -> Option<String> {
    if name.starts_with('\\') { return normalize_path(name); }
    if name.is_empty() || name.contains('/') { return None; }
    let root = normalize_path(root.unwrap_or("\\"))?;
    let mut result = root;
    for component in name.split('\\') {
        if component.is_empty() || component == "." || component == ".." { return None; }
        if result != "\\" { result.push('\\'); }
        result.push_str(component);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_and_root_relative_paths_are_normalized() {
        assert_eq!(normalize_path("\\KnownDlls"), Some("\\KnownDlls".into()));
        assert_eq!(join_path(Some("\\"), "KnownDlls").as_deref(), Some("\\KnownDlls"));
        assert_eq!(join_path(Some("\\BaseNamedObjects"), "Child").as_deref(), Some("\\BaseNamedObjects\\Child"));
    }

    #[test]
    fn malformed_object_paths_are_rejected() {
        for path in ["", "KnownDlls", "\\", "\\A\\..\\B", "\\A/B"] {
            if path == "\\" { assert!(normalize_path(path).is_some()); }
            else { assert!(normalize_path(path).is_none(), "path must be rejected: {path}"); }
        }
    }

    #[test]
    fn directory_record_layout_aligns_names_after_two_unicode_headers() {
        assert_eq!(record_layout(14, 18), Some(DirectoryRecordLayout {
            record_len: 68, name_offset: 32, type_offset: 48,
        }));
        assert!(record_layout(1, 2).is_none());
        assert!(record_layout(usize::MAX, 2).is_none());
    }
}

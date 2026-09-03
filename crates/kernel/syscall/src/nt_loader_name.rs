//! Windows loader module-name normalization shared by NT ABI consumers.

pub use pe::loader_name::matches_utf16 as matches_module_name;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use super::matches_module_name;
    fn wide(value: &[u8]) -> Vec<u8> { value.iter().flat_map(|byte| [*byte, 0]).collect() }

    #[test]
    fn matches_case_insensitive_names_with_or_without_dll_suffix() {
        assert!(matches_module_name(&wide(b"USER32"), &wide(b"user32.dll")));
        assert!(matches_module_name(&wide(b"user32.dll"), &wide(b"USER32")));
    }
    #[test]
    fn matches_path_qualified_requests_by_loaded_base_name() {
        assert!(matches_module_name(&wide(b"C:\\Windows\\System32\\user32.dll"), &wide(b"user32.dll")));
        assert!(matches_module_name(&wide(b"C:/Windows/System32/user32"), &wide(b"user32.dll")));
    }
    #[test]
    fn rejects_other_extensions_and_malformed_utf16() {
        assert!(!matches_module_name(&wide(b"user32.dll.bak"), &wide(b"user32.dll")));
        assert!(!matches_module_name(b"user32.dll", &wide(b"user32.dll")));
        assert!(!matches_module_name(&wide(b"user32x"), &wide(b"user32.dll")));
    }
}

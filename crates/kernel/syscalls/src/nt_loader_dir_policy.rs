//! Untargeted Windows DLL search-policy decisions.

#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;

pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

pub const DEFAULT_DIRECTORY_FLAGS: u32 = LOAD_LIBRARY_SEARCH_APPLICATION_DIR
    | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32
    | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
pub const SEARCH_DIRECTORY_FLAGS: u32 = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
    | DEFAULT_DIRECTORY_FLAGS;

/// Validate the flag mask accepted by `LdrSetDefaultDllDirectories`. # C: O(1)
pub const fn default_flags_valid(flags: u32) -> bool {
    flags != 0 && flags & !DEFAULT_DIRECTORY_FLAGS == 0
}

/// Expand the aggregate default-directory bit before constructing a path. # C: O(1)
pub const fn expand_default_flags(flags: u32) -> u32 {
    if flags & LOAD_LIBRARY_SEARCH_DEFAULT_DIRS != 0 {
        flags | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS
            | LOAD_LIBRARY_SEARCH_SYSTEM32
    } else {
        flags
    }
}

/// Validate the mutually exclusive `LdrGetDllPath` search modes. # C: O(1)
pub const fn request_flags_valid(flags: u32) -> bool {
    let valid = LOAD_WITH_ALTERED_SEARCH_PATH | SEARCH_DIRECTORY_FLAGS;
    flags & !valid == 0
        && !(flags & LOAD_WITH_ALTERED_SEARCH_PATH != 0
            && flags & SEARCH_DIRECTORY_FLAGS != 0)
}

/// Select explicit request flags, or the process defaults when no mode was supplied. # C: O(1)
pub const fn effective_flags(request: u32, defaults: u32) -> u32 {
    if request & LOAD_WITH_ALTERED_SEARCH_PATH != 0 {
        if defaults == 0 { LOAD_WITH_ALTERED_SEARCH_PATH }
        else { expand_default_flags(defaults | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) }
    } else if request & SEARCH_DIRECTORY_FLAGS != 0 {
        expand_default_flags(request)
    } else {
        expand_default_flags(defaults)
    }
}

/// Accept the path classes Wine permits for `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`. # C: O(N)
pub fn dll_load_directory_path_valid(path: &[u8]) -> bool {
    if path.len() >= 2 && path[0] == b'\\' && path[1] == 0 { return true; }
    if path.len() < 6 || path[1] != 0 || path[2] != b':' || path[3] != 0 { return false; }
    (path[4] == b'\\' || path[4] == b'/') && path[5] == 0
}

/// Join one canonical Windows directory and a module basename.
/// # C: O(directory length + name length)
#[cfg(target_arch = "x86_64")]
pub fn join_windows_path(directory: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = directory.to_vec();
    if !path.is_empty() && !matches!(path.last(), Some(b'\\' | b'/')) { path.push(b'\\'); }
    let mut base = name;
    for (index, byte) in name.iter().enumerate() {
        if *byte == b'\\' || *byte == b'/' { base = &name[index + 1..]; }
    }
    path.extend_from_slice(base);
    if base.len() < 4 || !base[base.len() - 4..].eq_ignore_ascii_case(b".dll") { path.extend_from_slice(b".dll"); }
    path
}

/// Convert an absolute Z-drive Windows path into the mounted Linux VFS path.
/// Other drive mappings remain explicit rather than silently selecting a host
/// directory that could disagree with the process DOS-device namespace.
/// # C: O(path length)
#[cfg(target_arch = "x86_64")]
pub fn windows_path_to_vfs(path: &[u8]) -> Option<Vec<u8>> {
    let mut path = path.to_vec();
    if path.starts_with(b"\\??\\") { path.drain(..4); }
    for byte in &mut path { if *byte == b'\\' { *byte = b'/'; } }
    if path.len() >= 2 && (path[0] == b'Z' || path[0] == b'z') && path[1] == b':' { path.drain(..2); }
    if path.first().copied() != Some(b'/') { return None; }
    Some(path)
}

/// Select the first readable candidate while preserving the caller's order.
/// # C: O(N_candidates)
#[cfg(target_arch = "x86_64")]
pub fn first_readable_candidate<F>(candidates: &[Vec<u8>], mut read: F) -> Option<(Vec<u8>, Vec<u8>)>
where F: FnMut(&[u8]) -> Option<Vec<u8>> {
    for candidate in candidates {
        if let Some(blob) = read(candidate) { return Some((candidate.clone(), blob)); }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use alloc::vec;

    #[test]
    fn default_directory_contract_accepts_only_nonzero_allowed_bits() {
        assert!(default_flags_valid(LOAD_LIBRARY_SEARCH_APPLICATION_DIR));
        assert!(default_flags_valid(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS));
        assert!(!default_flags_valid(0));
        assert!(!default_flags_valid(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR));
        assert!(!default_flags_valid(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | 0x8000));
    }

    #[test]
    fn aggregate_default_expands_to_application_user_and_system() {
        let flags = expand_default_flags(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        assert_eq!(flags & (LOAD_LIBRARY_SEARCH_APPLICATION_DIR
            | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32),
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS
                | LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    #[test]
    fn explicit_search_modes_override_process_defaults() {
        assert_eq!(effective_flags(LOAD_LIBRARY_SEARCH_SYSTEM32,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR), LOAD_LIBRARY_SEARCH_SYSTEM32);
        assert_eq!(effective_flags(0, LOAD_LIBRARY_SEARCH_USER_DIRS),
            LOAD_LIBRARY_SEARCH_USER_DIRS);
        assert!(!request_flags_valid(LOAD_WITH_ALTERED_SEARCH_PATH
            | LOAD_LIBRARY_SEARCH_SYSTEM32));
        assert!(request_flags_valid(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR));
    }

    #[test]
    fn dll_load_directory_is_not_lost_when_it_is_the_explicit_mode() {
        assert_eq!(effective_flags(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            LOAD_LIBRARY_SEARCH_SYSTEM32), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    }

    #[test]
    fn altered_mode_inherits_defaults_and_adds_module_directory() {
        assert_eq!(effective_flags(LOAD_WITH_ALTERED_SEARCH_PATH,
            LOAD_LIBRARY_SEARCH_SYSTEM32), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                | LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    #[test]
    fn dll_load_directory_rejects_drive_relative_names() {
        fn u16_bytes(value: &[u8]) -> alloc::vec::Vec<u8> {
            let mut result = alloc::vec::Vec::new();
            for byte in value { result.extend_from_slice(&[*byte, 0]); }
            result
        }
        assert!(dll_load_directory_path_valid(&u16_bytes(b"C:\\dir\\x.dll")));
        assert!(dll_load_directory_path_valid(&u16_bytes(b"\\\\host\\share\\x.dll")));
        assert!(!dll_load_directory_path_valid(&u16_bytes(b"C:x.dll")));
        assert!(!dll_load_directory_path_valid(&u16_bytes(b"x.dll")));
    }

    #[test]
    fn filesystem_probe_preserves_search_order_and_skips_missing_candidates() {
        let candidates = vec![b"Z:\\first\\foo.dll".to_vec(), b"Z:\\second\\foo.dll".to_vec()];
        let found = first_readable_candidate(&candidates, |candidate| {
            if candidate.starts_with(b"Z:\\second") { Some(b"MZ-valid".to_vec()) } else { None }
        }).unwrap();
        assert_eq!(found.0, candidates[1]);
        assert_eq!(found.1, b"MZ-valid");
    }

    #[test]
    fn filesystem_probe_prefers_the_first_readable_candidate() {
        let candidates = vec![b"Z:\\first\\foo.dll".to_vec(), b"Z:\\second\\foo.dll".to_vec()];
        let found = first_readable_candidate(&candidates, |_| Some(b"MZ-valid".to_vec())).unwrap();
        assert_eq!(found.0, candidates[0]);
    }

    #[test]
    fn filesystem_probe_maps_only_absolute_z_drive_paths_into_vfs() {
        assert_eq!(windows_path_to_vfs(b"Z:\\usr\\lib\\foo.dll"), Some(b"/usr/lib/foo.dll".to_vec()));
        assert_eq!(windows_path_to_vfs(b"C:\\Windows\\System32\\foo.dll"), None);
        assert_eq!(windows_path_to_vfs(b"foo.dll"), None);
    }
}

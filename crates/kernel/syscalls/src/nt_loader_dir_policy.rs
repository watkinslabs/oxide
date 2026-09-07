//! Untargeted Windows DLL search-policy decisions.

use alloc::vec::Vec;

pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

/// Canonical native system directory, in the reference spelling.
pub const SYSTEM_DIRECTORY: &[u8] = b"C:\\windows\\system32";
/// Legacy 16-bit system directory, second entry of the reference default path.
pub const SYSTEM_LEGACY_DIRECTORY: &[u8] = b"C:\\windows\\system";
/// Canonical native Windows directory, used when no other directory applies.
pub const WINDOWS_DIRECTORY: &[u8] = b"C:\\windows";

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

/// Reference default DLL load path, used whenever neither the request nor the
/// process defaults name a `LOAD_LIBRARY_SEARCH_*` set: the image directory,
/// the DLL-directory override or else the current directory, system32, the
/// legacy system directory, the Windows directory, then every `PATH` entry in
/// order. Inputs and outputs are UTF-16LE byte strings; empty inputs and
/// duplicates contribute nothing. # C: O(len(PATH))
pub fn legacy_search_order(image_dir: &[u8], dll_directory: Option<&[u8]>, current_dir: &[u8], path_env: &[u8]) -> Vec<Vec<u8>> {
    fn wide(value: &[u8]) -> Vec<u8> { value.iter().flat_map(|byte| [*byte, 0]).collect() }
    fn push(out: &mut Vec<Vec<u8>>, dir: &[u8]) {
        if dir.is_empty() || out.iter().any(|known| known == dir) { return; }
        out.push(dir.to_vec());
    }
    let mut out = Vec::new();
    push(&mut out, image_dir);
    match dll_directory { Some(dir) if !dir.is_empty() => push(&mut out, dir), _ => push(&mut out, current_dir) }
    push(&mut out, &wide(SYSTEM_DIRECTORY));
    push(&mut out, &wide(SYSTEM_LEGACY_DIRECTORY));
    push(&mut out, &wide(WINDOWS_DIRECTORY));
    for entry in path_env.chunks(2).collect::<Vec<_>>().split(|unit| unit == &[b';', 0]) {
        let bytes: Vec<u8> = entry.iter().flat_map(|unit| unit.iter().copied()).collect();
        push(&mut out, &bytes);
    }
    out
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

    /// The search order a delay-loaded `imm32.dll` reaches from a Notepad
    /// image staged in the system directory must name paths the boot image
    /// actually publishes, through the one DOS drive mapping the native file
    /// opens use.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn system_and_application_candidates_map_through_the_one_drive_owner() {
        let image = b"C:\\windows\\system32\\notepad.exe";
        let application = &image[..image.len() - b"\\notepad.exe".len()];
        let candidates = vec![join_windows_path(application, b"imm32.dll"),
            join_windows_path(SYSTEM_DIRECTORY, b"imm32.dll")];
        assert_eq!(candidates[0], b"C:\\windows\\system32\\imm32.dll".to_vec());
        assert_eq!(candidates[1], candidates[0]);
        assert_eq!(crate::nt_path::normalize_narrow_path(&candidates[1]).as_deref(),
            Some(&b"/windows/c/windows/system32/imm32.dll"[..]));
        assert_eq!(crate::nt_path::normalize_narrow_path(WINDOWS_DIRECTORY).as_deref(),
            Some(&b"/windows/c/windows"[..]));
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
    fn legacy_order_is_image_current_system32_system_windows_then_path() {
        fn wide(value: &[u8]) -> Vec<u8> { value.iter().flat_map(|byte| [*byte, 0]).collect() }
        let order = legacy_search_order(&wide(b"C:\\windows\\system32"), None, &wide(b"C:\\users\\me"),
            &wide(b"C:\\windows\\system32;D:\\tools;;C:\\windows"));
        let expect: Vec<Vec<u8>> = [b"C:\\windows\\system32".as_slice(), b"C:\\users\\me", b"C:\\windows\\system",
            b"C:\\windows", b"D:\\tools"].iter().map(|dir| wide(dir)).collect();
        assert_eq!(order, expect);
        let with_override = legacy_search_order(&wide(b"C:\\app"), Some(&wide(b"C:\\dlls")), &wide(b"C:\\cwd"), &[]);
        assert_eq!(with_override[1], wide(b"C:\\dlls"));
        assert!(!with_override.contains(&wide(b"C:\\cwd")));
        assert_eq!(legacy_search_order(&[], None, &[], &[]).len(), 3);
    }
}

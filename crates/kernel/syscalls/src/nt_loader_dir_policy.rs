//! Untargeted Windows DLL search-policy decisions.

pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

pub const DEFAULT_DIRECTORY_FLAGS: u32 = LOAD_LIBRARY_SEARCH_APPLICATION_DIR
    | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32
    | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;

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
    let valid = LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
        | DEFAULT_DIRECTORY_FLAGS;
    flags & !valid == 0
        && !(flags & LOAD_WITH_ALTERED_SEARCH_PATH != 0
            && flags & DEFAULT_DIRECTORY_FLAGS != 0)
}

/// Select explicit request flags, or the process defaults when no mode was supplied. # C: O(1)
pub const fn effective_flags(request: u32, defaults: u32) -> u32 {
    if request & (LOAD_WITH_ALTERED_SEARCH_PATH | DEFAULT_DIRECTORY_FLAGS) == 0 {
        defaults
    } else {
        request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

//! Flag policy for the x86-64 native process-create adapter.

// These are the process-create bits Wine passes to NtCreateUserProcess. The
// native path names the supported contract instead of silently dropping bits.
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x0000_0004;
pub const PROCESS_CREATE_FLAGS_SUSPENDED: u32 = 0x0000_0200;
pub const PROCESS_CREATE_FLAGS_SUPPORTED: u32 =
    PROCESS_CREATE_FLAGS_INHERIT_HANDLES | PROCESS_CREATE_FLAGS_SUSPENDED;

/// Select general handle-table inheritance from the NT create flags. # C: O(1)
pub const fn inherits_process_handles(flags: u32) -> bool {
    flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES != 0
}

/// Validate process-create flags implemented by the native x86-64 path. # C: O(1)
pub fn valid_process_create_flags(flags: u32) -> bool {
    flags & !PROCESS_CREATE_FLAGS_SUPPORTED == 0
}

/// Preserve initial suspension from either NT create flag. # C: O(1)
pub fn initial_thread_suspended(process_flags: u32, thread_flags: u32) -> bool {
    process_flags & PROCESS_CREATE_FLAGS_SUSPENDED != 0 || thread_flags & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_create_accepts_wine_inheritance_and_suspension_bits_only() {
        assert!(valid_process_create_flags(0));
        assert!(valid_process_create_flags(PROCESS_CREATE_FLAGS_INHERIT_HANDLES));
        assert!(valid_process_create_flags(PROCESS_CREATE_FLAGS_SUSPENDED));
        assert!(valid_process_create_flags(PROCESS_CREATE_FLAGS_SUPPORTED));
        assert!(!valid_process_create_flags(PROCESS_CREATE_FLAGS_SUPPORTED | 1));
    }

    #[test]
    fn process_create_suspension_is_preserved_from_both_layers() {
        assert!(!initial_thread_suspended(0, 0));
        assert!(initial_thread_suspended(PROCESS_CREATE_FLAGS_SUSPENDED, 0));
        assert!(initial_thread_suspended(0, 1));
    }

    #[test]
    fn process_create_inherits_handles_only_when_wine_requests_it() {
        assert!(!inherits_process_handles(0));
        assert!(inherits_process_handles(PROCESS_CREATE_FLAGS_INHERIT_HANDLES));
        assert!(inherits_process_handles(PROCESS_CREATE_FLAGS_SUPPORTED));
    }
}

//! Pure CLIENT_ID and process-handle access decisions for the NT adapter.

// These are the process-create bits Wine passes to NtCreateUserProcess. The
// native path names the supported contract instead of silently dropping bits.
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x0000_0004;
pub const PROCESS_CREATE_FLAGS_SUSPENDED: u32 = 0x0000_0200;
pub const PROCESS_CREATE_FLAGS_SUPPORTED: u32 =
    PROCESS_CREATE_FLAGS_INHERIT_HANDLES | PROCESS_CREATE_FLAGS_SUSPENDED;

/// Native thread-stack reservation floor and allocation granularity. Wine's
/// 64-bit NT path applies both before creating the thread's TEB.
pub const NT_THREAD_DEFAULT_STACK: u64 = 1 << 20;
pub const NT_THREAD_MIN_STACK: u64 = 1 << 20;
pub const NT_THREAD_MAX_STACK: u64 = 64 << 20;
pub const NT_THREAD_STACK_GRANULARITY: u64 = 64 << 10;

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

/// Normalize an NtCreateThreadEx stack reservation before mapping it. # C: O(1)
pub fn thread_stack_size(requested: u64) -> Option<u64> {
    let requested = if requested == 0 { NT_THREAD_DEFAULT_STACK } else { requested };
    let size = requested.max(NT_THREAD_MIN_STACK);
    let rounded = size.checked_add(NT_THREAD_STACK_GRANULARITY - 1)?
        & !(NT_THREAD_STACK_GRANULARITY - 1);
    (rounded <= NT_THREAD_MAX_STACK).then_some(rounded)
}

/// Validate the process-scoped CLIENT_ID shape used by NtOpenProcess. # C: O(1)
pub fn valid_process_client_id(process_id: u64, thread_id: u64) -> bool {
    process_id != 0 && process_id <= u32::MAX as u64 && thread_id == 0
}

/// Validate the two non-zero identifiers required by `NtOpenThread`. # C: O(1)
pub fn valid_thread_client_id(process_id: u64, thread_id: u64) -> bool {
    process_id != 0 && process_id <= u32::MAX as u64
        && thread_id != 0 && thread_id <= u32::MAX as u64
}

/// Match a thread's owning process against a native `CLIENT_ID`. # C: O(1)
pub fn thread_belongs_to_process(process_id: u64, task_process_id: u32) -> bool {
    process_id != 0 && process_id <= u32::MAX as u64 && process_id as u32 == task_process_id
}

/// Add the implicit wait right after validating a process access mask. # C: O(1)
pub fn process_granted_access(desired: u32, all_access: u32, synchronize: u32) -> Option<u32> {
    if desired & !all_access != 0 { None } else { Some(desired | synchronize) }
}

/// Preserve the full signed NT exit value when a process handle names another
/// process. The target's group-exit latch is the value later read by every
/// thread's terminal path. # C: O(1)
pub const fn termination_exit_status(raw: u32) -> i32 { raw as i32 }

/// Identify a process-handle termination that must target another process
/// group rather than dispatching the caller's own exit path. # C: O(1)
pub const fn terminates_external_process(current_tgid: u32, target_tgid: u32) -> bool {
    current_tgid != target_tgid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_client_id_requires_process_only_identity() {
        assert!(valid_process_client_id(41, 0));
        assert!(!valid_process_client_id(0, 0));
        assert!(!valid_process_client_id(41, 7));
        assert!(!valid_process_client_id(u64::MAX, 0));
    }

    #[test]
    fn process_access_adds_synchronize_without_accepting_unknown_bits() {
        assert_eq!(process_granted_access(0x400, 0x0fff, 0x1000), Some(0x1400));
        assert_eq!(process_granted_access(0x2000, 0x0fff, 0x1000), None);
    }

    #[test]
    fn thread_client_id_requires_both_native_ids() {
        assert!(valid_thread_client_id(41, 42));
        assert!(!valid_thread_client_id(0, 42));
        assert!(!valid_thread_client_id(41, 0));
        assert!(!valid_thread_client_id(u64::MAX, 42));
        assert!(!valid_thread_client_id(41, u64::MAX));
    }

    #[test]
    fn thread_client_id_must_name_its_owning_process() {
        assert!(thread_belongs_to_process(41, 41));
        assert!(!thread_belongs_to_process(42, 41));
        assert!(!thread_belongs_to_process(0, 0));
    }

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
    fn thread_stack_uses_native_floor_and_granularity() {
        assert_eq!(thread_stack_size(0), Some(NT_THREAD_DEFAULT_STACK));
        assert_eq!(thread_stack_size(0x1000), Some(NT_THREAD_MIN_STACK));
        assert_eq!(thread_stack_size(NT_THREAD_MIN_STACK + 1),
            Some(NT_THREAD_MIN_STACK + NT_THREAD_STACK_GRANULARITY));
    }

    #[test]
    fn thread_stack_rejects_values_that_round_past_native_limit() {
        assert_eq!(thread_stack_size(NT_THREAD_MAX_STACK), Some(NT_THREAD_MAX_STACK));
        assert_eq!(thread_stack_size(NT_THREAD_MAX_STACK + 1), None);
        assert_eq!(thread_stack_size(u64::MAX), None);
    }

    #[test]
    fn process_create_inherits_handles_only_when_wine_requests_it() {
        assert!(!inherits_process_handles(0));
        assert!(inherits_process_handles(PROCESS_CREATE_FLAGS_INHERIT_HANDLES));
        assert!(inherits_process_handles(PROCESS_CREATE_FLAGS_SUPPORTED));
    }

    #[test]
    fn external_termination_targets_the_named_group() {
        assert!(terminates_external_process(41, 42));
        assert!(!terminates_external_process(41, 41));
    }

    #[test]
    fn nt_termination_preserves_the_full_signed_exit_value() {
        assert_eq!(termination_exit_status(0x0000_1234), 0x1234);
        assert_eq!(termination_exit_status(0xffff_ffff), -1);
    }
}

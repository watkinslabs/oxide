//! Pure CLIENT_ID and process-handle access decisions for the NT adapter.

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
}

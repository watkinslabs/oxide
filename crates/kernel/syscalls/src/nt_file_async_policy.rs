//! Untargeted admission rules for NT file-I/O event completion.

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;

/// Validate the event word before an NT file operation reaches the VFS owner.
/// A zero event is the documented optional form; nonzero values must name an
/// event with modify-state access so completion can signal it.
pub(crate) const fn io_event_status(event: u64, exists: bool, is_event: bool, can_modify: bool) -> u64 {
    if event == 0 { return STATUS_SUCCESS; }
    if event > u32::MAX as u64 || !exists || !is_event { return STATUS_INVALID_HANDLE; }
    if !can_modify { return STATUS_ACCESS_DENIED; }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::io_event_status;

    const OK: u64 = 0;
    const INVALID_HANDLE: u64 = 0xc000_0008;
    const ACCESS_DENIED: u64 = 0xc000_0022;

    #[test]
    fn omitted_event_is_admitted() { assert_eq!(io_event_status(0, false, false, false), OK); }

    #[test]
    fn event_handle_must_fit_native_handle_and_exist() {
        assert_eq!(io_event_status(u32::MAX as u64 + 1, true, true, true), INVALID_HANDLE);
        assert_eq!(io_event_status(7, false, true, true), INVALID_HANDLE);
    }

    #[test]
    fn completion_event_must_be_an_event_object() {
        assert_eq!(io_event_status(7, true, false, true), INVALID_HANDLE);
    }

    #[test]
    fn completion_event_requires_modify_state_access() {
        assert_eq!(io_event_status(7, true, true, false), ACCESS_DENIED);
        assert_eq!(io_event_status(7, true, true, true), OK);
    }
}

//! Untargeted admission rules for NT file-I/O event completion.

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub(crate) const STATUS_PENDING: u64 = 0x0000_0103;
pub(crate) const STATUS_END_OF_FILE: u64 = 0xc000_0011;
const FILE_TYPE_REGULAR: u32 = 1;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0020;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0040;

/// Validate the event word before an NT file operation reaches the VFS owner.
/// A zero event is the documented optional form; nonzero values must name an
/// event with modify-state access so completion can signal it.
pub(crate) const fn io_event_status(event: u64, exists: bool, is_event: bool, can_modify: bool) -> u64 {
    if event == 0 { return STATUS_SUCCESS; }
    if event > u32::MAX as u64 || !exists || !is_event { return STATUS_INVALID_HANDLE; }
    if !can_modify { return STATUS_ACCESS_DENIED; }
    STATUS_SUCCESS
}

/// Return the syscall status for a regular-file transfer. Overlapped regular
/// files complete their VFS work before returning, but publish `Pending` to
/// the caller; the IOSB, event, and completion port carry the transfer result.
pub(crate) const fn regular_file_return_status(options: u32, fd_type: u32,
                                               status: u64, write: bool) -> u64 {
    let asynchronous = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == 0;
    if fd_type == FILE_TYPE_REGULAR && asynchronous
        && (status == STATUS_SUCCESS || (!write && status == STATUS_END_OF_FILE)) {
        STATUS_PENDING
    } else { status }
}

#[cfg(test)]
mod tests {
    use super::{io_event_status, regular_file_return_status, STATUS_END_OF_FILE, STATUS_PENDING};

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

    #[test]
    fn overlapped_regular_file_transfer_returns_pending_after_completion_publication() {
        assert_eq!(regular_file_return_status(0, 1, OK, true), STATUS_PENDING);
        assert_eq!(regular_file_return_status(0, 1, OK, false), STATUS_PENDING);
        assert_eq!(regular_file_return_status(0, 1, STATUS_END_OF_FILE, false), STATUS_PENDING);
    }

    #[test]
    fn synchronous_or_nonregular_transfer_returns_its_actual_status() {
        assert_eq!(regular_file_return_status(0x20, 1, OK, true), OK);
        assert_eq!(regular_file_return_status(0x40, 1, STATUS_END_OF_FILE, false), STATUS_END_OF_FILE);
        assert_eq!(regular_file_return_status(0, 2, OK, true), OK);
        assert_eq!(regular_file_return_status(0, 1, 0xc000_0005, true), 0xc000_0005);
    }
}

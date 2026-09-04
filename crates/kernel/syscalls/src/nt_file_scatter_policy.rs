//! Untargeted admission and completion policy for native NT scatter reads.

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
pub const STATUS_INVALID_USER_BUFFER: u64 = 0xc000_00e8;
pub const STATUS_END_OF_FILE: u64 = 0xc000_0011;
pub const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
pub const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub const FILE_TYPE_REGULAR: u32 = 1;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0020;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0040;

/// Validate the fixed-page contract before resolving a handle or touching a
/// segment. `length == 0` deliberately permits a null segment array. # C: O(1)
pub fn validate_shape(io: u64, segments: u64, length: usize, page_size: usize,
                      max_bytes: usize, fd_type: u32, options: u32) -> Result<usize, u64> {
    if io == 0 { return Err(STATUS_ACCESS_VIOLATION); }
    if page_size == 0 || length % page_size != 0 || length > max_bytes {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if fd_type != FILE_TYPE_REGULAR
        || options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0
        || options & FILE_NO_INTERMEDIATE_BUFFERING == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if length != 0 && segments == 0 { return Err(STATUS_INVALID_USER_BUFFER); }
    Ok(length / page_size)
}

/// Segment entries identify complete page-sized writable user buffers. # C: O(1)
pub const fn validate_segment(address: u64, page_size: usize) -> bool {
    address != 0 && page_size != 0 && address % page_size as u64 == 0
}

/// A zero-byte read at a nonempty request is EOF; prior progress remains a
/// successful short transfer and its count is retained by the I/O status. # C: O(1)
pub const fn completion_status(requested: usize, copied: usize) -> u64 {
    if copied == 0 && requested != 0 { STATUS_END_OF_FILE } else { STATUS_SUCCESS }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;
    const FILE_OPTIONS: u32 = FILE_NO_INTERMEDIATE_BUFFERING;

    fn valid(length: usize, segments: u64) -> Result<usize, u64> {
        validate_shape(0x1000, segments, length, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS)
    }

    #[test]
    fn io_status_is_checked_before_the_other_arguments() {
        assert_eq!(validate_shape(0, 0, 1, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS), Err(STATUS_ACCESS_VIOLATION));
    }

    #[test]
    fn length_is_a_whole_page_and_stays_bounded() {
        assert_eq!(valid(PAGE - 1, 0x2000), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(valid(16 * 1024 * 1024 + PAGE, 0x2000), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(valid(PAGE * 2, 0x2000), Ok(2));
    }

    #[test]
    fn direct_regular_file_is_required() {
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS | FILE_SYNCHRONOUS_IO_NONALERT),
            Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            2, FILE_OPTIONS), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn nonzero_length_requires_the_segment_array() {
        assert_eq!(valid(PAGE, 0), Err(STATUS_INVALID_USER_BUFFER));
        assert_eq!(valid(0, 0), Ok(0));
    }

    #[test]
    fn each_segment_must_be_page_aligned_and_nonnull() {
        assert!(validate_segment(0x4000, PAGE));
        assert!(!validate_segment(0x4001, PAGE));
        assert!(!validate_segment(0, PAGE));
    }

    #[test]
    fn empty_transfer_is_eof_but_completed_transfer_is_success() {
        assert_eq!(completion_status(PAGE, 0), STATUS_END_OF_FILE);
        assert_eq!(completion_status(PAGE * 2, PAGE), STATUS_SUCCESS);
        assert_eq!(completion_status(0, 0), STATUS_SUCCESS);
    }
}

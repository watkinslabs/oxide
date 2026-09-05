//! Untargeted admission and completion policy for native NT gather writes.

use syscall::nt::NtService;

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
pub const STATUS_INVALID_USER_BUFFER: u64 = 0xc000_00e8;
pub const STATUS_DISK_FULL: u64 = 0xc000_007f;
pub const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
pub const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub const FILE_TYPE_REGULAR: u32 = 1;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0020;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0040;

/// Identify the native file service owned by this adapter. Keeping the
/// ownership predicate beside the policy lets hosted tests verify the target-
/// gated dispatcher contract without fabricating a kernel task or user memory.
pub const fn owns(service: NtService) -> bool {
    matches!(service, NtService::NtWriteFileGather)
}

/// Validate the native ordering and fixed-page contract before handle access.
/// A non-page-sized request wins over the I/O-status pointer, matching NT. # C: O(1)
pub fn validate_shape(io: u64, segments: u64, length: usize, page_size: usize,
                      max_bytes: usize, fd_type: u32, options: u32) -> Result<usize, u64> {
    if page_size == 0 || length % page_size != 0 || length > max_bytes {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if io == 0 { return Err(STATUS_ACCESS_VIOLATION); }
    if fd_type != FILE_TYPE_REGULAR
        || options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0
        || options & FILE_NO_INTERMEDIATE_BUFFERING == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if length != 0 && segments == 0 { return Err(STATUS_INVALID_USER_BUFFER); }
    Ok(length / page_size)
}

/// Segment entries identify complete page-sized readable user buffers. # C: O(1)
pub const fn validate_segment(address: u64, page_size: usize) -> bool {
    address != 0 && page_size != 0 && address % page_size as u64 == 0
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
    fn length_precedes_iosb_pointer() {
        assert_eq!(validate_shape(0, 1, PAGE - 1, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_shape(0, 1, PAGE, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS), Err(STATUS_ACCESS_VIOLATION));
    }

    #[test]
    fn request_is_page_sized_and_bounded() {
        assert_eq!(valid(PAGE * 2, 0x2000), Ok(2));
        assert_eq!(valid(PAGE + 1, 0x2000), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(valid(16 * 1024 * 1024 + PAGE, 0x2000), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn direct_regular_non_synchronous_file_is_required() {
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            FILE_TYPE_REGULAR, FILE_OPTIONS | FILE_SYNCHRONOUS_IO_ALERT),
            Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_shape(1, 1, PAGE, PAGE, 16 * 1024 * 1024,
            2, FILE_OPTIONS), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn nonzero_request_requires_segment_array_and_aligned_pages() {
        assert_eq!(valid(PAGE, 0), Err(STATUS_INVALID_USER_BUFFER));
        assert!(validate_segment(0x4000, PAGE));
        assert!(!validate_segment(0x4001, PAGE));
        assert!(!validate_segment(0, PAGE));
    }

    #[test]
    fn empty_request_does_not_require_segment_array() {
        assert_eq!(valid(0, 0), Ok(0));
    }

    #[test]
    fn ownership_is_exclusive_to_native_gather_write() {
        assert!(owns(NtService::NtWriteFileGather));
        assert!(!owns(NtService::WriteFile));
        assert!(!owns(NtService::NtWriteVirtualMemory));
    }

    #[test]
    fn file_dispatch_reaches_gather_before_service_fallbacks() {
        let file = include_str!("nt_file.rs");
        let gather = file.find("nt_file_gather::dispatch").expect("gather owner");
        let fallback = file.find("match call.service").expect("file fallback");
        assert!(gather < fallback);

        let dispatch = include_str!("nt_dispatch.rs");
        assert!(dispatch.contains("nt_file::dispatch_native(call)"));
        assert!(!dispatch.contains("NtWriteFileGather"));
    }
}

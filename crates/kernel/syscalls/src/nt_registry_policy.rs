//! Target-independent validation for the first native registry notification
//! contract.  Keeping this policy separate makes its boundary testable on the
//! host while the delivery owner remains target-specific.

pub const REG_NOTIFY_CHANGE_LAST_SET: u64 = 0x0000_0004;
pub const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;

/// Admit the 64-bit NT handle argument without truncation. Native key handles
/// are 32-bit table values, and an unrepresentable value is an invalid handle,
/// not a different key selected by low bits.
pub const fn flush_handle(raw: u64) -> Result<u32, u64> {
    if raw > u32::MAX as u64 { Err(STATUS_INVALID_HANDLE) } else { Ok(raw as u32) }
}

/// Whether the ABI shape can be owned by the current asynchronous NT bridge.
/// APC delivery and output records remain separate contracts; accepting them
/// here without an owner would turn a pending request into a false success.
///
/// The filter and the buffer length are `ULONG`s the caller stored into frame
/// words, so only their low half is the value; the notification mode is a
/// one-byte `BOOLEAN`. Judging the whole word refused every real request.
/// A subtree request is answered either way and is not judged here.
pub const fn supported_request(
    apc: u64,
    apc_context: u64,
    io_status: u64,
    buffer: u64,
    length: u32,
    asynchronous: bool,
    filter: u32,
) -> bool {
    apc == 0
        && apc_context == 0
        && io_status != 0
        && io_status.checked_add(8).is_some()
        && buffer == 0
        && length == 0
        && asynchronous
        && filter == REG_NOTIFY_CHANGE_LAST_SET as u32
}

#[cfg(test)]
mod tests {
    use super::{flush_handle, supported_request, STATUS_INVALID_HANDLE, REG_NOTIFY_CHANGE_LAST_SET};

    #[test]
    fn flush_rejects_unrepresentable_64_bit_handle_without_truncation() {
        assert_eq!(flush_handle(u32::MAX as u64 + 1), Err(STATUS_INVALID_HANDLE));
        assert_eq!(flush_handle(u64::MAX), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn flush_preserves_native_handle_width() {
        assert_eq!(flush_handle(0), Ok(0));
        assert_eq!(flush_handle(u32::MAX as u64), Ok(u32::MAX));
    }

    const LAST_SET: u32 = REG_NOTIFY_CHANGE_LAST_SET as u32;

    fn valid() -> bool {
        supported_request(0, 0, 0x1000, 0, 0, true, LAST_SET)
    }

    #[test]
    fn accepts_async_last_set_without_output_buffer() {
        assert!(valid());
    }

    #[test]
    fn rejects_apc_delivery() {
        assert!(!supported_request(1, 0, 0x1000, 0, 0, true, LAST_SET));
    }

    #[test]
    fn rejects_invalid_filters() {
        assert!(!supported_request(0, 0, 0x1000, 0, 0, true, LAST_SET | 0x0000_0001));
        assert!(!supported_request(0, 0, 0x1000, 0, 0, true, 2));
    }

    #[test]
    fn rejects_io_status_block_pointer_wraparound() {
        assert!(!supported_request(0, 0, u64::MAX - 7, 0, 0, true, LAST_SET));
    }

    /// The caller's filter and length reach the kernel in frame words whose
    /// upper half is not part of the value, and the mode in one byte. Judging
    /// the whole word refused every request a caller actually makes.
    #[test]
    fn admits_the_request_a_caller_stores_into_stale_frame_words() {
        let filter = crate::nt_obj_sig::ulong(0x7fff_dead_0000_0004);
        let length = crate::nt_obj_sig::ulong(0x1234_5678_0000_0000);
        let asynchronous = crate::nt_obj_sig::boolean(0xdead_beef_0000_0001);
        assert!(supported_request(0, 0, 0x1000, 0, length, asynchronous, filter));
    }

    #[test]
    fn registry_has_one_dispatch_owner_before_legacy_fallbacks() {
        let source = include_str!("nt_dispatch.rs");
        let owner = "crate::nt_registry::dispatch(call)";
        assert_eq!(source.matches(owner).count(), 1);
        let owner_at = source.find(owner).expect("registry owner");
        let file_at = source.find("crate::nt_file::dispatch_native(call)").expect("file owner");
        assert!(owner_at < file_at);
    }
}

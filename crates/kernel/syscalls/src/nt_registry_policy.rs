//! Target-independent validation for the first native registry notification
//! contract.  Keeping this policy separate makes its boundary testable on the
//! host while the delivery owner remains target-specific.

pub const REG_NOTIFY_CHANGE_NAME: u64 = 0x0000_0001;
pub const REG_NOTIFY_CHANGE_LAST_SET: u64 = 0x0000_0004;

/// Whether the ABI shape can be owned by the current synchronous NT bridge.
/// APC delivery, subtree traversal, and output records remain separate
/// contracts; accepting them here without an owner would turn a pending
/// request into a false success.
pub const fn supported_request(
    apc: u64,
    apc_context: u64,
    io_status: u64,
    buffer: u64,
    length: u64,
    asynchronous: u64,
    subtree: u64,
    filter: u64,
) -> bool {
    apc == 0
        && apc_context == 0
        && io_status != 0
        && io_status.checked_add(8).is_some()
        && buffer == 0
        && length == 0
        && asynchronous != 0
        && subtree <= 1
        && filter != 0
        && filter & !(REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET) == 0
}

#[cfg(test)]
mod tests {
    use super::{supported_request, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME};

    fn valid() -> bool {
        supported_request(0, 0, 0x1000, 0, 0, 1, 0, REG_NOTIFY_CHANGE_LAST_SET)
    }

    #[test]
    fn accepts_async_last_set_without_output_buffer() {
        assert!(valid());
    }

    #[test]
    fn rejects_apc_delivery() {
        assert!(!supported_request(1, 0, 0x1000, 0, 0, 1, 0, REG_NOTIFY_CHANGE_LAST_SET));
    }

    #[test]
    fn accepts_subtree_and_rejects_invalid_filters() {
        assert!(supported_request(0, 0, 0x1000, 0, 0, 1, 1, REG_NOTIFY_CHANGE_LAST_SET));
        assert!(supported_request(0, 0, 0x1000, 0, 0, 1, 1, REG_NOTIFY_CHANGE_NAME));
        assert!(!supported_request(0, 0, 0x1000, 0, 0, 1, 2, REG_NOTIFY_CHANGE_LAST_SET));
        assert!(!supported_request(0, 0, 0x1000, 0, 0, 1, 0, 2));
    }

    #[test]
    fn accepts_name_notifications_owned_by_key_mutations() {
        assert!(supported_request(0, 0, 0x1000, 0, 0, 1, 0, REG_NOTIFY_CHANGE_NAME));
    }

    #[test]
    fn accepts_combined_name_and_last_set_notifications() {
        assert!(supported_request(
            0, 0, 0x1000, 0, 0, 1, 0,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        ));
    }

    #[test]
    fn rejects_io_status_block_pointer_wraparound() {
        assert!(!supported_request(0, 0, u64::MAX - 7, 0, 0, 1, 0, REG_NOTIFY_CHANGE_NAME));
    }
}

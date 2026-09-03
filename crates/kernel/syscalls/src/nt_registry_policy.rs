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
        && buffer == 0
        && length == 0
        && asynchronous != 0
        && subtree <= 1
        && matches!(filter, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET)
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
    fn rejects_subtree_and_unowned_filters() {
        assert!(supported_request(0, 0, 0x1000, 0, 0, 1, 1, REG_NOTIFY_CHANGE_LAST_SET));
        assert!(!supported_request(0, 0, 0x1000, 0, 0, 1, 2, REG_NOTIFY_CHANGE_LAST_SET));
        assert!(!supported_request(0, 0, 0x1000, 0, 0, 1, 0, 1));
    }

    #[test]
    fn accepts_name_notifications_owned_by_key_mutations() {
        assert!(supported_request(0, 0, 0x1000, 0, 0, 1, 0, REG_NOTIFY_CHANGE_NAME));
    }
}

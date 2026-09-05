pub const RELAY_TARGET_NOT_FOUND: u64 = 0xc000_007a;

/// Select the immutable implementation target behind a patched Wine relay.
/// The EAT address is intentionally excluded: after relay installation it is
/// the relay entry itself and using it as a fallback recurses into the thunk.
pub fn select_original_target(snapshot: Option<u64>, private: Option<u64>) -> Option<u64> {
    snapshot.or(private)
}

/// Convert an absent relay implementation into the native NT failure returned
/// to the caller; zero must never be used as an indirect return target.
pub fn select_original_target_or_status(snapshot: Option<u64>, private: Option<u64>) -> u64 {
    match snapshot.or(private) {
        Some(target) => target,
        None => RELAY_TARGET_NOT_FOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::{select_original_target, select_original_target_or_status, RELAY_TARGET_NOT_FOUND};

    #[test]
    fn prefers_the_address_space_snapshot() {
        assert_eq!(select_original_target(Some(0x1000), Some(0x2000)), Some(0x1000));
    }

    #[test]
    fn uses_wine_private_metadata_when_snapshot_is_absent() {
        assert_eq!(select_original_target(None, Some(0x2000)), Some(0x2000));
    }

    #[test]
    fn rejects_a_missing_target_instead_of_returning_the_patched_eat() {
        assert_eq!(select_original_target(None, None), None);
    }

    #[test]
    fn missing_target_is_a_native_failure_not_a_null_return_target() {
        assert_eq!(select_original_target_or_status(None, None), RELAY_TARGET_NOT_FOUND);
        assert_ne!(select_original_target_or_status(None, None), 0);
    }
}

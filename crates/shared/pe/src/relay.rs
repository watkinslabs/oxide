/// Select the immutable implementation target behind a patched Wine relay.
/// The EAT address is intentionally excluded: after relay installation it is
/// the relay entry itself and using it as a fallback recurses into the thunk.
pub fn select_original_target(snapshot: Option<u64>, private: Option<u64>) -> Option<u64> {
    snapshot.or(private)
}

#[cfg(test)]
mod tests {
    use super::select_original_target;

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
}

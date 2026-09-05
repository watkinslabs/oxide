//! Untargeted close admission shared by native NT close owners.

/// Permit handle-owned close cleanup only for a live, unprotected handle.
/// # C: O(1)
pub const fn admits_cleanup(live: bool, protected: bool) -> bool {
    live && !protected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_requires_live_unprotected_handle() {
        assert!(admits_cleanup(true, false));
        assert!(!admits_cleanup(true, true));
        assert!(!admits_cleanup(false, false));
        assert!(!admits_cleanup(false, true));
    }
}

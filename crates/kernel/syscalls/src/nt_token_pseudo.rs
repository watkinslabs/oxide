//! Token handles a caller names without opening one.
//!
//! Three handle values name the caller's own token rather than a table entry:
//! the process token, the thread's impersonation token, and the effective
//! token, which is the thread's while one is impersonated and the process's
//! otherwise. A caller reads its own user through the effective one without
//! ever opening a token, so refusing these values refuses that read.

/// The token the process runs under.
pub(crate) const CURRENT_PROCESS_TOKEN: u64 = !3u64;
/// The token the thread impersonates, if it impersonates one.
pub(crate) const CURRENT_THREAD_TOKEN: u64 = !4u64;
/// Whichever of the two is in force.
pub(crate) const CURRENT_THREAD_EFFECTIVE_TOKEN: u64 = !5u64;

/// Which of the caller's own tokens a handle value names, if any.
/// # C: O(1)
pub(crate) const fn names_own_token(raw: u64) -> bool {
    matches!(raw, CURRENT_PROCESS_TOKEN | CURRENT_THREAD_TOKEN | CURRENT_THREAD_EFFECTIVE_TOKEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three values, written the way a caller forms them.
    #[test]
    fn the_three_own_token_handles_are_named_rather_than_opened() {
        assert_eq!(CURRENT_PROCESS_TOKEN, 0xffff_ffff_ffff_fffc);
        assert_eq!(CURRENT_THREAD_TOKEN, 0xffff_ffff_ffff_fffb);
        assert_eq!(CURRENT_THREAD_EFFECTIVE_TOKEN, 0xffff_ffff_ffff_fffa);
        for raw in [CURRENT_PROCESS_TOKEN, CURRENT_THREAD_TOKEN, CURRENT_THREAD_EFFECTIVE_TOKEN] {
            assert!(names_own_token(raw));
        }
    }

    /// A table handle, and the two neighbouring reserved values that name
    /// something else, are not tokens of the caller's own.
    #[test]
    fn a_table_handle_and_its_neighbours_are_not_the_callers_own_token() {
        for raw in [0, 4, 0x10004, u64::MAX, u64::MAX - 1, !6u64] {
            assert!(!names_own_token(raw));
        }
    }
}

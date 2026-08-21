//! Whole-filesystem sync durability policy.

/// Whether a `sync_fs` pass owes the backing device a durability barrier.
/// The waiting pass alone orders completed writes; `nobarrier` suppresses it.
/// # C: O(1)
pub(super) fn sync_fs_needs_barrier(wait: bool, barrier: bool) -> bool {
    wait && barrier
}

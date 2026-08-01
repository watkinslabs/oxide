// SysV shm destroy predicate, free of registry/task/namespace state so
// `cargo test -p ipc` proves it without a kernel target (`docs/53`).
//
// A segment dies when nobody is attached AND either `shmctl(IPC_RMID)` already
// marked it `SHM_DEST`, or the segment's IPC namespace has
// `kernel.shm_rmid_forced` set — the second arm is what reclaims a segment
// whose creator exited while still attached to it.

use super::SHM_DEST;

/// `shm_may_destroy`: no attachments left, and the segment is either marked
/// for destruction or force-reclaimed by its namespace.
/// # C: O(1)
pub fn shm_may_destroy(nattch: i64, rmid_forced: bool, mode: u32) -> bool {
    nattch <= 0 && (rmid_forced || (mode & SHM_DEST) != 0)
}

/// Whether an exiting creator's segment is destroyed now (`exit_shm` step 2):
/// without `shm_rmid_forced` the segment is only unlinked from the creator, so
/// a later `sysctl -w kernel.shm_rmid_forced=1` can still sweep it.
/// # C: O(1)
pub fn exit_shm_destroys(nattch: i64, rmid_forced: bool, mode: u32) -> bool {
    rmid_forced && shm_may_destroy(nattch, rmid_forced, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: u32 = 0;

    #[test]
    fn attached_segment_never_dies() {
        for forced in [false, true] {
            for mode in [NONE, SHM_DEST] {
                assert!(!shm_may_destroy(1, forced, mode));
                assert!(!shm_may_destroy(7, forced, mode));
            }
        }
    }

    #[test]
    fn unattached_dies_on_shm_dest_or_forced_only() {
        assert!(!shm_may_destroy(0, false, NONE), "plain idle segment survives");
        assert!(shm_may_destroy(0, false, SHM_DEST), "IPC_RMID + last detach destroys");
        assert!(shm_may_destroy(0, true, NONE), "shm_rmid_forced reclaims an idle segment");
        assert!(shm_may_destroy(0, true, SHM_DEST));
    }

    #[test]
    fn negative_attach_count_is_treated_as_idle() {
        // `release_detached` reads the post-decrement count; an underflow from a
        // double close must not resurrect a doomed segment.
        assert!(shm_may_destroy(-1, false, SHM_DEST));
    }

    #[test]
    fn exit_only_destroys_under_forced_rmid() {
        assert!(!exit_shm_destroys(0, false, SHM_DEST), "creator exit alone does not unlink an RMIDed segment");
        assert!(!exit_shm_destroys(0, false, NONE));
        assert!(exit_shm_destroys(0, true, NONE), "forced rmid reclaims at creator exit");
        assert!(!exit_shm_destroys(2, true, NONE), "still attached: only orphaned, not destroyed");
    }
}

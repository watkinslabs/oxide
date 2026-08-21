//! One owner for every system-wide power transition (`32a§2`, `32b§3.1`).
//!
//! Suspend, hibernation, cold-boot restore, and preserve-context kexec all
//! mutate the same task/device/core state.  They therefore contend on this
//! single claim instead of keeping subsystem-local busy flags.

use core::sync::atomic::{AtomicBool, Ordering};

static IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// An exclusive system-transition claim.
///
/// Dropping the token is the only production release path, which makes every
/// early return unwind the admission state automatically. # C: O(1)
pub struct Claim { _private: () }

impl Drop for Claim {
    fn drop(&mut self) { release(); }
}

/// Try to begin a system transition. A contender is refused instead of queued.
/// # C: O(1)
pub fn try_claim() -> Option<Claim> {
    IN_PROGRESS.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| Claim { _private: () })
}

/// Whether any system transition owns the machine. # C: O(1)
pub fn in_progress() -> bool { IN_PROGRESS.load(Ordering::Acquire) }

/// Compatibility entry for existing suspend tests while callers move to the
/// RAII token. The ownership bit remains the one above. # C: O(1)
pub(crate) fn try_claim_legacy() -> bool {
    IN_PROGRESS.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Compatibility release paired with [`try_claim_legacy`]. # C: O(1)
pub(crate) fn release() { IN_PROGRESS.store(false, Ordering::Release); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_and_hibernate_contend_on_one_claim() {
        let _guard = crate::suspend::test_lock();
        let suspend = try_claim().expect("first transition");
        assert!(in_progress());
        assert!(try_claim().is_none(), "a second transition must not get a shadow claim");
        drop(suspend);
        assert!(!in_progress());
        let hibernate = try_claim().expect("drop releases the same owner");
        drop(hibernate);
    }
}

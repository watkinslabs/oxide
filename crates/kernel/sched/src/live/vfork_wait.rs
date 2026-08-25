//! CLONE_VFORK completion wait.
//!
//! Linux stores a `struct completion *` in the child task's
//! `task_struct::vfork_done`. Oxide keeps the equivalent completion object on
//! the child, so the completion state and its wait queue have one owner.

use crate::Task;
pub use crate::vfork_completion::VforkCompletion;

/// Wait through the child-owned Linux completion object. # C: O(N_wakeups)
pub unsafe fn wait_for_done(child: &Task) -> bool {
    // SAFETY: the caller holds the child Arc for the whole wait, and the
    // completion is embedded in that child exactly like Linux's owner.
    unsafe { child.vfork_completion.wait() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_stable_when_child_finishes_before_parent_waits() {
        let completion = VforkCompletion::new();
        completion.arm();
        assert!(!completion.is_complete());
        assert!(completion.complete());
        assert!(completion.is_complete());
        assert!(!completion.complete(), "completion is one-shot");
    }
}

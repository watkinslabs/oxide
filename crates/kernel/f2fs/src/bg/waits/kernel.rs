//! Wake lists for one mount's background threads.
//!
//! Three, not one, because the three wakes mean different things. The cleaner
//! and the discard thread each park on their own, so a discard round does not
//! wake a cleaner that has nothing to do. The third is the other direction: a
//! caller blocked in the balance path parks on it and the cleaner releases it
//! when the pass it was waiting for is done.

use sched::live::WaitList;

/// The three wake points of one mount's background threads.
pub struct Waits {
    pub gc: WaitList,
    pub discard: WaitList,
    /// The merge thread, and the callers waiting on the checkpoint it is about
    /// to write. Both directions on ONE list: the thread parks on it for work
    /// and the callers park on it for the result, and a wake of either kind
    /// wakes both — which costs a condition re-test and cannot lose a wake.
    pub ckpt: WaitList,
    /// Callers blocked in the balance path, waiting for the cleaner's pass.
    pub foreground: WaitList,
}

impl Default for Waits {
    fn default() -> Self { Self::new() }
}

impl Waits {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { gc: WaitList::new(), discard: WaitList::new(), ckpt: WaitList::new(),
               foreground: WaitList::new() }
    }

    /// # C: O(1)
    pub fn wake_gc(&self) { self.gc.wake_all(); }

    /// # C: O(1)
    pub fn wake_discard(&self) { self.discard.wake_all(); }

    /// Wake the merge thread AND everybody waiting on its result. # C: O(waiters)
    pub fn wake_ckpt(&self) { self.ckpt.wake_all(); }

    /// Release every caller blocked on the pass that just finished.
    ///
    /// All of them, not one: they were all waiting for free space, and the
    /// pass either produced some for all of them or produced none.
    /// # C: O(waiters)
    pub fn wake_foreground(&self) { self.foreground.wake_all(); }

    /// Whether a caller is blocked waiting for a cleaning pass. # C: O(1)
    pub fn foreground_waiting(&self) -> bool { self.foreground.has_waiters() }
}

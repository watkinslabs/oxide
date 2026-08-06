//! Bottom-half-safe serialization for mutable FIB state.

use sync::{Socket as FibLockClass, Spinlock};

/// FIB state is read from transmit/receive datapaths and changed from process
/// control paths. Keep bottom-half exclusion in the type so no caller can take
/// the underlying lock without `spin_lock_bh` semantics.
pub(crate) struct FibLock<T>(Spinlock<T, FibLockClass>);

impl<T> FibLock<T> {
    /// Build one bottom-half-safe FIB lock. # C: O(1)
    pub(crate) const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    /// Exclude networking bottom halves while FIB state is held. # C: O(contention)
    pub(crate) fn lock(&self) -> sync::LockBhGuard<'_, T, FibLockClass, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_lock_disables_bottom_halves_for_whole_guard_lifetime() {
        sched::preempt::_test_reset();
        let lock = FibLock::new(7u32);
        {
            let guard = lock.lock();
            assert_eq!(*guard, 7);
            assert_eq!(sched::preempt::softirq_count(), sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }
}

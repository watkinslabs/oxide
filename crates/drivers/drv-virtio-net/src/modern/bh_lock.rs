//! Bottom-half-safe serialization for virtio-net state shared with NET_RX.

use sync::{Spinlock, TaskList as DriverLockClass};

/// Keep bottom-half exclusion in the registry type: process paths and NET_RX
/// both touch these tables, so every acquisition needs `spin_lock_bh` semantics.
pub(super) struct DriverBhLock<T>(Spinlock<T, DriverLockClass>);

impl<T> DriverBhLock<T> {
    /// Build one bottom-half-safe driver lock. # C: O(1)
    pub(super) const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    /// Exclude networking bottom halves while driver state is held. # C: O(contention)
    pub(super) fn lock(
        &self,
    ) -> sync::LockBhGuard<'_, T, DriverLockClass, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_lock_disables_bottom_halves_for_whole_guard_lifetime() {
        sched::preempt::_test_reset();
        let lock = DriverBhLock::new(7u32);
        {
            let guard = lock.lock();
            assert_eq!(*guard, 7);
            assert_eq!(sched::preempt::softirq_count(), sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }
}

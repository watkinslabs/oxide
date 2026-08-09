//! Bottom-half-safe serialization for state shared with the NET_RX softirq.

use sync::{LockClass, Socket as FibLockClass, Spinlock};

/// State read from transmit/receive datapaths and changed from process
/// control paths. Keep bottom-half exclusion in the type so no caller can take
/// the underlying lock without `spin_lock_bh` semantics. The lock class stays
/// a parameter so a converted lock keeps its lockdep rank; FIB state, the
/// original user, keeps its `Socket` default.
pub(crate) struct FibLock<T, C: LockClass = FibLockClass>(Spinlock<T, C>);

impl<T, C: LockClass> FibLock<T, C> {
    /// Build one bottom-half-safe lock. # C: O(1)
    pub(crate) const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    /// Exclude networking bottom halves while the state is held. # C: O(contention)
    pub(crate) fn lock(&self) -> sync::LockBhGuard<'_, T, C, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_lock_disables_bottom_halves_for_whole_guard_lifetime() {
        sched::preempt::_test_reset();
        let lock: FibLock<u32> = FibLock::new(7u32);
        {
            let guard = lock.lock();
            assert_eq!(*guard, 7);
            assert_eq!(sched::preempt::softirq_count(), sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }
}

use sync::{Guard, LockClass, Spinlock};

struct RtnlLockClass;

impl LockClass for RtnlLockClass { fn rank() -> u16 { 125 } }

pub(crate) struct Rtnl {
    lock: Spinlock<(), RtnlLockClass>,
}

/// Opaque proof that the calling process context holds the stack RTNL lock.
pub struct RtnlGuard<'a> {
    _guard: Guard<'a, (), RtnlLockClass>,
    stack:  &'a crate::NetStack,
}

impl Rtnl {
    /// # C: O(1)
    pub(crate) const fn new() -> Self { Self { lock: Spinlock::new(()) } }

    /// # C: O(contention)
    /// # Ctx: schedulable process context
    /// # Lk: stack RTNL lock acquired
    /// # Sleeps: never
    pub(crate) fn lock<'a>(&'a self, stack: &'a crate::NetStack) -> RtnlGuard<'a> {
        RtnlGuard { _guard: self.lock.lock(), stack }
    }
}

impl RtnlGuard<'_> {
    pub(crate) fn stack(&self) -> &crate::NetStack { self.stack }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn concurrent_holders_are_excluded() {
        const THREADS: usize = 4;
        const ITERATIONS: usize = 2_000;
        let stack = Arc::new(crate::NetStack::new());
        let start = Arc::new(Barrier::new(THREADS));
        let inside = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut workers = alloc::vec::Vec::new();

        for _ in 0..THREADS {
            let stack = stack.clone();
            let start = start.clone();
            let inside = inside.clone();
            let entered = entered.clone();
            workers.push(thread::spawn(move || {
                start.wait();
                for _ in 0..ITERATIONS {
                    let _guard = stack.rtnl_lock();
                    assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                    thread::yield_now();
                    entered.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(inside.fetch_sub(1, Ordering::SeqCst), 1);
                }
            }));
        }
        for worker in workers { worker.join().unwrap(); }

        assert_eq!(inside.load(Ordering::SeqCst), 0);
        assert_eq!(entered.load(Ordering::Relaxed), THREADS * ITERATIONS);
    }

    #[test]
    fn dropping_guard_releases_lock() {
        let stack = crate::NetStack::new();
        { let _guard = stack.rtnl_lock(); }
        let _guard = stack.rtnl_lock();
    }
}

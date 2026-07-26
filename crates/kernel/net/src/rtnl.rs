//! Stack RTNL lock — Linux `rtnl_lock()`.
//!
//! This is a SLEEPING mutex, exactly as Linux's is (`mutex_lock(&rtnl_mutex)`),
//! and it must be: RTNL holders legitimately block. They allocate, talk to
//! drivers, and wait on devices while holding it.
//!
//! It was a spinlock, and that was the single worst bug in the boot. A holder
//! that slept put every other acquirer into an unbounded spin, and because the
//! kernel does not preempt kernel mode, the spinner then owned the CPU forever
//! and the sleeping holder could never be rescheduled to release it. One real
//! instance: `ktimers` firing `ipv6_control_tick` spun here while
//! NetworkManager held RTNL across a sleep — 0 context switches for 40 s, the
//! whole machine dead at ~191 s, before gdm.
//!
//! Because it sleeps, RTNL must NEVER be taken from softirq or hard IRQ. Every
//! call site was audited for that (78 process-context sites); the four that
//! were softirq-reachable were fixed first: IGMP/MLD query response now reads
//! the interface generation without RTNL, and final socket destruction is
//! deferred out of softirq.

/// Lock implementation, chosen at the module boundary.
///
/// On the kernel target RTNL is a sleeping mutex, matching Linux. Hosted builds
/// have no scheduler to sleep on -- `sched::live` does not even exist there --
/// and their "tasks" are real OS threads that make progress independently, so a
/// spinlock is the correct stand-in and the exclusion contract under test is
/// identical.
#[cfg(target_os = "oxide-kernel")]
mod imp {
    pub(super) type Lock = sched::live::Mutex<()>;
    pub(super) type LockGuard<'a> = sched::live::MutexGuard<'a, ()>;
    pub(super) const fn new() -> Lock { sched::live::Mutex::new(()) }
    /// # SAFETY: caller is in process context holding no spinlock -- see the
    /// call-site audit quoted in `Rtnl::lock`.
    pub(super) fn lock(l: &Lock) -> LockGuard<'_> { unsafe { l.lock() } }
    pub(super) fn try_lock(l: &Lock) -> Option<LockGuard<'_>> { l.try_lock() }
}

#[cfg(not(target_os = "oxide-kernel"))]
mod imp {
    use sync::{Guard, LockClass, Spinlock};
    pub(super) struct RtnlLockClass;
    impl LockClass for RtnlLockClass { fn rank() -> u16 { 125 } }
    pub(super) type Lock = Spinlock<(), RtnlLockClass>;
    pub(super) type LockGuard<'a> = Guard<'a, (), RtnlLockClass>;
    pub(super) const fn new() -> Lock { Spinlock::new(()) }
    pub(super) fn lock(l: &Lock) -> LockGuard<'_> { l.lock() }
    pub(super) fn try_lock(l: &Lock) -> Option<LockGuard<'_>> { Some(l.lock()) }
}

pub(crate) struct Rtnl {
    lock: imp::Lock,
    #[cfg(test)] acquisitions: core::sync::atomic::AtomicUsize,
}

/// Opaque proof that the calling process context holds the stack RTNL lock.
pub struct RtnlGuard<'a> {
    _guard: imp::LockGuard<'a>,
    stack:  &'a crate::NetStack,
}

impl Rtnl {
    /// # C: O(1)
    pub(crate) const fn new() -> Self { Self {
        lock: imp::new(),
        #[cfg(test)] acquisitions: core::sync::atomic::AtomicUsize::new(0),
    } }

    /// # C: O(1) uncontended; one context switch per contended round
    /// # Ctx: schedulable process context ONLY -- never softirq, never hard IRQ
    /// # Lk: stack RTNL lock acquired
    /// # Sleeps: yes, while another task holds it
    pub(crate) fn lock<'a>(&'a self, stack: &'a crate::NetStack) -> RtnlGuard<'a> {
        #[cfg(test)]
        self.acquisitions.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // SAFETY: process context, holding no spinlock. Every RTNL call site was
        // audited for this: 78 are process-context (syscalls, netlink handlers,
        // ioctls, the ktimers timer callbacks and the netns reaper kthread), and
        // the four softirq-reachable ones were removed before this conversion --
        // IGMP/MLD RX no longer takes RTNL, and final socket release is deferred
        // out of softirq. Keeping this wrapper safe leaves the 117 callers
        // untouched; the contract is enforced by that audit, not by each caller.
        let guard = imp::lock(&self.lock);
        RtnlGuard { _guard: guard, stack }
    }

    /// Non-blocking acquire (Linux `rtnl_trylock`). For a caller that must not
    /// wait -- a periodic task that can simply skip this round rather than
    /// queue behind a long control-plane operation.
    /// # C: O(1)
    pub(crate) fn try_lock<'a>(&'a self, stack: &'a crate::NetStack)
        -> Option<RtnlGuard<'a>>
    {
        #[cfg(test)]
        self.acquisitions.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Some(RtnlGuard { _guard: imp::try_lock(&self.lock)?, stack })
    }

    #[cfg(test)]
    pub(crate) fn acquisition_count(&self) -> usize {
        self.acquisitions.load(core::sync::atomic::Ordering::Relaxed)
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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use super::WaitList;

/// Re-entrant NT mutant state. Ownership is a thread id, not a process id;
/// this is the distinction that makes recursive waits and release validation
/// observable to Wine-derived `RtlEnterCriticalSection` implementations.
pub struct NtMutant {
    owner: AtomicU64,
    recursion: AtomicU32,
    waiters: WaitList,
}

impl NtMutant {
    /// Construct an unnamed mutant, optionally owned by its creating thread. # C: O(1)
    pub fn new(owner: Option<u64>) -> Self {
        Self { owner: AtomicU64::new(owner.unwrap_or(0)), recursion: AtomicU32::new(if owner.is_some() { 1 } else { 0 }), waiters: WaitList::new() }
    }

    /// Return whether this thread can acquire the mutant immediately. # C: O(1)
    pub fn is_signaled_for(&self, tid: u64) -> bool {
        let owner = self.owner.load(Ordering::Acquire);
        owner == 0 || owner == tid
    }

    /// Acquire the mutant or recursively increase this thread's ownership. # C: O(1)
    pub fn try_acquire(&self, tid: u64) -> bool {
        if tid == 0 { return false; }
        let owner = self.owner.load(Ordering::Acquire);
        if owner == tid { return self.recursion.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| count.checked_add(1)).is_ok(); }
        if owner != 0 { return false; }
        if self.owner.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            self.recursion.store(1, Ordering::Release);
            true
        } else { false }
    }

    /// Release one recursive level and return the previous NT count. # C: O(1)
    pub fn release(&self, tid: u64) -> Result<i32, ()> {
        if tid == 0 || self.owner.load(Ordering::Acquire) != tid { return Err(()); }
        let count = self.recursion.load(Ordering::Acquire);
        if count == 0 { return Err(()); }
        let previous = -(count as i32);
        if count == 1 {
            self.recursion.store(0, Ordering::Release);
            self.owner.store(0, Ordering::Release);
            self.waiters.wake_all();
        } else { self.recursion.store(count - 1, Ordering::Release); }
        Ok(previous)
    }

    /// Return the NT basic-information view for this thread. # C: O(1)
    pub fn basic_info(&self, tid: u64) -> (i32, bool, bool) {
        let owner = self.owner.load(Ordering::Acquire);
        (-(self.recursion.load(Ordering::Acquire) as i32), owner == tid && tid != 0, false)
    }

    /// Wait and acquire using the scheduler predicate protocol. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and keeps this object alive through the wait.
    pub unsafe fn wait(&self, tid: u64, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: the predicate only accesses this live mutant and its owned wait list.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.try_acquire(tid)) }
    }
}

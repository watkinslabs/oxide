// Sleeping reader-writer semaphore — Linux `struct rw_semaphore`.
//
// `sync::RwLock` is a reader-writer SPINlock: a contended acquirer busy-waits,
// so it may only guard spans that neither sleep nor take long. The span this
// primitive exists for is the opposite kind — `signal_struct::exec_update_lock`
// is held for WRITE across the whole of `execve`'s point of no return (address
// space swap, fd-table unshare, credential commit), which allocates, faults and
// may be preempted. Spinning through that on another CPU is unbounded.
//
// Writer-pessimistic, matching Linux: once a writer is queued, arriving readers
// wait behind it rather than joining the live read batch, so a reader stream
// cannot starve the exec side forever.
//
// Module manifest:
//   `sleep` — the blocking acquires. They park on a `live::WaitList`, which
//             exists only where the scheduler does, so they live behind that
//             module's own cfg rather than scattering it through the gate
//             arithmetic below. The gate, the non-blocking acquires and the
//             release paths are unconditional and hosted-tested.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use sync::{MutexGate, Spinlock};

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod sleep;

/// Gate state. Behind the gate lock so "test and enqueue" is atomic against
/// every release.
pub(crate) struct Gate {
    /// Readers currently holding.
    pub(crate) readers: u32,
    /// A writer currently holds.
    pub(crate) writer:  bool,
    /// Writers blocked. Non-zero closes the door on arriving readers.
    pub(crate) pending: u32,
}

impl Gate {
    const fn new() -> Self { Self { readers: 0, writer: false, pending: 0 } }
    /// A read may proceed only with no writer holding and none queued.
    /// # C: O(1)
    pub(crate) const fn read_ok(&self) -> bool { !self.writer && self.pending == 0 }
    /// A write may proceed only when the semaphore is completely idle.
    /// # C: O(1)
    pub(crate) const fn write_ok(&self) -> bool { !self.writer && self.readers == 0 }
}

pub struct RwSem<T> {
    pub(crate) gate: Spinlock<Gate, MutexGate>,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub(crate) wait: crate::live::WaitList,
    data: UnsafeCell<T>,
}

// SAFETY: the gate admits either one writer or a batch of readers, so a write guard is the sole mutator and read guards share only `&T`.
unsafe impl<T: Send + Sync> Sync for RwSem<T> {}
// SAFETY: moving the semaphore moves the data with it; guards borrow it and cannot outlive the move.
unsafe impl<T: Send> Send for RwSem<T> {}

impl<T> RwSem<T> {
    /// # C: O(1)
    pub const fn new(val: T) -> Self {
        Self {
            gate: Spinlock::new(Gate::new()),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            wait: crate::live::WaitList::new(),
            data: UnsafeCell::new(val),
        }
    }

    /// Non-blocking shared acquire (Linux `down_read_trylock`). The only read
    /// form legal from IRQ/softirq context or while holding a spinlock.
    /// # C: O(1)
    pub fn try_read(&self) -> Option<RwSemReadGuard<'_, T>> {
        let mut g = self.gate.lock();
        if !g.read_ok() { return None; }
        g.readers += 1;
        Some(RwSemReadGuard { sem: self })
    }

    /// Non-blocking exclusive acquire (Linux `down_write_trylock`).
    /// # C: O(1)
    pub fn try_write(&self) -> Option<RwSemWriteGuard<'_, T>> {
        let mut g = self.gate.lock();
        if !g.write_ok() { return None; }
        g.writer = true;
        Some(RwSemWriteGuard { sem: self })
    }

    /// Advisory: some holder is present. Can change the instant it returns.
    /// # C: O(1)
    pub fn is_locked(&self) -> bool {
        let g = self.gate.lock();
        g.writer || g.readers != 0
    }

    /// # C: O(1) + O(N_waiters) wake
    fn release_read(&self) {
        let idle = { let mut g = self.gate.lock(); g.readers -= 1; g.readers == 0 };
        // Only the LAST reader out can let a writer in, so only it need wake.
        if idle { self.wake_waiters(); }
    }

    /// # C: O(1) + O(N_waiters) wake
    fn release_write(&self) {
        { let mut g = self.gate.lock(); g.writer = false; }
        // Every waiter: a released write admits either the next writer or a
        // whole batch of readers, and each waiter's gate re-check sorts out
        // which. Waking one would strand the rest of a reader batch.
        self.wake_waiters();
    }

    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    /// # C: O(N_waiters)
    fn wake_waiters(&self) { self.wait.wake_all(); }

    #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
    /// No scheduler in this build, so no acquire can have parked. # C: O(1)
    fn wake_waiters(&self) {}
}

pub struct RwSemReadGuard<'a, T> { sem: &'a RwSem<T> }

impl<T> Deref for RwSemReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: a read guard exists only while the gate counts this reader, and the gate admits no writer concurrently.
        unsafe { &*self.sem.data.get() }
    }
}

impl<T> Drop for RwSemReadGuard<'_, T> {
    fn drop(&mut self) { self.sem.release_read(); }
}

pub struct RwSemWriteGuard<'a, T> { sem: &'a RwSem<T> }

impl<T> Deref for RwSemWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the write guard is the sole holder the gate admits, so no other accessor exists.
        unsafe { &*self.sem.data.get() }
    }
}

impl<T> DerefMut for RwSemWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the write guard is the sole holder the gate admits, so it is the sole mutator.
        unsafe { &mut *self.sem.data.get() }
    }
}

impl<T> Drop for RwSemWriteGuard<'_, T> {
    fn drop(&mut self) { self.sem.release_write(); }
}

#[cfg(test)]
#[path = "rwsem/tests.rs"]
mod tests;

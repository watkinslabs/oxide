// Blocking acquires for [`super::RwSem`] — Linux `down_read` / `down_write`.
//
// Lost-wakeup ordering, which is the whole difficulty, is the same discipline
// `live::mutex` uses: the enqueue happens UNDER the gate, so a releaser cannot
// slip between "saw it busy" and "became visible as a waiter". The gate is
// dropped BEFORE `schedule`, so it is never held across the sleep.

use super::{RwSem, RwSemReadGuard, RwSemWriteGuard};

impl<T> RwSem<T> {
    /// Shared acquire, sleeping while a writer holds or waits
    /// (Linux `down_read`).
    ///
    /// # SAFETY: process/kthread context ONLY, holding no spinlock — this can
    /// sleep, and a hard-IRQ handler that sleeps parks on the shared IRQ stack.
    /// # C: O(1) uncontended; one context switch per contended round
    /// # Ctx: process
    /// # Sleeps: yes, while a writer owns or awaits it
    pub unsafe fn read(&self) -> RwSemReadGuard<'_, T> {
        loop {
            let mut g = self.gate.lock();
            if g.read_ok() {
                g.readers += 1;
                drop(g);
                return RwSemReadGuard { sem: self };
            }
            // SAFETY: running task in process context; the gate is dropped below, before `schedule`, so no lock is held across the sleep.
            unsafe { self.wait.park_interruptible_with_deadline(0); }
            drop(g);
            // SAFETY: parked on this semaphore's own wait list while holding no lock.
            unsafe { crate::live::schedule(); }
        }
    }

    /// Exclusive acquire, sleeping while anyone holds (Linux `down_write`).
    /// Counts itself as a queued writer for the whole wait, which is what stops
    /// a reader stream from starving it.
    ///
    /// # SAFETY: process/kthread context ONLY, holding no spinlock.
    /// # C: O(1) uncontended; one context switch per contended round
    /// # Ctx: process
    /// # Sleeps: yes, while any holder is present
    pub unsafe fn write(&self) -> RwSemWriteGuard<'_, T> {
        {
            let mut g = self.gate.lock();
            if g.write_ok() { g.writer = true; drop(g); return RwSemWriteGuard { sem: self }; }
            g.pending += 1;
        }
        loop {
            let mut g = self.gate.lock();
            if g.write_ok() {
                g.writer = true;
                g.pending -= 1;
                drop(g);
                return RwSemWriteGuard { sem: self };
            }
            // SAFETY: running task in process context; the gate is dropped below, before `schedule`, so no lock is held across the sleep.
            unsafe { self.wait.park_interruptible_with_deadline(0); }
            drop(g);
            // SAFETY: parked on this semaphore's own wait list while holding no lock.
            unsafe { crate::live::schedule(); }
        }
    }
}

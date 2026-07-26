// Sleeping mutex — Linux `struct mutex` (`skizm.md` §2 finding (a), Step 7).
//
// Until now every lock in the core kernel was a spinlock, so a subsystem that
// needed to hold a lock ACROSS a sleep could not express it: it either
// busy-waited or held a spinlock while doing I/O. The inventory called that
// "upstream of a lot of what we have been chasing", and it is — a spinlock held
// across block I/O is an unbounded spin for every other CPU.
//
// A contended waiter here SLEEPS instead. The owner may block, do I/O, or be
// preempted while holding it, and the cost to everyone else is a context
// switch rather than a spin.
//
// Deliberate subset (`skizm.md` §7, labelled as required): no priority
// inheritance, no adaptive spinning (Linux's `mutex_spin_on_owner`). Those are
// optimisations over this contract, not part of it.
//
// **Never take this from IRQ or softirq context, and never while holding a
// spinlock** — both can sleep here, and a hard-IRQ handler that sleeps parks
// on the shared IRQ stack. `try_lock` is the non-blocking form for those.
//
// Lost-wakeup ordering, which is the whole difficulty:
//
//   locker                              unlocker
//   ------                              --------
//   take gate                           take gate
//   see locked -> enqueue self on wait   set unlocked
//   drop gate                            drop gate
//   schedule()                           wake_one()
//
// The enqueue happens UNDER the gate, so an unlocker cannot slip between "saw
// it locked" and "became visible as a waiter": it is either before our enqueue
// (and then our own gate acquisition sees `locked == false`) or after it (and
// then its `wake_one` finds us). The gate is dropped BEFORE `schedule`, so it
// is never held across the sleep. Same shape as `inode_wait`.

extern crate alloc;

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use sync::{MutexGate, Spinlock};

use super::WaitList;

/// Gate state. One bool, but behind the gate lock so the "test and enqueue"
/// pair is atomic with respect to unlock.
struct Gate {
    locked: bool,
}

pub struct Mutex<T> {
    gate: Spinlock<Gate, MutexGate>,
    wait: WaitList,
    data: UnsafeCell<T>,
}

// SAFETY: the gate serializes ownership, so exactly one guard exists at a time
// and T behaves as if &mut-borrowed by that guard.
unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    /// # C: O(1)
    pub const fn new(val: T) -> Self {
        Self {
            gate: Spinlock::new(Gate { locked: false }),
            wait: WaitList::new(),
            data: UnsafeCell::new(val),
        }
    }

    /// Non-blocking acquire (Linux `mutex_trylock`). The only form legal from
    /// IRQ/softirq context or while holding a spinlock, because it never sleeps.
    /// # C: O(1)
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let mut g = self.gate.lock();
        if g.locked {
            return None;
        }
        g.locked = true;
        Some(MutexGuard { mutex: self })
    }

    /// Acquire, sleeping while contended (Linux `mutex_lock`).
    ///
    /// # SAFETY: process/kthread context ONLY. The caller must not be in a
    /// hard-IRQ or softirq handler and must hold no spinlock, because this can
    /// sleep — see the module note.
    /// # C: O(1) uncontended; one context switch per contended round
    /// # Sleeps: yes, while another task owns it
    pub unsafe fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            let mut g = self.gate.lock();
            if !g.locked {
                g.locked = true;
                return MutexGuard { mutex: self };
            }
            // Enqueue UNDER the gate — that is what closes the lost wakeup.
            // SAFETY: caller is the running task in process context; the gate is
            // dropped immediately below, before `schedule`, so no lock is held
            // across the sleep. Interruptible so a pending unmasked signal
            // returns us to Runnable rather than sleeping through it.
            unsafe { self.wait.park_interruptible_with_deadline(0); }
            drop(g);
            // SAFETY: parked on this mutex's wait list holding no lock.
            unsafe { super::schedule(); }
        }
    }

    /// True if currently held. Advisory only — it can change the instant it
    /// returns; for anything load-bearing use `try_lock`.
    /// # C: O(1)
    pub fn is_locked(&self) -> bool { self.gate.lock().locked }

    /// Release. Split out so `MutexGuard::drop` and the tests share one path.
    /// # C: O(1) + O(1) wake
    fn unlock(&self) {
        {
            let mut g = self.gate.lock();
            g.locked = false;
        }
        // Wake AFTER dropping the gate: the woken task's first act is to take
        // the gate, so waking under it would just make it spin on us.
        self.wait.wake_one();
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while this task owns the gate, so it is the sole accessor.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard exists only while this task owns the gate, so it is the sole mutable accessor.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) { self.mutex.unlock(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncontended_try_lock_round_trip() {
        let m: Mutex<u32> = Mutex::new(0);
        assert!(!m.is_locked());
        {
            let mut g = m.try_lock().expect("free mutex must be acquirable");
            *g = 7;
            assert!(m.is_locked(), "held for the guard's lifetime");
        }
        assert!(!m.is_locked(), "released on drop");
        assert_eq!(*m.try_lock().unwrap(), 7);
    }

    #[test]
    fn try_lock_fails_while_held_and_succeeds_after_release() {
        let m: Mutex<()> = Mutex::new(());
        let g = m.try_lock().unwrap();
        assert!(m.try_lock().is_none(), "a second acquire must fail, not spin");
        drop(g);
        assert!(m.try_lock().is_some(), "release must hand it back");
    }

    #[test]
    fn unlock_is_idempotent_in_state_terms() {
        // Drop order and the explicit unlock path must agree: after either, the
        // gate reads unlocked and the next acquire succeeds.
        let m: Mutex<u8> = Mutex::new(1);
        m.try_lock().unwrap().clone_from(&2);
        assert!(!m.is_locked());
        assert_eq!(*m.try_lock().unwrap(), 2);
    }

    #[test]
    fn data_survives_lock_cycles() {
        let m: Mutex<alloc::vec::Vec<u32>> = Mutex::new(alloc::vec::Vec::new());
        for i in 0..8u32 {
            m.try_lock().unwrap().push(i);
        }
        let g = m.try_lock().unwrap();
        assert_eq!(g.len(), 8);
        assert_eq!(g[7], 7);
    }
}

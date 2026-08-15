use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
use core::sync::atomic::AtomicUsize;

#[cfg(test)]
static LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_lock_calls() { LOCK_CALLS.store(0, Ordering::Relaxed); }

#[cfg(test)]
pub(crate) fn lock_calls() -> usize { LOCK_CALLS.load(Ordering::Relaxed) }

pub(crate) struct SpinLock<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `held` serializes every shared access to the contained `T` value.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self { held: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Acquire exclusive registry access. # C: O(1) uncontended
    pub(crate) fn lock(&self) -> Guard<'_, T> {
        #[cfg(test)]
        LOCK_CALLS.fetch_add(1, Ordering::Relaxed);
        while self.held.compare_exchange_weak(false, true,
            Ordering::Acquire, Ordering::Relaxed).is_err()
        {
            while self.held.load(Ordering::Relaxed) { spin_loop(); }
        }
        Guard { lock: self }
    }
}

pub(crate) struct Guard<'a, T> { lock: &'a SpinLock<T> }

impl<T> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard exclusively controls access until its Drop runs.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard exclusively controls access until its Drop runs.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) { self.lock.held.store(false, Ordering::Release); }
}

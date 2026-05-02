// Reader-writer spinlock per `06§3.2`. Reader-prefer (writers can
// starve, accepted by spec; "use sparingly. Prefer RCU for read-mostly").
// Carries a `LockClass` like `Spinlock` so the partial-order check in
// `06§3.6` covers it once `debug-lockdep` lands.
//
// State word layout (`AtomicU32`):
//   bit 31         : writer holds (or pending — set during writer wait)
//   bits 0..30     : reader count
// Idle = 0; reader = `count` low bits set; writer = `WRITER_BIT` only
// (no readers concurrent).
//
// No `lock_irqsave` variant yet; reachable from non-IRQ contexts only.
// Wired alongside the first IRQ-shared consumer (none yet).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::LockClass;

const WRITER_BIT: u32 = 1 << 31;
const READER_MASK: u32 = !WRITER_BIT;
const READER_MAX: u32 = READER_MASK; // saturates at 2^31 - 1 readers

pub struct RwLock<T, C: LockClass> {
    state: AtomicU32,
    cell:  UnsafeCell<T>,
    _class: PhantomData<C>,
}

// SAFETY: state CAS gates exclusive vs shared access; readers only
// take a shared `&T`, writer takes the sole `&mut T`. Standard
// reader-writer invariant per `06§3.2`.
unsafe impl<T: Send + Sync, C: LockClass> Sync for RwLock<T, C> {}
unsafe impl<T: Send,         C: LockClass> Send for RwLock<T, C> {}

impl<T, C: LockClass> RwLock<T, C> {
    /// # C: O(1)
    pub const fn new(val: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            cell:  UnsafeCell::new(val),
            _class: PhantomData,
        }
    }

    /// Acquire a shared (read) lock. Spins while a writer holds.
    /// Multiple readers are concurrent.
    /// # C: O(contention)
    /// # Lk: this lock acquired (read)
    pub fn read(&self) -> RwReadGuard<'_, T, C> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT != 0 || (s & READER_MASK) == READER_MAX {
                core::hint::spin_loop();
                continue;
            }
            if self.state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwReadGuard { lock: self };
            }
        }
    }

    /// Acquire an exclusive (write) lock. Spins while any reader or
    /// another writer holds. Reader-prefer: a writer can starve under
    /// continuous reader load (`06§3.2` accepts this).
    /// # C: O(contention)
    /// # Lk: this lock acquired (write)
    pub fn write(&self) -> RwWriteGuard<'_, T, C> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s != 0 {
                core::hint::spin_loop();
                continue;
            }
            if self.state
                .compare_exchange_weak(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwWriteGuard { lock: self };
            }
        }
    }

    /// Snapshot of the lock state — number of readers and whether a
    /// writer holds. For tests / debug-lockdep only.
    /// # C: O(1)
    pub fn debug_state(&self) -> (u32, bool) {
        let s = self.state.load(Ordering::Relaxed);
        ((s & READER_MASK), (s & WRITER_BIT) != 0)
    }
}

pub struct RwReadGuard<'a, T, C: LockClass> {
    lock: &'a RwLock<T, C>,
}

impl<T, C: LockClass> Deref for RwReadGuard<'_, T, C> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: RwReadGuard exists only after a successful reader-count
        // increment with no writer bit set; T is shared-borrowed, never
        // mutated through this guard, while the count is non-zero.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T, C: LockClass> Drop for RwReadGuard<'_, T, C> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

pub struct RwWriteGuard<'a, T, C: LockClass> {
    lock: &'a RwLock<T, C>,
}

impl<T, C: LockClass> Deref for RwWriteGuard<'_, T, C> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: RwWriteGuard exists only after the CAS that took the
        // writer bit when state was 0; sole accessor for its lifetime
        // per the RwLock state invariant.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T, C: LockClass> DerefMut for RwWriteGuard<'_, T, C> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: same as Deref — sole accessor implies sole mutator
        // for the lifetime of this RwWriteGuard, per RwLock invariant.
        unsafe { &mut *self.lock.cell.get() }
    }
}

impl<T, C: LockClass> Drop for RwWriteGuard<'_, T, C> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AddressSpace;
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn read_then_drop_returns_state_to_zero() {
        let l: RwLock<u32, AddressSpace> = RwLock::new(7);
        {
            let g = l.read();
            assert_eq!(*g, 7);
            let (rc, w) = l.debug_state();
            assert_eq!((rc, w), (1, false));
        }
        let (rc, w) = l.debug_state();
        assert_eq!((rc, w), (0, false));
    }

    #[test]
    fn multiple_readers_concurrent() {
        let l: RwLock<u32, AddressSpace> = RwLock::new(42);
        let g1 = l.read();
        let g2 = l.read();
        let g3 = l.read();
        assert_eq!(*g1, 42);
        assert_eq!(*g2, 42);
        assert_eq!(*g3, 42);
        let (rc, _) = l.debug_state();
        assert_eq!(rc, 3);
    }

    #[test]
    fn writer_excludes_readers_and_self() {
        let l: RwLock<u32, AddressSpace> = RwLock::new(0);
        {
            let mut g = l.write();
            *g = 99;
            let (rc, w) = l.debug_state();
            assert_eq!((rc, w), (0, true));
        }
        let g = l.read();
        assert_eq!(*g, 99);
    }

    #[test]
    fn concurrent_readers_writer_eventually_wins() {
        // Many readers in a tight loop; one writer must eventually
        // acquire and observe its own write. Smoke-test only — full
        // fairness analysis is out of scope (writers can starve).
        let l: Arc<RwLock<u32, AddressSpace>> = Arc::new(RwLock::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let l = Arc::clone(&l);
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    let g = l.read();
                    let _ = *g;
                }
            }));
        }
        let writer_l = Arc::clone(&l);
        let writer = thread::spawn(move || {
            let mut g = writer_l.write();
            *g = 777;
        });
        writer.join().unwrap();
        for h in handles { h.join().unwrap(); }
        let g = l.read();
        assert_eq!(*g, 777);
    }
}

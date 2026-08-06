use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{AddressSpace as AddressSpaceClass, Spinlock};

const WRITER: u32 = 1 << 31;
const READERS: u32 = !WRITER;

type ParkHook = fn(usize);
type ScheduleHook = fn();
type WakeHook = fn(usize);

static PARK_HOOK: AtomicU64 = AtomicU64::new(0);
static SCHEDULE_HOOK: AtomicU64 = AtomicU64::new(0);
static WAKE_HOOK: AtomicU64 = AtomicU64::new(0);

fn load_hook<T: Copy>(slot: &AtomicU64) -> Option<T> {
    let raw = slot.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: each slot is written only by set_mmap_rwsem_wait_hooks with the matching fn type.
    Some(unsafe { core::mem::transmute_copy::<u64, T>(&raw) })
}

/// Install scheduler wait hooks for mmap rwsem contention.
/// # C: O(1)
pub fn set_mmap_rwsem_wait_hooks(park: ParkHook, schedule: ScheduleHook, wake: WakeHook) {
    PARK_HOOK.store(park as usize as u64, Ordering::Release);
    SCHEDULE_HOOK.store(schedule as usize as u64, Ordering::Release);
    WAKE_HOOK.store(wake as usize as u64, Ordering::Release);
}

/// Clear process-global mmap rwsem wait hooks for hosted tests.
/// # C: O(1)
#[cfg(test)]
pub fn clear_mmap_rwsem_wait_hooks() {
    PARK_HOOK.store(0, Ordering::Release);
    SCHEDULE_HOOK.store(0, Ordering::Release);
    WAKE_HOOK.store(0, Ordering::Release);
}

/// Per-mm sleepable mmap reader/writer semaphore.
pub struct MmapRwsem<T> {
    state: AtomicU32,
    writers_waiting: AtomicU32,
    wait_lock: Spinlock<(), AddressSpaceClass>,
    cell: UnsafeCell<T>,
}

// SAFETY: state grants either shared immutable access or one exclusive mutable accessor.
unsafe impl<T: Send + Sync> Sync for MmapRwsem<T> {}
// SAFETY: the protected value and synchronization state can move between execution contexts.
unsafe impl<T: Send> Send for MmapRwsem<T> {}

impl<T> MmapRwsem<T> {
    /// # C: O(1)
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            writers_waiting: AtomicU32::new(0),
            wait_lock: Spinlock::new(()),
            cell: UnsafeCell::new(value),
        }
    }

    fn key(&self) -> usize { self as *const Self as usize }

    fn park(&self, gate: sync::Guard<'_, (), AddressSpaceClass>) {
        let park = load_hook::<ParkHook>(&PARK_HOOK);
        let schedule = load_hook::<ScheduleHook>(&SCHEDULE_HOOK);
        match (park, schedule) {
            (Some(park), Some(schedule)) => {
                park(self.key());
                drop(gate);
                schedule();
            }
            _ => {
                drop(gate);
                sync::relax();
            }
        }
    }

    /// Acquire shared, sleeping behind an active or queued writer.
    /// # C: O(contention)
    /// # Sleeps: yes, on contention after runtime hooks are installed
    pub fn read(&self) -> MmapReadGuard<'_, T> {
        loop {
            let gate = self.wait_lock.lock();
            let state = self.state.load(Ordering::Relaxed);
            if state & WRITER == 0
                && state & READERS != READERS
                && self.writers_waiting.load(Ordering::Relaxed) == 0
            {
                self.state.store(state + 1, Ordering::Release);
                drop(gate);
                return MmapReadGuard { lock: self };
            }
            self.park(gate);
        }
    }

    /// Acquire exclusive, sleeping until readers and the writer drain.
    /// # C: O(contention)
    /// # Sleeps: yes, on contention after runtime hooks are installed
    pub fn write(&self) -> MmapWriteGuard<'_, T> {
        let mut queued = false;
        loop {
            let gate = self.wait_lock.lock();
            if !queued {
                self.writers_waiting.fetch_add(1, Ordering::Relaxed);
                queued = true;
            }
            if self.state.load(Ordering::Relaxed) == 0 {
                self.writers_waiting.fetch_sub(1, Ordering::Relaxed);
                self.state.store(WRITER, Ordering::Release);
                drop(gate);
                return MmapWriteGuard { lock: self };
            }
            self.park(gate);
        }
    }

    fn wake(&self) {
        if let Some(wake) = load_hook::<WakeHook>(&WAKE_HOOK) { wake(self.key()); }
    }

    fn read_unlock(&self) {
        let gate = self.wait_lock.lock();
        let state = self.state.load(Ordering::Relaxed);
        self.state.store(state - 1, Ordering::Release);
        if state == 1 { self.wake(); }
        drop(gate);
    }

    fn write_unlock(&self) {
        let gate = self.wait_lock.lock();
        self.state.store(0, Ordering::Release);
        self.wake();
        drop(gate);
    }

    /// Reader/writer snapshot for hosted lock-contract tests.
    /// # C: O(1)
    #[cfg(test)]
    pub fn debug_state(&self) -> (u32, bool) {
        let state = self.state.load(Ordering::Acquire);
        (state & READERS, state & WRITER != 0)
    }
}

pub struct MmapReadGuard<'a, T> { lock: &'a MmapRwsem<T> }

impl<T> Drop for MmapReadGuard<'_, T> {
    fn drop(&mut self) { self.lock.read_unlock(); }
}

impl<T> Deref for MmapReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: successful shared acquisition excludes writers until this guard drops.
        unsafe { &*self.lock.cell.get() }
    }
}

pub struct MmapWriteGuard<'a, T> { lock: &'a MmapRwsem<T> }

impl<T> Drop for MmapWriteGuard<'_, T> {
    fn drop(&mut self) { self.lock.write_unlock(); }
}

impl<T> Deref for MmapWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: successful exclusive acquisition is the sole cell accessor until this guard drops.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T> DerefMut for MmapWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: successful exclusive acquisition is the sole mutable cell accessor until this guard drops.
        unsafe { &mut *self.lock.cell.get() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use std::sync::{Condvar, Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

    struct WaitState { parked: u32, wake: bool }

    fn state() -> &'static (Mutex<WaitState>, Condvar) {
        static STATE: OnceLock<(Mutex<WaitState>, Condvar)> = OnceLock::new();
        STATE.get_or_init(|| (Mutex::new(WaitState { parked: 0, wake: false }), Condvar::new()))
    }

    fn serial() -> &'static Mutex<()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| Mutex::new(()))
    }

    fn park(_key: usize) {
        let (lock, cv) = state();
        let mut state = lock.lock().unwrap();
        state.parked += 1;
        cv.notify_all();
    }

    fn schedule() {
        let (lock, cv) = state();
        let mut state = lock.lock().unwrap();
        while !state.wake { state = cv.wait(state).unwrap(); }
    }

    fn wake(_key: usize) {
        let (lock, cv) = state();
        let mut state = lock.lock().unwrap();
        state.wake = true;
        cv.notify_all();
    }

    fn reset() {
        let (lock, _) = state();
        *lock.lock().unwrap() = WaitState { parked: 0, wake: false };
        set_mmap_rwsem_wait_hooks(park, schedule, wake);
    }

    #[test]
    fn contended_fault_reader_parks_until_vma_writer_releases() {
        let _serial = serial().lock().unwrap();
        reset();
        let sem = Arc::new(MmapRwsem::new(0u32));
        let writer = sem.write();
        let peer = Arc::clone(&sem);
        let reader = thread::spawn(move || { let _guard = peer.read(); });
        let (lock, cv) = state();
        let state = lock.lock().unwrap();
        let (state, timeout) = cv.wait_timeout_while(state, Duration::from_secs(2), |s| s.parked == 0).unwrap();
        assert!(!timeout.timed_out(), "mmap reader spun instead of parking");
        drop(state);
        drop(writer);
        reader.join().unwrap();
        assert_eq!(sem.debug_state(), (0, false));
        clear_mmap_rwsem_wait_hooks();
    }
}

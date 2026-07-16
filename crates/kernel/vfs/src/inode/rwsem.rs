use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Inode as InodeLockClass, Spinlock};

const WRITER: u32 = 1 << 31;
const READERS: u32 = !WRITER;

type ParkHook = fn(usize);
type ScheduleHook = fn();
type WakeHook = fn(usize);

static PARK_HOOK: AtomicU64 = AtomicU64::new(0);
static SCHEDULE_HOOK: AtomicU64 = AtomicU64::new(0);
static WAKE_HOOK: AtomicU64 = AtomicU64::new(0);

fn load_hook<T>(slot: &AtomicU64) -> Option<T> where T: Copy {
    let raw = slot.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: each slot is written only by set_inode_rwsem_wait_hooks with the matching fn type.
    Some(unsafe { core::mem::transmute_copy::<u64, T>(&raw) })
}

/// Install scheduler wait hooks for inode rwsem contention. # C: O(1)
pub fn set_inode_rwsem_wait_hooks(park: ParkHook, schedule: ScheduleHook, wake: WakeHook) {
    PARK_HOOK.store(park as usize as u64, Ordering::Release);
    SCHEDULE_HOOK.store(schedule as usize as u64, Ordering::Release);
    WAKE_HOOK.store(wake as usize as u64, Ordering::Release);
}

/// Clear process-global inode rwsem wait hooks for hosted tests. # C: O(1)
pub fn clear_inode_rwsem_wait_hooks() {
    PARK_HOOK.store(0, Ordering::Release);
    SCHEDULE_HOOK.store(0, Ordering::Release);
    WAKE_HOOK.store(0, Ordering::Release);
}

/// Linux-shaped sleepable `inode->i_rwsem`.
pub struct InodeRwsem {
    state: AtomicU32,
    writers_waiting: AtomicU32,
    wait_lock: Spinlock<(), InodeLockClass>,
    cell: UnsafeCell<()>,
}

// SAFETY: rwsem state grants either shared immutable access or one exclusive mutable access to cell.
unsafe impl Sync for InodeRwsem {}
// SAFETY: the protected unit value and synchronization state can move between execution contexts.
unsafe impl Send for InodeRwsem {}

impl InodeRwsem {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(0), writers_waiting: AtomicU32::new(0), wait_lock: Spinlock::new(()), cell: UnsafeCell::new(()) }
    }

    fn key(&self) -> usize { self as *const Self as usize }

    fn park(&self, gate: sync::Guard<'_, (), InodeLockClass>) {
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
                core::hint::spin_loop();
            }
        }
    }

    /// Acquire shared, parking behind an active or queued writer. # C: O(contention)
    pub fn read(&self) -> InodeRwsemReadGuard<'_> {
        loop {
            let gate = self.wait_lock.lock();
            let state = self.state.load(Ordering::Relaxed);
            if state & WRITER == 0
                && state & READERS != READERS
                && self.writers_waiting.load(Ordering::Relaxed) == 0
            {
                self.state.store(state + 1, Ordering::Release);
                drop(gate);
                return InodeRwsemReadGuard { lock: self };
            }
            self.park(gate);
        }
    }

    /// Acquire exclusive, parking until readers and writer drain. # C: O(contention)
    pub fn write(&self) -> InodeRwsemWriteGuard<'_> {
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
                return InodeRwsemWriteGuard { lock: self };
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

    /// Reader/writer snapshot for hosted lock-contract tests. # C: O(1)
    #[cfg(test)]
    pub fn debug_state(&self) -> (u32, bool) {
        let state = self.state.load(Ordering::Acquire);
        (state & READERS, state & WRITER != 0)
    }
}

pub struct InodeRwsemReadGuard<'a> { lock: &'a InodeRwsem }
impl Drop for InodeRwsemReadGuard<'_> { fn drop(&mut self) { self.lock.read_unlock(); } }
impl core::ops::Deref for InodeRwsemReadGuard<'_> {
    type Target = ();
    fn deref(&self) -> &Self::Target {
        // SAFETY: successful shared acquisition excludes writers until this guard drops.
        unsafe { &*self.lock.cell.get() }
    }
}

pub struct InodeRwsemWriteGuard<'a> { lock: &'a InodeRwsem }
impl Drop for InodeRwsemWriteGuard<'_> { fn drop(&mut self) { self.lock.write_unlock(); } }
impl core::ops::Deref for InodeRwsemWriteGuard<'_> {
    type Target = ();
    fn deref(&self) -> &Self::Target {
        // SAFETY: successful exclusive acquisition is the sole cell accessor until this guard drops.
        unsafe { &*self.lock.cell.get() }
    }
}
impl core::ops::DerefMut for InodeRwsemWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: successful exclusive acquisition is the sole cell accessor until this guard drops.
        unsafe { &mut *self.lock.cell.get() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
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
        set_inode_rwsem_wait_hooks(park, schedule, wake);
    }

    fn wait_for_parks(count: u32) {
        let (lock, cv) = state();
        let state = lock.lock().unwrap();
        let (state, timeout) = cv.wait_timeout_while(state, Duration::from_secs(2), |s| s.parked < count).unwrap();
        assert!(!timeout.timed_out(), "rwsem waiter did not park");
        assert!(state.parked >= count);
    }

    #[test]
    fn contended_reader_parks_then_wakes() {
        let _serial = serial().lock().unwrap();
        reset();
        let sem = Arc::new(InodeRwsem::new());
        let writer = sem.write();
        let peer = Arc::clone(&sem);
        let reader = thread::spawn(move || { let _guard = peer.read(); });
        wait_for_parks(1);
        drop(writer);
        reader.join().unwrap();
        assert_eq!(sem.debug_state(), (0, false));
        clear_inode_rwsem_wait_hooks();
    }

    #[test]
    fn queued_writer_excludes_later_reader() {
        let _serial = serial().lock().unwrap();
        static ORDER: AtomicU32 = AtomicU32::new(0);
        reset();
        ORDER.store(0, Ordering::Release);
        let sem = Arc::new(InodeRwsem::new());
        let first_reader = sem.read();
        let writer_sem = Arc::clone(&sem);
        let writer = thread::spawn(move || {
            let _guard = writer_sem.write();
            assert_eq!(ORDER.fetch_add(1, Ordering::AcqRel), 0);
        });
        wait_for_parks(1);
        let reader_sem = Arc::clone(&sem);
        let reader = thread::spawn(move || {
            let _guard = reader_sem.read();
            assert_eq!(ORDER.fetch_add(1, Ordering::AcqRel), 1);
        });
        wait_for_parks(2);
        drop(first_reader);
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(ORDER.load(Ordering::Acquire), 2);
        clear_inode_rwsem_wait_hooks();
    }
}

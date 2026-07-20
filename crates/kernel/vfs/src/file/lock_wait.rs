use sync::{Spinlock, TaskList as FileLockWaitClass};

/// Typed scheduler boundary for blocking file locks. VFS owns the file-lock
/// contract; the scheduler owns task parking, so this avoids a VFS→sched edge.
pub type FileLockParkHook = fn(usize);
/// Scheduler yield operation paired with [`FileLockParkHook`].
pub type FileLockScheduleHook = fn();
/// Scheduler wake operation for a file-lock contention key.
pub type FileLockWakeHook = fn(usize);
/// Scheduler signal-pending query for interruptible file-lock waits.
pub type FileLockInterruptedHook = fn() -> bool;

#[derive(Copy, Clone)]
struct FileLockWaitHooks {
    park:        Option<FileLockParkHook>,
    schedule:    Option<FileLockScheduleHook>,
    wake:        Option<FileLockWakeHook>,
    interrupted: Option<FileLockInterruptedHook>,
}

impl FileLockWaitHooks {
    /// # C: O(1)
    const fn empty() -> Self { Self { park: None, schedule: None, wake: None, interrupted: None } }
}

static FILE_LOCK_WAIT_HOOKS: Spinlock<FileLockWaitHooks, FileLockWaitClass> =
    Spinlock::new(FileLockWaitHooks::empty());

/// Install the scheduler operations used by blocking file locks. # C: O(1)
pub fn set_file_lock_wait_hooks(
    park: FileLockParkHook, schedule: FileLockScheduleHook, wake: FileLockWakeHook,
    interrupted: FileLockInterruptedHook,
) {
    *FILE_LOCK_WAIT_HOOKS.lock() = FileLockWaitHooks {
        park: Some(park), schedule: Some(schedule), wake: Some(wake), interrupted: Some(interrupted),
    };
}

/// Clear process-global file-lock hooks for hosted tests. # C: O(1)
pub fn clear_file_lock_wait_hooks() { *FILE_LOCK_WAIT_HOOKS.lock() = FileLockWaitHooks::empty(); }

/// Register the running task before the file-lock state gate is released. # C: O(1)
pub fn file_lock_park(key: usize) {
    let park = FILE_LOCK_WAIT_HOOKS.lock().park;
    if let Some(park) = park { park(key); }
}

/// Yield after `file_lock_park` while no file-lock gate remains held. # C: sleeps
pub fn file_lock_schedule() {
    let schedule = FILE_LOCK_WAIT_HOOKS.lock().schedule;
    if let Some(schedule) = schedule { schedule(); }
}

/// Wake all blocking file-lock contenders after releasing the state gate. # C: O(N_waiters)
pub fn file_lock_wake(key: usize) {
    let wake = FILE_LOCK_WAIT_HOOKS.lock().wake;
    if let Some(wake) = wake { wake(key); }
}

/// True when an interruptible file-lock wait must return EINTR. # C: O(1)
pub fn file_lock_interrupted() -> bool {
    let interrupted = FILE_LOCK_WAIT_HOOKS.lock().interrupted;
    interrupted.is_some_and(|interrupted| interrupted())
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static EVENTS: AtomicUsize = AtomicUsize::new(0);
    const PARKED: usize = 1;
    const SCHEDULED: usize = 2;
    const WOKEN: usize = 4;

    fn park(key: usize) { EVENTS.fetch_or(PARKED | key, Ordering::AcqRel); }
    fn schedule() { EVENTS.fetch_or(SCHEDULED, Ordering::AcqRel); }
    fn wake(key: usize) { EVENTS.fetch_or(WOKEN | key, Ordering::AcqRel); }
    fn interrupted() -> bool { true }

    #[test]
    fn typed_hooks_dispatch_after_registration() {
        const KEY: usize = 8;
        EVENTS.store(0, Ordering::Release);
        set_file_lock_wait_hooks(park, schedule, wake, interrupted);
        file_lock_park(KEY);
        file_lock_schedule();
        file_lock_wake(KEY);
        assert_eq!(EVENTS.load(Ordering::Acquire), PARKED | SCHEDULED | WOKEN | KEY);
        assert!(file_lock_interrupted());
        clear_file_lock_wait_hooks();
    }
}

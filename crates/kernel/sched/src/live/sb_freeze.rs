use super::{schedule, KeyedWaitQueues};

static WAITERS: KeyedWaitQueues<usize> = KeyedWaitQueues::new();

/// Register current on the sb-freeze wait list; VFS holds its freeze wait lock.
/// # C: O(log N)
pub fn park(key: usize) {
    WAITERS.prepare(key);
}

/// Yield after [`park`] has registered the current task and VFS dropped its lock.
/// # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller just parked current on a WaitList and holds no VFS freeze lock.
    unsafe { schedule(); }
}

/// Wake every task sleeping on the given sb-freeze wait list.
/// # C: O(N_waiters)
pub fn wake(key: usize) {
    WAITERS.wake_all(key);
}

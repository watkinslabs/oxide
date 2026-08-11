use super::{schedule, KeyedWaitQueues};

/// `false` is the reader FIFO, `true` the writer FIFO.
static WAITERS: KeyedWaitQueues<(usize, bool)> = KeyedWaitQueues::new();

/// Register current while VFS holds the rwsem registration gate. # C: O(log N)
pub fn park(key: usize) {
    park_reader(key);
}

/// Register a rwsem reader while its registration gate is held. # C: O(log N)
pub fn park_reader(key: usize) {
    WAITERS.prepare_interruptible((key, false));
}

/// Register a rwsem writer while its registration gate is held. # C: O(log N)
pub fn park_writer(key: usize) {
    WAITERS.prepare_interruptible((key, true));
}

/// Register a rwsem waiter in its reader or writer FIFO. # C: O(log N)
pub fn park_rwsem(key: usize, writer: bool) {
    if writer { park_writer(key); } else { park_reader(key); }
}

/// Schedule after VFS registered current and dropped the rwsem gate. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller is parked on an inode wait list and holds no rwsem gate.
    unsafe { schedule(); }
}

/// Wake all tasks waiting for this inode state transition. # C: O(N_waiters)
pub fn wake(key: usize) {
    WAITERS.wake_all((key, false));
    WAITERS.wake_all((key, true));
}

/// Wake a rwsem's next writer, or its blocked reader batch when no writer
/// remains. The rwsem holds its registration gate across this choice.
/// # C: O(N_readers) in a reader phase, O(1) in a writer phase
pub fn wake_rwsem(key: usize, writers_waiting: bool) {
    if writers_waiting { WAITERS.wake_one((key, true)); }
    else { WAITERS.wake_all((key, false)); }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_KEY: usize = usize::MAX;

    #[test]
    fn wake_prunes_an_empty_keyed_wait_list() {
        let before = WAITERS.queue_count();
        WAITERS.prepare((EMPTY_KEY, false));
        wake(EMPTY_KEY);
        assert_eq!(WAITERS.queue_count(), before);
    }
}

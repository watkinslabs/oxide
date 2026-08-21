use super::{schedule, KeyedWaitQueues};

/// `false` is the reader FIFO, `true` the writer FIFO.
static WAITERS: KeyedWaitQueues<(usize, bool)> = KeyedWaitQueues::new();

/// Register current while VFS holds the rwsem registration gate. # C: O(log N)
#[track_caller]
pub fn park(key: usize) {
    park_reader(key);
    crate::park_site::note(core::panic::Location::caller());
}

/// Register current for a signal/freezer-interruptible inode wait.
/// # C: O(log N)
#[track_caller]
pub fn park_interruptible(key: usize) {
    WAITERS.prepare_interruptible((key, false));
    crate::park_site::note(core::panic::Location::caller());
}

/// Register a rwsem reader while its registration gate is held. # C: O(log N)
#[track_caller]
pub fn park_reader(key: usize) {
    WAITERS.prepare((key, false));
    crate::park_site::note(core::panic::Location::caller());
}

/// Register a rwsem writer while its registration gate is held. # C: O(log N)
#[track_caller]
pub fn park_writer(key: usize) {
    WAITERS.prepare((key, true));
    crate::park_site::note(core::panic::Location::caller());
}

/// Register a rwsem waiter in its reader or writer FIFO. # C: O(log N)
#[track_caller]
pub fn park_rwsem(key: usize, writer: bool) {
    if writer { park_writer(key); } else { park_reader(key); }
    crate::park_site::note(core::panic::Location::caller());
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
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use crate::live::runqueue::{self, Runqueue};
    use crate::{SchedClass, Task, TaskState, WaitState};

    const EMPTY_KEY: usize = usize::MAX;

    #[test]
    fn wake_prunes_an_empty_keyed_wait_list() {
        let before = WAITERS.queue_count();
        WAITERS.prepare((EMPTY_KEY, false));
        wake(EMPTY_KEY);
        assert_eq!(WAITERS.queue_count(), before);
    }

    #[test]
    fn file_lock_park_publishes_interruptible_and_admits_a_fake_freezer_wake() {
        const KEY: usize = usize::MAX - 1;
        let task = Arc::new(Task::new(0x72f1, "file-lock-wait",
            SchedClass::Normal { weight: 1024 }));
        task.kernel_thread.store(false, Ordering::Release);
        let idle = Arc::new(Task::new(0xffff_72f1, "idle", SchedClass::Idle));
        // SAFETY: hosted test owns CPU0's transient runqueue for this focused
        // publication control and uninstalls it before returning.
        unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
        let rq = runqueue::global().expect("just installed");
        // SAFETY: hosted model owns this runqueue; no context switch races it.
        let _ = unsafe { rq.swap_current(Arc::clone(&task)) };

        park_interruptible(KEY);
        assert_eq!(task.state(), TaskState::Sleeping);
        assert_eq!(task.sleep_wait_state(), WaitState::Interruptible);
        task.freeze_reasons.store(crate::freeze_reason::SLEEP, Ordering::Release);
        assert_eq!(task.deliverable_signals(), 0);
        assert!(crate::signal_pending_state(&task, task.sleep_wait_state()),
            "the published wait state must admit the freezer's fake signal wake");

        task.set_state(TaskState::Runnable);
        wake(KEY);
        // SAFETY: paired with this test's isolated install above.
        unsafe { runqueue::uninstall_global(); }
    }
}

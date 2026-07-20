use alloc::sync::Arc;

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList};

struct State {
    pending: usize,
    error: Option<BlockError>,
}

/// Completion join for a writeback command. The count is reserved before a
/// request is submitted, so an inline legacy completion and an IRQ completion
/// have identical accounting and neither can be lost.
pub(super) struct Batch {
    state: Spinlock<State, TaskList>,
    #[cfg(target_os = "oxide-kernel")]
    waiters: sched::live::WaitList,
}

impl Batch {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Spinlock::new(State { pending: 0, error: None }),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
        })
    }

    pub(super) fn reserve(&self) { self.state.lock().pending += 1; }

    pub(super) fn complete(&self, result: KResult<()>) {
        let wake = {
            let mut state = self.state.lock();
            if state.error.is_none() { state.error = result.err(); }
            state.pending -= 1;
            state.pending == 0
        };
        #[cfg(target_os = "oxide-kernel")]
        if wake { self.waiters.wake_all(); }
        #[cfg(not(target_os = "oxide-kernel"))]
        let _ = wake;
    }

    pub(super) fn wait(&self) -> KResult<()> {
        loop {
            let state = self.state.lock();
            if state.pending == 0 { return state.error.map_or(Ok(()), Err); }
            #[cfg(target_os = "oxide-kernel")]
            {
                // SAFETY: the completion path needs this state lock before it
                // can wake us; publishing first and dropping it before
                // schedule closes the completion-before-sleep race.
                unsafe { self.waiters.park(); }
                drop(state);
                // SAFETY: the wait list publishes this task before the state lock drops,
                // and scheduling transfers execution until that published waiter wakes.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                drop(state);
                return Err(BlockError::Eagain);
            }
        }
    }
}

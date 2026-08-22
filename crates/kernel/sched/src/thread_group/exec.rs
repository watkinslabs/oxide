use alloc::sync::Arc;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use crate::task::WaitOutcome;
use crate::Task;

use super::{release_reference, ExitDisposition, ThreadGroup};

impl ThreadGroup {
    /// True after every exec sibling completed switched-out retirement. # C: O(1)
    pub fn exec_siblings_gone(&self) -> bool { self.state.lock().live == 1 }

    /// Wait killably until no sibling can still execute against the outgoing mm.
    /// # SAFETY: process context on the running exec task with no scheduler lock held.
    /// # C: O(N_wakeups)
    /// # Sleeps: yes
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait_exec_siblings(&self) -> WaitOutcome {
        // SAFETY: the group owns this wait list for its lifetime; the caller
        // guarantees process context and holds no lock needed by exit.
        unsafe { crate::live::wait_event_killable(&self.exec_wait, || self.exec_siblings_gone()) }
    }

    /// Retire a switched-out task exactly once and delay an early leader until
    /// the final sibling exits. # C: O(N_subscribers)
    pub fn finish_exit(&self, task: Arc<Task>) -> ExitDisposition {
        if !task.pid.claim_exit_retirement() {
            release_reference(task);
            return ExitDisposition::AlreadyRetired;
        }
        let disposition = if task.pid.is_group_leader() {
            let waitable = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 { true }
                else { state.pending_leader = Some(Arc::clone(&task)); false }
            };
            if waitable {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(task)
            } else { ExitDisposition::DeferredLeader }
        } else {
            crate::registry::mark_reaped(&task);
            let pending_leader = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 { state.pending_leader.take() } else { None }
            };
            release_reference(task);
            if let Some(leader) = pending_leader {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(leader)
            } else { ExitDisposition::ReleasedThread }
        };
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.exec_wait.wake_all();
        disposition
    }
}

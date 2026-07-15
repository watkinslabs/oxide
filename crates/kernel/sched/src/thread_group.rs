use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use crate::pid::PidIdentity;
use crate::Task;

/// Result of retiring one task from its thread group after context handoff.
pub enum ExitDisposition {
    AlreadyRetired,
    ReleasedThread,
    DeferredLeader,
    WaitableLeader(Arc<Task>),
}

/// Stable thread-group owner shared by all member tasks.
pub struct ThreadGroup {
    leader: Arc<PidIdentity>,
    state: Spinlock<ThreadGroupState, TaskListClass>,
    user_ns: AtomicU64,
    system_ns: AtomicU64,
}

struct ThreadGroupState {
    live: u32,
    pending_leader: Option<Arc<Task>>,
}

impl ThreadGroup {
    /// Create a one-task group around its leader PID identity. # C: O(1)
    pub fn new(leader: Arc<PidIdentity>) -> Self {
        Self {
            leader,
            state: Spinlock::new(ThreadGroupState { live: 1, pending_leader: None }),
            user_ns: AtomicU64::new(0),
            system_ns: AtomicU64::new(0),
        }
    }

    /// Commit one fully initialized clone-thread member. # C: O(1)
    pub fn commit_member(&self) {
        self.state.lock().live += 1;
    }

    /// Whether exactly one live task remains in this thread group. # C: O(1)
    pub fn is_single_member(&self) -> bool { self.state.lock().live == 1 }

    /// Charge aggregate process CPU time from the per-CPU accounting tick.
    /// # C: O(1)
    /// # Ctx: timer IRQ
    pub fn charge_cpu(&self, user: bool, delta_ns: u64) {
        if user { self.user_ns.fetch_add(delta_ns, Ordering::Relaxed); }
        else { self.system_ns.fetch_add(delta_ns, Ordering::Relaxed); }
    }

    /// Aggregate process CPU time without walking the thread registry. # C: O(1)
    pub fn cpu_sample(&self) -> (u64, u64) {
        (self.user_ns.load(Ordering::Acquire), self.system_ns.load(Ordering::Acquire))
    }

    /// Retire a switched-out task exactly once and delay an early leader until
    /// the final sibling exits. # C: O(N_subscribers)
    pub fn finish_exit(&self, task: Arc<Task>) -> ExitDisposition {
        if !task.pid.claim_exit_retirement() {
            return ExitDisposition::AlreadyRetired;
        }
        if task.pid.is_group_leader() {
            let waitable = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 {
                    true
                } else {
                    state.pending_leader = Some(Arc::clone(&task));
                    false
                }
            };
            if waitable {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(task)
            } else {
                ExitDisposition::DeferredLeader
            }
        } else {
            crate::registry::mark_reaped(&task);
            let pending_leader = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 { state.pending_leader.take() } else { None }
            };
            if let Some(leader) = pending_leader {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(leader)
            } else {
                ExitDisposition::ReleasedThread
            }
        }
    }
}

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::pid::PidIdentity;
use crate::Task;

use super::REG;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidfdKind {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidfdAcquireError {
    NotFound,
    NotLeader,
}

/// Acquire an exact visible identity in `namespace` and pin it before reap
/// publication. # C: O(N_tasks)
/// # Lk: REG.lock
pub fn acquire_pidfd(
    namespace: u64,
    pid: u32,
    kind: PidfdKind,
) -> Result<Arc<PidIdentity>, PidfdAcquireError> {
    let registry = REG.lock();
    for (_, weak) in registry.iter() {
        let Some(task) = weak.upgrade() else {
            continue;
        };
        if task.reaped.load(Ordering::Acquire)
            || task.pid_ns.load(Ordering::Acquire) != namespace
            || task.vtid.load(Ordering::Acquire) != pid
        {
            continue;
        }
        if kind == PidfdKind::Process && task.vtgid.load(Ordering::Acquire) != pid {
            return Err(PidfdAcquireError::NotLeader);
        }
        return Ok(Arc::clone(&task.pid));
    }
    Err(PidfdAcquireError::NotFound)
}

/// Publish `release_task`; acquisition either observes this or already owns
/// the canonical PID identity. # C: O(N_subscribers)
/// # Lk: none
pub fn mark_reaped(task: &Task) {
    task.reaped.store(true, Ordering::Release);
    task.pid.detach(task);
}

/// Test readiness from the retained PID identity. # C: O(1)
pub fn pidfd_exit_ready(target: &PidIdentity) -> bool {
    target.exit_ready()
}

/// Publish exact-thread exit before the scheduler retires group membership.
/// # C: O(N_subscribers)
/// # Lk: none
pub fn publish_pidfd_exit(target: &Task) {
    target.pid.publish_task_exit();
}

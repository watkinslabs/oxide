use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::pid::PidIdentity;
use crate::Task;
use namespace_identity::NamespaceRef;

use super::snapshot_tasks_for_pid_lookup;

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

/// Acquire an exact identity visible from one retained caller namespace.
/// The returned pid identity stores only weak namespace mappings. # C: O(N_tasks)
pub fn acquire_pidfd_in_namespace(
    namespace: &NamespaceRef,
    pid: u32,
    kind: PidfdKind,
) -> Result<Arc<PidIdentity>, PidfdAcquireError> {
    let mut nonleader = false;
    for task in snapshot_tasks_for_pid_lookup() {
        if task.reaped.load(Ordering::Acquire) || task.pid.visible_tid(namespace) != Some(pid) {
            continue;
        }
        if kind == PidfdKind::Process && !task.pid.is_group_leader() {
            nonleader = true;
            continue;
        }
        return Ok(Arc::clone(&task.pid));
    }
    if nonleader { Err(PidfdAcquireError::NotLeader) } else { Err(PidfdAcquireError::NotFound) }
}

/// Publish Linux `release_task`: remove the task from the process table while
/// preserving its independently retained PID identity for already-open pidfds.
/// A reaped task can remain strongly owned by a pidfd or thread-group state,
/// so merely waiting for the registry's `Weak` entry to decay retains stale
/// `/proc` scan work indefinitely. # C: O(N_tasks + N_subscribers)
/// # Lk: REG
pub fn mark_reaped(task: &Task) {
    task.reaped.store(true, Ordering::Release);
    task.pid.detach(task);
    super::REG.lock().retain(|(tid, _)| *tid != task.tid);
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

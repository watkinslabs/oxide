use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::pid::PidIdentity;
use crate::Task;
use namespace_identity::NamespaceRef;

use super::core::{RegIrq, REG};
use super::snapshot::snapshot_tasks_for_pid_lookup;

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
/// `/proc` scan work indefinitely. # C: O(log N_tasks)
/// # Lk: REG
pub fn mark_reaped(task: &Task) {
    task.reaped.store(true, Ordering::Release);
    task.pid.detach(task);
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.by_tid.remove(&task.tid);
    // Drop the vpid hint too if it currently names this exact (now-reaped)
    // task or is already dead — pure hygiene, `vpid.rs::lookup_by_vpid`
    // re-validates `reaped` on every hit regardless, so leaving it would
    // still be correct, just a wasted hint slot until the next insert/lookup
    // heals it.
    let vpid = task.vtgid.load(Ordering::Acquire);
    if vpid != 0 {
        let stale = g.vpid_hint.get(&vpid)
            .map_or(false, |w| w.upgrade().map_or(true, |t| t.tid == task.tid));
        if stale { g.vpid_hint.remove(&vpid); }
    }
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

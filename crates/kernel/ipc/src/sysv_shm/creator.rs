// The `shm_creator` back-reference and `exit_shm`.
//
// A segment records the TASK that created it, as a `Weak<Task>` — the task
// identity itself, never its tid. Tids are recycled, so a tid-keyed creator
// table would hand a freshly forked task the segments of a long-dead one and
// let it destroy them; the weak reference cannot be confused that way and
// keeps no segment alive past its creator.
//
// The back-reference doubles as the orphan marker read by
// `rmid_forced::destroy_orphaned`: `Some` means the creator has not exited
// yet, `None` means it has and the segment is a sweep candidate. That is one
// piece of state with one owner (the segment), not a per-task list that could
// disagree with it.

use alloc::sync::Weak;
use core::sync::atomic::Ordering;

use sched::Task;

use super::rules::exit_shm_destroys;
use super::{rmid_forced, REG};

/// The creating task, for a new segment's `creator` slot. `None` outside task
/// context (boot, hosted tests without a registry): such a segment is orphaned
/// from birth, exactly like one whose creator has already exited.
/// # C: O(log N_tasks)
pub(super) fn current_creator() -> Option<Weak<Task>> {
    let cur = sched::current()?;
    sched::registry::lookup(cur.tid).as_ref().map(alloc::sync::Arc::downgrade)
}

/// Whether `weak` names exactly `task`. Upgrading first is what makes the
/// pointer comparison sound: a dead `Weak` keeps returning the address of a
/// freed allocation, which a later task could be allocated at.
/// # C: O(1)
fn names(weak: &Weak<Task>, task: &Task) -> bool {
    match weak.upgrade() {
        Some(arc) => core::ptr::eq(alloc::sync::Arc::as_ptr(&arc), task as *const Task),
        None => false,
    }
}

/// Linux `exit_shm(task)`, run from `do_exit` for every dying task.
///
/// Every segment this task created is unlinked from it (the creator slot is
/// cleared, marking the segment orphaned) and, when the namespace has
/// `shm_rmid_forced` set, destroyed if nothing is attached. Without the
/// sysctl the segment only becomes an orphan, so a later
/// `sysctl -w kernel.shm_rmid_forced=1` can still reclaim it — that deferred
/// sweep is the reason the unlink happens unconditionally.
/// # C: O(N_segments)
/// # Lk: takes the shm registry lock; callers hold no IPC lock
pub fn exit_shm(task: &Task) {
    let doomed = {
        let mut g = REG.segs.lock();
        let mut out = alloc::vec::Vec::new();
        let mut i = 0;
        while i < g.len() {
            let mine = {
                let mut slot = g[i].creator.lock();
                match slot.as_ref() {
                    Some(w) if names(w, task) => { *slot = None; true }
                    _ => false,
                }
            };
            if !mine { i += 1; continue; }
            let seg = &g[i];
            let forced = rmid_forced::is_forced(seg.ns);
            let nattch = seg.nattch.load(Ordering::Acquire);
            if exit_shm_destroys(nattch, forced, seg.mode) { out.push(g.remove(i)); } else { i += 1; }
        }
        out
    };
    // Backing teardown runs with the registry lock dropped (`release_detached`).
    drop(doomed);
}

#[cfg(test)]
mod tests;

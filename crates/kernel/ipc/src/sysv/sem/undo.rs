//! `SEM_UNDO` bookkeeping — Linux `struct sem_undo` / `struct sem_undo_list`
//! and `exit_sem` (`ipc/sem.c`).
//!
//! Keying: Linux keys the undo list on `task->sysvsem.undo_list`, shared by
//! `CLONE_SYSVSEM` and refcounted, so all threads of one process share it and a
//! plain `fork()` child starts empty. glibc always passes `CLONE_SYSVSEM` from
//! `pthread_create` and never from `fork`, so keying on the thread-group id
//! reproduces that exactly for every real caller. It is NOT exact for a
//! hand-rolled `clone(CLONE_SYSVSEM)` WITHOUT `CLONE_THREAD` — such a child
//! gets its own empty list here where Linux would share the parent's.
//!
//! Lock order: `model::REG` → `SemSet::state` → `UNDO`.

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as SemLockClass};
use syscall::errno::Errno;

use super::model::{self, clamp_semval};

/// Linux `struct sem_undo`: one per (process, set) pair. Removing the entry is
/// this kernel's form of Linux's `un->semid = -1` invalidation — a later
/// `exit_sem` simply finds nothing to apply.
struct UndoEntry {
    ns: NamespaceId,
    semid: i32,
    /// `semadj[]`. Linux stores `short`; the range gate below keeps every value
    /// inside `[-(SEMAEM+1), SEMAEM]`, which is exactly `short`.
    semadj: Vec<i32>,
}

/// Linux `struct sem_undo_list`, one per thread group.
struct ProcUndo {
    tgid: u32,
    entries: Vec<UndoEntry>,
}

static UNDO: Spinlock<Vec<ProcUndo>, SemLockClass> = Spinlock::new(Vec::new());

/// Linux `find_alloc_undo`: get, or create zeroed, this process's adjustment
/// array for `semid`. Called before the set lock is taken, as Linux does.
/// # C: O(N_entries + nsems)
pub fn find_alloc(tgid: u32, ns: NamespaceId, semid: i32, nsems: usize) -> Result<(), Errno> {
    let mut g = UNDO.lock();
    if let Some(p) = g.iter_mut().find(|p| p.tgid == tgid) {
        if let Some(e) = p.entries.iter_mut().find(|e| e.ns == ns && e.semid == semid) {
            // An id is only ever reused with a fresh sequence half, and
            // `invalidate_set` drops the entry on removal, so a surviving entry
            // always describes THIS set. Widening defensively keeps the
            // `semadj[sem_num]` indexing in `perform_atomic_semop` — already
            // bounded by the caller's `EFBIG` check against `nsems` — in range
            // for every reachable state.
            if e.semadj.len() < nsems {
                if e.semadj.try_reserve(nsems - e.semadj.len()).is_err() {
                    return Err(Errno::Enomem);
                }
                e.semadj.resize(nsems, 0);
            }
            return Ok(());
        }
    }
    let mut semadj: Vec<i32> = Vec::new();
    if semadj.try_reserve_exact(nsems).is_err() { return Err(Errno::Enomem); }
    for _ in 0..nsems { semadj.push(0); }
    let entry = UndoEntry { ns, semid, semadj };
    match g.iter_mut().find(|p| p.tgid == tgid) {
        Some(p) => {
            if p.entries.try_reserve(1).is_err() { return Err(Errno::Enomem); }
            p.entries.push(entry);
        }
        None => {
            if g.try_reserve(1).is_err() { return Err(Errno::Enomem); }
            let mut entries = Vec::new();
            entries.push(entry);
            g.push(ProcUndo { tgid, entries });
        }
    }
    Ok(())
}

/// Run `f` over this process's adjustment array for `semid`, which the caller
/// must already hold the set lock for. `None` is passed when no entry exists —
/// either the batch carries no `SEM_UNDO`, or an `IPC_RMID` invalidated it
/// (Linux's `un->semid == -1`), which the caller turns into `EIDRM`.
/// # C: O(N_entries)
pub fn with_semadj<R>(tgid: u32, ns: NamespaceId, semid: i32,
                      f: impl FnOnce(Option<&mut [i32]>) -> R) -> R
{
    let mut g = UNDO.lock();
    let slot = g.iter_mut()
        .find(|p| p.tgid == tgid)
        .and_then(|p| p.entries.iter_mut().find(|e| e.ns == ns && e.semid == semid));
    match slot {
        Some(e) => f(Some(&mut e.semadj[..])),
        None => f(None),
    }
}

/// Whether this process still has a live entry for `semid`. # C: O(N_entries)
pub fn has_entry(tgid: u32, ns: NamespaceId, semid: i32) -> bool {
    UNDO.lock().iter()
        .find(|p| p.tgid == tgid)
        .is_some_and(|p| p.entries.iter().any(|e| e.ns == ns && e.semid == semid))
}

/// Linux `SETVAL`/`SETALL`: an explicit value assignment makes every process's
/// pending adjustment for that semaphore meaningless, so they are zeroed.
/// `semnum` of `None` zeroes the whole array (`SETALL`). # C: O(N_procs × N_entries)
pub fn clear_adjustments(ns: NamespaceId, semid: i32, semnum: Option<usize>) {
    let mut g = UNDO.lock();
    for p in g.iter_mut() {
        for e in p.entries.iter_mut().filter(|e| e.ns == ns && e.semid == semid) {
            match semnum {
                Some(i) => if let Some(v) = e.semadj.get_mut(i) { *v = 0; },
                None => for v in e.semadj.iter_mut() { *v = 0; },
            }
        }
    }
}

/// Linux `freeary`'s undo walk (`un->semid = -1`): drop every entry naming this
/// set so a later `exit_sem` cannot apply adjustments to a set that has been
/// removed — or to a different set that later takes the same id.
/// # C: O(N_procs × N_entries)
pub fn invalidate_set(ns: NamespaceId, semid: i32) {
    let mut g = UNDO.lock();
    for p in g.iter_mut() { p.entries.retain(|e| !(e.ns == ns && e.semid == semid)); }
    g.retain(|p| !p.entries.is_empty());
}

/// Linux `exit_sem`: apply every registered adjustment for the exiting process,
/// clamped to `[0, SEMVMX]` at BOTH ends, stamp `sempid`, wake anyone the new
/// values may have unblocked, then drop the process's list. Idempotent — a
/// second call for the same thread group finds nothing.
/// # C: O(N_entries × nsems)
pub fn exit_sem(tgid: u32) {
    let entries = {
        let mut g = UNDO.lock();
        match g.iter().position(|p| p.tgid == tgid) {
            None => return,
            Some(i) => g.swap_remove(i).entries,
        }
    };
    for e in entries {
        let Some(set) = model::lookup_checked(e.ns, e.semid) else { continue };
        let mut st = set.state.lock();
        if st.removed { continue; }
        let n = core::cmp::min(st.sems.len(), e.semadj.len());
        for i in 0..n {
            if e.semadj[i] == 0 { continue; }
            st.sems[i].val = clamp_semval(st.sems[i].val.saturating_add(e.semadj[i]));
            st.sems[i].pid = tgid;
        }
        set.commit_wake(&mut st);
    }
}

#[cfg(test)]
pub(super) fn reset_for_test() { UNDO.lock().clear(); }

#[cfg(test)]
pub(super) fn semadj_snapshot(tgid: u32, ns: NamespaceId, semid: i32) -> Option<Vec<i32>> {
    UNDO.lock().iter()
        .find(|p| p.tgid == tgid)
        .and_then(|p| p.entries.iter().find(|e| e.ns == ns && e.semid == semid))
        .map(|e| e.semadj.clone())
}

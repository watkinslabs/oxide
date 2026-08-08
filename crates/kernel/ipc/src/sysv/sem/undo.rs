//! `SEM_UNDO` bookkeeping — Linux `struct sem_undo` / `struct sem_undo_list`
//! and `exit_sem`.
//!
//! OWNERSHIP. The adjustment list is REFCOUNTED and shared by HANDLE, keyed on
//! `Task::sysvsem_undo`. That is what `CLONE_SYSVSEM` shares, and the flag is
//! independent of `CLONE_THREAD`: threads of one process share a list because
//! `pthread_create` passes the flag, not because they share a thread group, and
//! a `clone(CLONE_SYSVSEM)` child WITHOUT `CLONE_THREAD` shares its parent's
//! list too. The list dies — and its adjustments are applied — when the LAST
//! task holding a handle drops it.
//!
//! The handle lives on the task because it is a property of the task; the list,
//! its refcount and its entries live here because they are semaphore state.
//! Every operation therefore takes the caller's handle slot rather than reading
//! any global "current task", which is also what makes the whole file
//! hosted-testable.
//!
//! Lock order: `model::REG` → `SemSet::state` → `UNDO`.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as SemLockClass};
use syscall::errno::Errno;

use super::model::{self, clamp_semval};

/// Identifies one `sem_undo_list`. `NO_UNDO_LIST` means the task has none —
/// Linux's NULL `undo_list` pointer.
pub type UndoId = u64;

/// A task holding no adjustment list.
pub const NO_UNDO_LIST: UndoId = 0;

/// Linux `struct sem_undo`: one per (list, set) pair. Removing the entry is
/// this kernel's form of Linux's `un->semid = -1` invalidation — a later
/// `exit_sem` simply finds nothing to apply.
struct UndoEntry {
    ns: NamespaceId,
    semid: i32,
    /// `semadj[]`. Linux stores `short`; the range gate below keeps every value
    /// inside `[-(SEMAEM+1), SEMAEM]`, which is exactly `short`.
    semadj: Vec<i32>,
}

/// Linux `struct sem_undo_list`: an id, a reference count, and the entries.
struct ProcUndo {
    id: UndoId,
    /// `refcount_t refcnt` — one per task holding this list's handle.
    refs: u32,
    entries: Vec<UndoEntry>,
}

static UNDO: Spinlock<Vec<ProcUndo>, SemLockClass> = Spinlock::new(Vec::new());

/// Source of list ids. Monotonic and never reused, so a stale handle can never
/// name a list that has since been recreated.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Linux `get_undo_list`: return the caller's list, allocating an empty one on
/// first use. Allocation is lazy because most processes never issue a
/// `SEM_UNDO` operation at all.
/// # C: O(1) amortised
pub fn get_undo_list(slot: &AtomicU64) -> Result<UndoId, Errno> {
    let existing = slot.load(Ordering::Acquire);
    if existing != NO_UNDO_LIST { return Ok(existing); }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut g = UNDO.lock();
    if g.try_reserve(1).is_err() { return Err(Errno::Enomem); }
    g.push(ProcUndo { id, refs: 1, entries: Vec::new() });
    slot.store(id, Ordering::Release);
    Ok(id)
}

/// Linux `copy_semundo`: with `CLONE_SYSVSEM` the child SHARES the parent's
/// list, taking a reference — which forces the parent's list into existence if
/// it had none. Without the flag the child starts with no list at all, so a
/// plain `fork()` inherits no adjustments.
/// # C: O(1) amortised
pub fn copy_semundo(sysvsem: bool, parent: &AtomicU64, child: &AtomicU64) -> Result<(), Errno> {
    if !sysvsem { child.store(NO_UNDO_LIST, Ordering::Release); return Ok(()); }
    let id = get_undo_list(parent)?;
    {
        let mut g = UNDO.lock();
        match g.iter_mut().find(|p| p.id == id) {
            Some(p) => p.refs += 1,
            // The list was torn down between the two locks; the child inherits
            // nothing rather than a handle naming no list.
            None => { child.store(NO_UNDO_LIST, Ordering::Release); return Ok(()); }
        }
    }
    child.store(id, Ordering::Release);
    Ok(())
}

/// Linux `find_alloc_undo`: get, or create zeroed, this list's adjustment array
/// for `semid`. Called before the set lock is taken, as Linux does.
/// # C: O(N_entries + nsems)
pub fn find_alloc(id: UndoId, ns: NamespaceId, semid: i32, nsems: usize) -> Result<(), Errno> {
    if id == NO_UNDO_LIST { return Err(Errno::Enomem); }
    let mut g = UNDO.lock();
    let Some(p) = g.iter_mut().find(|p| p.id == id) else { return Err(Errno::Enomem) };
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
    let mut semadj: Vec<i32> = Vec::new();
    if semadj.try_reserve_exact(nsems).is_err() { return Err(Errno::Enomem); }
    for _ in 0..nsems { semadj.push(0); }
    if p.entries.try_reserve(1).is_err() { return Err(Errno::Enomem); }
    p.entries.push(UndoEntry { ns, semid, semadj });
    Ok(())
}

/// Run `f` over this list's adjustment array for `semid`, which the caller
/// must already hold the set lock for. `None` is passed when no entry exists —
/// either the batch carries no `SEM_UNDO`, or an `IPC_RMID` invalidated it
/// (Linux's `un->semid == -1`), which the caller turns into `EIDRM`.
/// # C: O(N_entries)
pub fn with_semadj<R>(id: UndoId, ns: NamespaceId, semid: i32,
                      f: impl FnOnce(Option<&mut [i32]>) -> R) -> R
{
    let mut g = UNDO.lock();
    let slot = g.iter_mut()
        .find(|p| p.id == id)
        .and_then(|p| p.entries.iter_mut().find(|e| e.ns == ns && e.semid == semid));
    match slot {
        Some(e) => f(Some(&mut e.semadj[..])),
        None => f(None),
    }
}

/// Whether this list still has a live entry for `semid`. # C: O(N_entries)
pub fn has_entry(id: UndoId, ns: NamespaceId, semid: i32) -> bool {
    UNDO.lock().iter()
        .find(|p| p.id == id)
        .is_some_and(|p| p.entries.iter().any(|e| e.ns == ns && e.semid == semid))
}

/// Linux `SETVAL`/`SETALL`: an explicit value assignment makes every process's
/// pending adjustment for that semaphore meaningless, so they are zeroed.
/// `semnum` of `None` zeroes the whole array (`SETALL`). # C: O(N_lists × N_entries)
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
///
/// An emptied list is NOT dropped: a task still holds its handle and may
/// register new adjustments against it.
/// # C: O(N_lists × N_entries)
pub fn invalidate_set(ns: NamespaceId, semid: i32) {
    let mut g = UNDO.lock();
    for p in g.iter_mut() { p.entries.retain(|e| !(e.ns == ns && e.semid == semid)); }
}

/// Linux `exit_sem`: drop this task's handle on its adjustment list and, when
/// that was the LAST reference, apply every registered adjustment — clamped to
/// `[0, SEMVMX]` at BOTH ends — stamp `sempid`, and wake anyone the new values
/// may have unblocked.
///
/// A task sharing its list with a live sibling applies NOTHING: the adjustments
/// describe semaphores the survivors are still using, and releasing them early
/// is exactly the corruption `SEM_UNDO` exists to prevent. Idempotent — a task
/// whose handle is already clear owes nothing.
/// # C: O(N_entries × nsems) on the last reference, O(N_lists) otherwise
pub fn exit_sem(slot: &AtomicU64, tgid: u32) {
    let id = slot.swap(NO_UNDO_LIST, Ordering::AcqRel);
    if id == NO_UNDO_LIST { return; }
    let entries = {
        let mut g = UNDO.lock();
        let Some(i) = g.iter().position(|p| p.id == id) else { return };
        g[i].refs -= 1;
        if g[i].refs != 0 { return; }
        g.swap_remove(i).entries
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

/// How many tasks hold `id`. Zero for a list that no longer exists.
/// # C: O(N_lists)
pub fn refs_for_test(id: UndoId) -> u32 {
    UNDO.lock().iter().find(|p| p.id == id).map_or(0, |p| p.refs)
}

#[cfg(test)]
pub(super) fn reset_for_test() {
    UNDO.lock().clear();
    // The handle outlives the list it named, so clearing one without the other
    // leaves the stand-in task pointing at a list that no longer exists.
    if let Some(slot) = super::super::block::current_undo_slot() {
        slot.store(NO_UNDO_LIST, Ordering::Release);
    }
}

#[cfg(test)]
pub(super) fn semadj_snapshot(id: UndoId, ns: NamespaceId, semid: i32) -> Option<Vec<i32>> {
    UNDO.lock().iter()
        .find(|p| p.id == id)
        .and_then(|p| p.entries.iter().find(|e| e.ns == ns && e.semid == semid))
        .map(|e| e.semadj.clone())
}

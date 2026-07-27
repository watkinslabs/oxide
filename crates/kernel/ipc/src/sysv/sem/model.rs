//! `struct sem` / `struct sem_array` and the per-namespace registry
//! (`ipc/sem.c`).
//!
//! One `Spinlock` per set stands in for Linux's `sem_perm.lock` +
//! per-semaphore `sem->lock` pair. Linux splits them purely for SMP scaling
//! (`sem_lock`'s `use_global_lock` hysteresis); every user-visible rule —
//! batch atomicity, `sem_otime` update, wake ordering — is defined against the
//! whole array, so a single array lock is the same semantics with less
//! machinery. Nothing here is observable through the syscall ABI.
//!
//! Lock order: `REG` → `SemSet::state` → `undo::UNDO`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as SemLockClass};
use syscall::errno::Errno;

use super::super::block::{self, WaitList};
use super::super::ids::IpcIds;
use super::super::limits::{SEMMNI, SEMMNS, SEMVMX};
use super::super::perm::{IpcCred, IpcPerm};

/// Linux `struct sem`. `ncnt`/`zcnt` are maintained around the park instead of
/// being recomputed by walking pending queues (`count_semcnt`): the counted
/// quantity is identical — tasks whose FIRST unsatisfiable operation is on this
/// semaphore, split by "wants an increase" vs "wants zero".
pub struct Sem {
    /// `semval`.
    pub val: i32,
    /// `sempid` — thread-group id of the last mutator.
    pub pid: u32,
    /// `semncnt` — parked tasks blocked on `sem_op < 0` here.
    pub ncnt: u32,
    /// `semzcnt` — parked tasks blocked on `sem_op == 0` here.
    pub zcnt: u32,
}

impl Sem {
    /// # C: O(1)
    pub const fn new() -> Self { Self { val: 0, pid: 0, ncnt: 0, zcnt: 0 } }
}

/// Everything in a set that a `semop`/`semctl` mutates, under one lock.
pub struct SemState {
    pub sems: Vec<Sem>,
    /// `sem_otime` — wall seconds of the last committed `semop`. Linux keeps a
    /// per-semaphore copy and takes the max in `get_semotime` purely to avoid
    /// cache-line trashing; the max of the per-sem stamps IS this single
    /// last-commit stamp.
    pub otime: i64,
    /// `sem_ctime`.
    pub ctime: i64,
    /// B1427: set (under this lock) by `IPC_RMID` / namespace teardown before
    /// their one-shot `wake_all()`. The blocking branch of `semop` checks it
    /// under the SAME guard it publishes its park under — without that, a
    /// removal racing a waiter's park (or simply preceding it) has no way to
    /// tell a LATER parker "this set is already gone": the removal wakes once,
    /// at removal time, reaching only whoever is registered at that instant.
    /// A waiter whose park lands after that one-shot wake — the id is already
    /// out of the registry, so no future commit and no second `IPC_RMID` can
    /// ever wake it again — would sleep forever. Checking `removed` under this
    /// guard turns every ordering against a removal into an immediate `EIDRM`.
    pub removed: bool,
}

impl SemState {
    /// Charge or discharge the blocked-waiter tally for the semaphore a
    /// blocking op named. `sem_op == 0` is a wait-for-zero (`semzcnt`),
    /// anything negative is a wait-for-increase (`semncnt`); a positive
    /// `sem_op` never blocks. # C: O(1)
    pub fn count_blocked(&mut self, sem_num: usize, sem_op: i16, add: bool) {
        let Some(s) = self.sems.get_mut(sem_num) else { return };
        let slot = if sem_op == 0 { &mut s.zcnt } else { &mut s.ncnt };
        *slot = if add { slot.saturating_add(1) } else { slot.saturating_sub(1) };
    }
}

/// Linux `struct sem_array`.
pub struct SemSet {
    pub perm: IpcPerm,
    /// `sem_nsems`, fixed at creation.
    pub nsems: usize,
    /// Owning IPC namespace, so teardown and `exit_sem` address the right space.
    pub ns: NamespaceId,
    pub state: Spinlock<SemState, SemLockClass>,
    /// One queue for the whole set. Different waiters need different magnitudes,
    /// so every commit broadcasts and each waiter re-evaluates its own batch —
    /// Linux's `update_queue` does the re-evaluation on the waker's side, which
    /// is a scheduling optimisation, not a semantic difference.
    pub wait: WaitList,
}

impl SemSet {
    /// Wall-clock stamp + broadcast after a committed mutation. Called with
    /// `state` held: the waiter publishes its park under that same guard, so a
    /// wake can never land in an empty list while a waiter is mid-park.
    /// # C: O(N_waiters)
    pub fn commit_wake(&self, st: &mut SemState) {
        st.otime = block::real_seconds();
        self.wait.wake_all();
    }
}

/// Registry root: one identifier space per namespace plus Linux's
/// `ns->used_sems` accounting, under one lock so `SEMMNS` cannot be raced.
struct Registry {
    ids: IpcIds<SemSet>,
    used: Vec<(NamespaceId, usize)>,
}

static REG: Spinlock<Registry, SemLockClass> =
    Spinlock::new(Registry { ids: IpcIds::new(), used: Vec::new() });

impl Registry {
    fn used_sems(&self, ns: NamespaceId) -> usize {
        self.used.iter().find(|(n, _)| *n == ns).map(|(_, v)| *v).unwrap_or(0)
    }

    fn used_add(&mut self, ns: NamespaceId, n: usize) {
        match self.used.iter_mut().find(|(k, _)| *k == ns) {
            Some(slot) => slot.1 += n,
            None => self.used.push((ns, n)),
        }
    }

    fn used_sub(&mut self, ns: NamespaceId, n: usize) {
        if let Some(slot) = self.used.iter_mut().find(|(k, _)| *k == ns) {
            slot.1 = slot.1.saturating_sub(n);
        }
    }
}

/// Linux `sem_obtain_object_check` — id indexes the slot and its sequence half
/// must still match, so a stale id from a removed set is `EINVAL`.
/// # C: O(1)
pub fn lookup_checked(ns: NamespaceId, id: i32) -> Option<Arc<SemSet>> {
    REG.lock().ids.lookup_checked(ns, id, |s| s.perm.seq)
}

/// Linux `sem_obtain_object` — `SEM_STAT`/`SEM_STAT_ANY` address by raw index.
/// # C: O(1)
pub fn lookup_idx(ns: NamespaceId, idx: i32) -> Option<Arc<SemSet>> {
    REG.lock().ids.lookup_idx(ns, idx)
}

/// `(ids.in_use, used_sems, max_idx)` for `SEM_INFO`. # C: O(1)
pub fn info_counters(ns: NamespaceId) -> (usize, usize, i64) {
    let g = REG.lock();
    (g.ids.in_use(ns), g.used_sems(ns), g.ids.max_idx(ns))
}

/// Linux `newary` + `ipc_addid`: allocate the identifier, build the array and
/// publish it. Caller has already applied `ksys_semget`'s `nsems` bounds.
/// # C: O(nsems)
pub fn newary(ns: NamespaceId, key: i32, nsems: usize, semflg: i32, cred: &IpcCred)
    -> Result<i32, Errno>
{
    if nsems == 0 { return Err(Errno::Einval); }
    let mut sems: Vec<Sem> = Vec::new();
    if sems.try_reserve_exact(nsems).is_err() { return Err(Errno::Enomem); }
    for _ in 0..nsems { sems.push(Sem::new()); }

    let mut g = REG.lock();
    if g.used_sems(ns).saturating_add(nsems) > SEMMNS { return Err(Errno::Enospc); }
    let (idx, seq, id) = g.ids.alloc_idx(ns, SEMMNI).ok_or(Errno::Enospc)?;
    let now = block::real_seconds();
    let set = Arc::new(SemSet {
        perm: IpcPerm::new(key, id, seq, semflg, cred),
        nsems, ns,
        state: Spinlock::new(SemState { sems, otime: 0, ctime: now, removed: false }),
        wait: WaitList::new(),
    });
    g.ids.install(ns, idx, set);
    g.used_add(ns, nsems);
    Ok(id)
}

/// Linux `ipc_findkey`, applied to this class's key field. # C: O(max_idx)
pub fn lookup_key(ns: NamespaceId, key: i32) -> Option<Arc<SemSet>> {
    REG.lock().ids.lookup_key(ns, key, |s| s.perm.key)
}

/// Linux `freeary`: unpublish the id, release its `used_sems` charge, drop
/// every undo entry that names it, then flag + broadcast so parked callers
/// unwind with `EIDRM`. # C: O(N_undo + N_waiters)
pub fn freeary(set: &Arc<SemSet>) {
    {
        let mut g = REG.lock();
        g.ids.remove(set.ns, set.perm.id);
        g.used_sub(set.ns, set.nsems);
    }
    retire(set);
}

/// Flag-and-broadcast half of `freeary`, shared with namespace teardown. The
/// undo invalidation runs under `state` so an `exit_sem` cannot observe a
/// half-removed set and re-apply adjustments to it. # C: O(N_undo + N_waiters)
fn retire(set: &Arc<SemSet>) {
    let mut st = set.state.lock();
    st.removed = true;
    super::undo::invalidate_set(set.ns, set.perm.id);
    set.wait.wake_all();
}

/// Linux `sem_exit_ns` → `free_ipcs(ns, ..., freeary)`. # C: O(N_sets)
pub(crate) fn reap_namespace(ns: NamespaceId) {
    let sets = {
        let mut g = REG.lock();
        let sets = g.ids.drain_namespace(ns);
        g.used.retain(|(k, _)| *k != ns);
        sets
    };
    for set in sets { retire(&set); }
}

/// Clamp an exit-time undo adjustment the way Linux does — at both ends, not
/// just at zero (`exit_sem`'s "Linux caps the semaphore value, both at 0 and at
/// SEMVMX"). # C: O(1)
pub fn clamp_semval(v: i32) -> i32 {
    if v < 0 { 0 } else if v > SEMVMX { SEMVMX } else { v }
}

/// Resolve the calling task's IPC namespace. # C: O(1)
pub fn current_ns() -> Result<NamespaceId, Errno> {
    crate::ipc_namespace::current().map(|o| o.key()).map_err(|_| Errno::Einval)
}

#[cfg(test)]
pub(super) fn reset_for_test() {
    let mut g = REG.lock();
    let spaces: Vec<NamespaceId> = g.used.iter().map(|(k, _)| *k).collect();
    for ns in spaces { g.ids.drain_namespace(ns); }
    g.used.clear();
}

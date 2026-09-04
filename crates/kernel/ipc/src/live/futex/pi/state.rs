use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::cell::Cell;

use sched::Task;
use sched::pi_prio::{PiDonorKey, PiTreeNode, PiWaiterTree, donor_key_outranks};
use sync::{Guard, RtMutexWait, Spinlock};
use syscall::errno::Errno;

use super::super::core::Key;

/// A parked `FUTEX_LOCK_PI` waiter's grant slot. Written under [`PI_TABLE`],
/// read by the waiter after it drops the lock and parks, so the waiter can
/// tell an ownership handoff from a timeout or a signal without re-taking the
/// table lock in a context where it may already be gone.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum Grant {
    /// Still queued, not yet the owner.
    Pending = 0,
    /// This waiter is now the owner; the user word already names its TID.
    Owner = 1,
    /// Same as [`Grant::Owner`], plus the previous owner died holding the
    /// mutex, so the word carries `FUTEX_OWNER_DIED`.
    OwnerDied = 2,
    /// Owner exit could not access the user word; this waiter must fail, not park forever.
    OwnerFault = 3,
}

pub(crate) struct PiWaiter {
    pub(crate) task: Arc<Task>,
    pub(crate) tid: u32,
    wait_node: Pin<Box<PiTreeNode>>,
    owner_node: Pin<Box<PiTreeNode>>,
    /// A [`Grant`] discriminant. `Arc` so the waiter keeps its own handle after
    /// the entry has been removed from the table by whoever granted it.
    pub(crate) grant: Arc<AtomicU32>,
    /// Set for a `FUTEX_WAIT_REQUEUE_PI` waiter still parked on the SOURCE
    /// futex: it may only be moved to `requeue_target` by a `FUTEX_CMP_REQUEUE_PI`,
    /// never woken by a plain `FUTEX_WAKE`.
    pub(crate) requeue_target: Option<Key>,
}

impl PiWaiter {
    pub(crate) fn waiter_id(&self) -> u64 { self.wait_node.waiter_id() }
    pub(crate) fn key(&self) -> PiDonorKey { self.wait_node.key() }
    pub(crate) fn order(&self) -> u64 { self.wait_node.order() }
    pub(crate) fn lock_id(&self) -> u64 { self.wait_node.lock_id() }
    pub(crate) fn blocked_on(&self) -> sched::PiBlockedOn {
        sched::PiBlockedOn { lock_id: self.lock_id(), waiter_id: self.waiter_id(),
            node: self.wait_node.as_ref().get_ref() as *const PiTreeNode as usize }
    }
    pub(crate) fn wait_node(&mut self) -> Pin<&mut PiTreeNode> {
        self.wait_node.as_mut()
    }
    pub(crate) fn owner_node(&mut self) -> Pin<&mut PiTreeNode> {
        self.owner_node.as_mut()
    }
    pub(crate) fn owner_key(&self) -> PiDonorKey { self.owner_node.key() }
    pub(crate) fn owner_linked(&self) -> bool { self.owner_node.is_linked() }
    pub(crate) fn set_unlinked_key(&mut self, key: PiDonorKey, order: u64) {
        self.wait_node().set_key(key, order);
        self.owner_node().set_key(key, order);
    }
    pub(crate) fn revisit(&mut self, epoch: u64) -> bool {
        self.wait_node().revisit(epoch)
    }
}

/// Kernel-side ownership record for one PI futex — Linux `futex_pi_state`.
///
/// It exists only while the futex is contended: created by the first waiter,
/// destroyed when the last waiter leaves. While it exists, `FUTEX_WAITERS`
/// stays set in the user word, so every lock and unlock is forced through the
/// kernel and the two views cannot drift apart.
pub(crate) struct PiState {
    pub(crate) id: u64,
    pub(crate) key: Key,
    /// The user VA of the futex word. Kept alongside the key because a SHARED
    /// futex keys on the physical page, and the owner-death walk needs an
    /// address it can actually store through.
    pub(crate) uaddr: u64,
    /// `None` once the owner died without unlocking — the mutex is ownerless
    /// until the exit walk hands it to the top waiter.
    pub(crate) owner: Option<Arc<Task>>,
    pub(crate) owner_tid: u32,
    pub(crate) waiters: Vec<PiWaiter>,
    wait_tree: PiWaiterTree,
    owner_link: Option<u64>,
}

impl PiState {
    pub(crate) fn new(key: Key, uaddr: u64, owner_tid: u32,
                      owner: Option<Arc<Task>>, waiters: Vec<PiWaiter>) -> Self {
        let id = NEXT_STATE_ID.fetch_add(1, Ordering::Relaxed);
        let mut state = Self { id, key, uaddr, owner, owner_tid, waiters,
            wait_tree: PiWaiterTree::new(), owner_link: None };
        for index in 0..state.waiters.len() { state.bind_waiter(index); }
        state
    }

    fn bind_waiter(&mut self, index: usize) {
        let key = self.waiters[index].key();
        let order = self.waiters[index].order();
        self.waiters[index].wait_node().set_position(key, order, self.id);
        self.waiters[index].owner_node().set_position(key, order, self.id);
        if self.waiters[index].requeue_target.is_none() {
            self.wait_tree.insert(self.waiters[index].wait_node());
        }
    }

    pub(crate) fn push_waiter(&mut self, waiter: PiWaiter) {
        assert!(self.waiters.len() < self.waiters.capacity(),
            "prepared PI waiter capacity exhausted under RtMutexWait");
        self.waiters.push(waiter);
        self.bind_waiter(self.waiters.len() - 1);
    }

    /// Index of the waiter that must receive the mutex next: the highest
    /// scheduling class, ties broken by queue order (FIFO within a priority,
    /// matching what the rt runqueue does inside one priority bucket).
    /// # C: O(N_waiters) identity lookup after O(1) cached-tree selection
    pub(crate) fn top_waiter(&self) -> Option<usize> {
        let id = self.wait_tree.first()?.waiter_id();
        self.waiters.iter().position(|waiter| waiter.waiter_id() == id)
    }

    /// First source waiter after `after`, ordered by PI key then FIFO.
    /// Requeue waiters are not linked into `wait_tree` until transferred to
    /// the destination rtmutex, so source selection orders their stable keys
    /// directly without allocating under RtMutexWait.
    /// # C: O(N_waiters)
    pub(crate) fn source_waiter_after(&self, after: Option<(PiDonorKey, u64)>) -> Option<usize> {
        let before = |akey: PiDonorKey, aorder: u64, bkey: PiDonorKey, border: u64| {
            donor_key_outranks(akey, bkey)
                || (!donor_key_outranks(bkey, akey) && aorder < border)
        };
        let mut best = None;
        for (index, waiter) in self.waiters.iter().enumerate() {
            if after.is_some_and(|(key, order)| !before(key, order, waiter.key(), waiter.order())) {
                continue;
            }
            if best.is_none_or(|current: usize| before(waiter.key(), waiter.order(),
                self.waiters[current].key(), self.waiters[current].order())) {
                best = Some(index);
            }
        }
        best
    }

    pub(crate) fn unlink_waiter(&mut self, index: usize) {
        self.wait_tree.remove(self.waiters[index].wait_node());
    }

    pub(crate) fn rekey_waiter(&mut self, index: usize, key: PiDonorKey, order: u64) {
        self.wait_tree.remove(self.waiters[index].wait_node());
        self.waiters[index].wait_node().set_key(key, order);
        self.wait_tree.insert(self.waiters[index].wait_node());
    }

    pub(crate) fn remove_unlinked(&mut self, index: usize) -> PiWaiter {
        assert!(!self.waiters[index].wait_node.is_linked());
        assert!(!self.waiters[index].owner_linked());
        self.waiters.swap_remove(index)
    }

    pub(crate) fn owner_link(&self) -> Option<u64> { self.owner_link }
    pub(crate) fn set_owner_link(&mut self, link: Option<u64>) { self.owner_link = link; }
}

static NEXT_WAITER_ORDER: AtomicU64 = AtomicU64::new(0);
static NEXT_WAITER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STATE_ID: AtomicU64 = AtomicU64::new(1);
pub(crate) static NEXT_CHAIN_EPOCH: AtomicU64 = AtomicU64::new(1);

fn waiter_priority_changed(task: &Arc<Task>) {
    let mut tbl = PI_TABLE.lock();
    super::graph::rekey_blocked_task(&mut tbl, task);
}

const HOOK_UNINIT: u8 = 0;
const HOOK_INSTALLING: u8 = 1;
const HOOK_READY: u8 = 2;
static WAITER_CHANGE_HOOK_STATE: AtomicU8 = AtomicU8::new(HOOK_UNINIT);

fn ensure_hook_with<I: FnOnce(), W: FnMut()>(state: &AtomicU8, install: I, mut wait: W) {
    let mut install = Some(install);
    loop {
        match state.load(Ordering::Acquire) {
            HOOK_READY => return,
            HOOK_UNINIT if state.compare_exchange(HOOK_UNINIT, HOOK_INSTALLING,
                Ordering::AcqRel, Ordering::Acquire).is_ok() => {
                install.take().unwrap()();
                state.store(HOOK_READY, Ordering::Release);
                return;
            }
            HOOK_UNINIT | HOOK_INSTALLING => wait(),
            _ => panic!("invalid waiter-change hook state"),
        }
    }
}

fn ensure_waiter_change_hook() {
    ensure_hook_with(&WAITER_CHANGE_HOOK_STATE,
        || sched::live::pi_boost::install_waiter_change_hook(waiter_priority_changed),
        core::hint::spin_loop);
}

#[cfg(test)]
pub(crate) fn ensure_hook_for_test<I: FnOnce(), W: FnMut()>(state: &AtomicU8,
    install: I, wait: W) { ensure_hook_with(state, install, wait); }

/// Allocate and capture two stable waiter nodes before RtMutexWait. # C: O(allocation + N_cpus)
pub(crate) fn new_waiter(task: Arc<Task>, tid: u32, grant: Arc<AtomicU32>,
                         requeue_target: Option<Key>) -> PiWaiter {
    ensure_waiter_change_hook();
    let key = sched::live::pi_boost::donor_key(&task);
    let order = NEXT_WAITER_ORDER.fetch_add(1, Ordering::Relaxed);
    let waiter_id = NEXT_WAITER_ID.fetch_add(1, Ordering::Relaxed);
    PiWaiter { wait_node: Box::pin(PiTreeNode::new(&task, key, order, 0, waiter_id)),
        owner_node: Box::pin(PiTreeNode::new(&task, key, order, 0, waiter_id)),
        task, tid, grant, requeue_target }
}

pub(crate) fn next_waiter_order() -> u64 {
    NEXT_WAITER_ORDER.fetch_add(1, Ordering::Relaxed)
}

/// Every live PI state, keyed the same way the wait queues are.
///
/// This table is only the futex-key/state identity index and the common
/// rtmutex wait-lock domain. Waiter ordering lives in each state's intrusive
/// wait tree; owner-wide aggregation and blocked-on edges live under each
/// task's `TaskPiState`, so no donation path scans this table by owner.
/// Donor publication nests TaskPi then Runqueue under this lock; wakes are
/// collected and performed only after the guard is dropped.
pub(crate) struct PiTable(Spinlock<Vec<PiState>, RtMutexWait>);

#[cfg(test)]
std::thread_local! { static PI_TABLE_DEPTH: Cell<u32> = const { Cell::new(0) }; }

impl PiTable {
    const fn new() -> Self { Self(Spinlock::new(Vec::new())) }
    pub(crate) fn lock(&self) -> PiRawGuard<'_> {
        let guard = self.0.lock();
        #[cfg(test)]
        PI_TABLE_DEPTH.with(|depth| depth.set(depth.get() + 1));
        PiRawGuard { guard }
    }
}

pub(crate) struct PiRawGuard<'a> { guard: Guard<'a, Vec<PiState>, RtMutexWait> }
impl Deref for PiRawGuard<'_> {
    type Target = Vec<PiState>;
    fn deref(&self) -> &Self::Target { &self.guard }
}
impl DerefMut for PiRawGuard<'_> { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.guard } }
impl Drop for PiRawGuard<'_> {
    fn drop(&mut self) {
        #[cfg(test)]
        PI_TABLE_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

#[cfg(test)]
pub(crate) fn pi_table_held_for_test() -> bool {
    PI_TABLE_DEPTH.with(|depth| depth.get() != 0)
}

pub(crate) static PI_TABLE: PiTable = PiTable::new();

/// Guard retaining replaced Vec allocations until after RtMutexWait unlocks.
/// Field order is deliberate: Rust drops `guard` before the retired buffers,
/// so allocator deallocation cannot run in the spinlocked section.
pub(crate) struct PiTableGuard {
    guard: PiRawGuard<'static>,
    _retired_table: Option<Vec<PiState>>,
    _retired_waiters: Option<Vec<PiWaiter>>,
    new_waiters: Option<Vec<PiWaiter>>,
}

impl Deref for PiTableGuard {
    type Target = Vec<PiState>;
    fn deref(&self) -> &Self::Target { &self.guard }
}

impl DerefMut for PiTableGuard {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.guard }
}

impl PiTableGuard {
    pub(crate) fn take_new_waiters(&mut self) -> Vec<PiWaiter> {
        self.new_waiters.take().unwrap_or_default()
    }
}

#[cfg(test)]
static FAIL_RESERVE_VA: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn fail_next_reservation(uaddr: u64) {
    FAIL_RESERVE_VA.store(uaddr, Ordering::Release);
}

fn forced_reserve_failure(key: Key) -> bool {
    #[cfg(test)]
    if FAIL_RESERVE_VA.compare_exchange(key.va, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        return true;
    }
    #[cfg(not(test))]
    let _ = key;
    false
}

fn reserve_vec<T>(capacity: usize) -> Result<Vec<T>, Errno> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| Errno::Enomem)?;
    Ok(out)
}

/// Allocate one waiter slot before RtMutexWait. # C: O(allocation)
pub(crate) fn prepare_waiter_slot() -> Result<Vec<PiWaiter>, Errno> { reserve_vec(1) }

/// Lock the table with one allocation-free insertion available either in an
/// existing state's waiter array or in the state table itself. Any backing
/// replacement is allocated before reacquiring and revalidating the lock.
/// # C: O(S + allocation)
pub(crate) fn lock_for_waiter_insert(key: Key) -> Result<PiTableGuard, Errno> {
    if forced_reserve_failure(key) { return Err(Errno::Enomem); }
    loop {
        let guard = PI_TABLE.lock();
        let state = find(&guard, key);
        let table_need = usize::from(state.is_none() && guard.len() == guard.capacity());
        let waiter_need = state.filter(|&i| guard[i].waiters.len() == guard[i].waiters.capacity())
            .map(|i| guard[i].waiters.len() + 1);
        if table_need == 0 && waiter_need.is_none() {
            return Ok(PiTableGuard { guard, _retired_table: None,
                _retired_waiters: None, new_waiters: None });
        }
        let table_capacity = guard.len() + table_need;
        drop(guard);
        let mut table_spare = if table_need != 0 { Some(reserve_vec(table_capacity)?) } else { None };
        let mut waiter_spare = match waiter_need { Some(n) => Some(reserve_vec(n)?), None => None };

        let mut guard = PI_TABLE.lock();
        let state = find(&guard, key);
        let need_table_now = state.is_none() && guard.len() == guard.capacity();
        let need_waiter_now = state.filter(|&i| guard[i].waiters.len() == guard[i].waiters.capacity());
        if need_table_now && table_spare.as_ref().is_none_or(|v| v.capacity() < guard.len() + 1)
            || need_waiter_now.is_some_and(|i| waiter_spare.as_ref()
                .is_none_or(|v| v.capacity() < guard[i].waiters.len() + 1)) {
            drop(guard);
            continue;
        }
        let retired_table = if need_table_now {
            let mut old = core::mem::replace(&mut *guard, table_spare.take().unwrap());
            guard.append(&mut old);
            Some(old)
        } else { table_spare.take() };
        let retired_waiters = if let Some(i) = need_waiter_now {
            let mut old = core::mem::replace(&mut guard[i].waiters, waiter_spare.take().unwrap());
            guard[i].waiters.append(&mut old);
            Some(old)
        } else { waiter_spare.take() };
        return Ok(PiTableGuard { guard, _retired_table: retired_table,
            _retired_waiters: retired_waiters, new_waiters: None });
    }
}

/// Reserve destination state/waiter storage for a requeue before locking it.
/// # C: O(S + N_waiters + allocation)
pub(crate) fn lock_for_requeue(src: Key, dst: Key, limit: usize) -> Result<PiTableGuard, Errno> {
    if forced_reserve_failure(dst) { return Err(Errno::Enomem); }
    loop {
        let guard = PI_TABLE.lock();
        let moving = find(&guard, src).map(|i| guard[i].waiters.iter()
            .filter(|w| w.requeue_target == Some(dst)).take(limit).count()).unwrap_or(0);
        let dest = find(&guard, dst);
        let need_table = dest.is_none() && moving != 0 && guard.len() == guard.capacity();
        let need_new_waiters = dest.is_none() && moving != 0;
        let need_waiters = dest.map(|i| guard[i].waiters.len() + moving)
            .filter(|&needed| dest.is_some_and(|i| needed > guard[i].waiters.capacity()));
        if !need_table && !need_new_waiters && need_waiters.is_none() {
            return Ok(PiTableGuard { guard, _retired_table: None,
                _retired_waiters: None, new_waiters: None });
        }
        let table_capacity = guard.len() + usize::from(need_table);
        drop(guard);
        let mut table_spare = if need_table { Some(reserve_vec(table_capacity)?) } else { None };
        let mut waiter_spare = match need_waiters { Some(n) => Some(reserve_vec(n)?), None => None };
        let mut new_waiters = if need_new_waiters { Some(reserve_vec(moving)?) } else { None };

        let mut guard = PI_TABLE.lock();
        let moving = find(&guard, src).map(|i| guard[i].waiters.iter()
            .filter(|w| w.requeue_target == Some(dst)).take(limit).count()).unwrap_or(0);
        let dest = find(&guard, dst);
        let need_table_now = dest.is_none() && moving != 0 && guard.len() == guard.capacity();
        let need_new_now = dest.is_none() && moving != 0;
        let need_waiter_now = dest.filter(|&i| guard[i].waiters.len() + moving > guard[i].waiters.capacity());
        if need_table_now && table_spare.as_ref().is_none_or(|v| v.capacity() < guard.len() + 1)
            || need_new_now && new_waiters.as_ref().is_none_or(|v| v.capacity() < moving)
            || need_waiter_now.is_some_and(|i| waiter_spare.as_ref()
                .is_none_or(|v| v.capacity() < guard[i].waiters.len() + moving)) {
            drop(guard);
            continue;
        }
        let retired_table = if need_table_now {
            let mut old = core::mem::replace(&mut *guard, table_spare.take().unwrap());
            guard.append(&mut old);
            Some(old)
        } else { table_spare.take() };
        let retired_waiters = if let Some(i) = need_waiter_now {
            let mut old = core::mem::replace(&mut guard[i].waiters, waiter_spare.take().unwrap());
            guard[i].waiters.append(&mut old);
            Some(old)
        } else { waiter_spare.take().or_else(|| if need_new_now { None } else { new_waiters.take() }) };
        return Ok(PiTableGuard { guard, _retired_table: retired_table,
            _retired_waiters: retired_waiters, new_waiters });
    }
}

#[cfg(test)]
static REBOOST_GATE: std::sync::Mutex<Option<(u32, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>> =
    std::sync::Mutex::new(None);

/// Stop one publication while it still owns RtMutexWait, for race tests. # C: O(1)
#[cfg(test)]
pub(crate) fn arm_reboost_gate(owner_tid: u32, entered: Arc<std::sync::Barrier>,
                               release: Arc<std::sync::Barrier>) {
    *REBOOST_GATE.lock().unwrap() = Some((owner_tid, entered, release));
}

#[cfg(test)]
pub(crate) fn wait_reboost_gate(owner_tid: u32) {
    let gate = {
        let mut gate = REBOOST_GATE.lock().unwrap();
        if gate.as_ref().is_some_and(|g| g.0 == owner_tid) { gate.take() } else { None }
    };
    if let Some((_, entered, release)) = gate {
        entered.wait();
        release.wait();
    }
}

/// Index of the state for `key`, if any.
/// # C: O(S)
pub(crate) fn find(tbl: &[PiState], key: Key) -> Option<usize> {
    tbl.iter().position(|s| s.key == key)
}

pub(crate) fn find_id(tbl: &[PiState], id: u64) -> Option<usize> {
    tbl.iter().position(|state| state.id == id)
}

/// Publish an ownership grant while the PI transaction is still locked.
/// # C: O(1)
pub(crate) fn grant(w: &PiWaiter, grant: Grant) {
    w.grant.store(grant as u32, Ordering::Release);
}

/// Wake a waiter after every PI/task/rq lock has been released. # C: O(1)
pub(crate) fn wake(w: &PiWaiter) {
    // SAFETY: wake-site; the Arc in the waiter entry keeps the task alive
    // across the call, exactly as the non-PI `wake_key` path does.
    unsafe { sched::live::try_to_wake_up(w.task.clone()); }
}

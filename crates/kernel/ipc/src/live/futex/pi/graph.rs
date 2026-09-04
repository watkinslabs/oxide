//! Linux-shaped PI graph maintenance under `RtMutexWait -> TaskPi -> rq`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sched::Task;

use super::state::{NEXT_CHAIN_EPOCH, PiState, PiWaiter, find_id, next_waiter_order};

fn waiter_index(state: &PiState, waiter_id: u64) -> Option<usize> {
    state.waiters.iter().position(|waiter| waiter.waiter_id() == waiter_id)
}

fn blocked_on(task: &Task) -> Option<sched::PiBlockedOn> {
    task.pi_lock.lock().blocked_on()
}

fn set_blocked(waiter: &PiWaiter) {
    waiter.task.pi_lock.lock().set_blocked_on(waiter.blocked_on());
}

fn clear_blocked(waiter: &PiWaiter) {
    waiter.task.pi_lock.lock().clear_blocked_on(waiter.waiter_id());
}

/// Refresh an allocated but unlinked node at the exact wait-lock insertion point.
pub(crate) fn prepare_waiter(waiter: &mut PiWaiter) {
    let key = sched::live::pi_boost::donor_key(&waiter.task);
    waiter.set_unlinked_key(key, next_waiter_order());
}

fn owner_tree_needs_sync(state: &PiState, desired: Option<u64>) -> bool {
    if state.owner_link() != desired { return true; }
    let Some(waiter_id) = desired else { return false };
    let index = waiter_index(state, waiter_id).expect("owner PI node lost its waiter");
    state.waiters[index].owner_key() != state.waiters[index].key()
}

/// Make the owner's task-local PI tree contain exactly this lock's top waiter.
fn sync_owner_tree(state: &mut PiState) -> Option<(Arc<Task>, bool)> {
    let owner = state.owner.clone()?;
    let desired = state.top_waiter().map(|index| state.waiters[index].waiter_id());
    if !owner_tree_needs_sync(state, desired) { return Some((owner, false)); }
    let old = state.owner_link();
    let lock_id = state.id;
    let changed = sched::live::pi_boost::update_owner_waiters(&owner, |pi| {
        if let Some(waiter_id) = old {
            let index = waiter_index(state, waiter_id).expect("linked owner waiter vanished");
            pi.remove_waiter(state.waiters[index].owner_node());
        }
        if let Some(waiter_id) = desired {
            let index = waiter_index(state, waiter_id).expect("top waiter vanished");
            let key = state.waiters[index].key();
            let order = state.waiters[index].order();
            state.waiters[index].owner_node().set_position(key, order, lock_id);
            pi.insert_waiter(state.waiters[index].owner_node());
        }
    });
    state.set_owner_link(desired);
    Some((owner, changed))
}

/// Remove this lock's top waiter from its old owner's task-local PI tree.
pub(crate) fn detach_owner(state: &mut PiState) -> Option<(Arc<Task>, bool)> {
    let owner = state.owner.clone()?;
    let Some(waiter_id) = state.owner_link() else { return Some((owner, false)); };
    let changed = sched::live::pi_boost::update_owner_waiters(&owner, |pi| {
        let index = waiter_index(state, waiter_id).expect("linked owner waiter vanished");
        pi.remove_waiter(state.waiters[index].owner_node());
    });
    state.set_owner_link(None);
    Some((owner, changed))
}

/// Propagate one changed owner's effective key through its single blocked-on
/// edge. A per-waiter epoch detects corruption without a finite depth bound.
pub(crate) fn propagate_from(table: &mut [PiState], owner: &Arc<Task>) {
    let epoch = NEXT_CHAIN_EPOCH.fetch_add(1, Ordering::Relaxed);
    let mut task = Arc::clone(owner);
    loop {
        #[cfg(test)]
        super::state::wait_reboost_gate(task.tid);
        let Some(blocked) = blocked_on(&task) else { return };
        let Some(state_index) = find_id(table, blocked.lock_id) else { return };
        let Some(index) = waiter_index(&table[state_index], blocked.waiter_id) else { return };
        if table[state_index].waiters[index].revisit(epoch) { return; }
        debug_assert_eq!(blocked.node,
            table[state_index].waiters[index].blocked_on().node);
        let key = sched::live::pi_boost::donor_key(&task);
        if table[state_index].waiters[index].key() == key { return; }
        table[state_index].rekey_waiter(index, key, next_waiter_order());
        let Some((parent, changed)) = sync_owner_tree(&mut table[state_index]) else { return };
        if !changed { return; }
        task = parent;
    }
}

pub(crate) fn enqueue(table: &mut [PiState], state_index: usize, waiter: PiWaiter) {
    table[state_index].push_waiter(waiter);
    let index = table[state_index].waiters.len() - 1;
    set_blocked(&table[state_index].waiters[index]);
    if let Some((owner, true)) = sync_owner_tree(&mut table[state_index]) {
        propagate_from(table, &owner);
    }
}

pub(crate) fn remove(table: &mut [PiState], state_index: usize, waiter_index: usize) -> PiWaiter {
    if table[state_index].waiters[waiter_index].requeue_target.is_some() {
        return table[state_index].remove_unlinked(waiter_index);
    }
    table[state_index].unlink_waiter(waiter_index);
    let changed = sync_owner_tree(&mut table[state_index]);
    clear_blocked(&table[state_index].waiters[waiter_index]);
    let waiter = table[state_index].remove_unlinked(waiter_index);
    if let Some((owner, true)) = changed { propagate_from(table, &owner); }
    waiter
}

/// Transfer a lock after the userspace owner word has already committed.
pub(crate) fn handoff(table: &mut [PiState], state_index: usize,
                      waiter_index: usize) -> PiWaiter {
    let old = detach_owner(&mut table[state_index]);
    table[state_index].unlink_waiter(waiter_index);
    clear_blocked(&table[state_index].waiters[waiter_index]);
    let waiter = table[state_index].remove_unlinked(waiter_index);
    table[state_index].owner = Some(Arc::clone(&waiter.task));
    table[state_index].owner_tid = waiter.tid;
    let new = sync_owner_tree(&mut table[state_index]);
    if let Some((owner, true)) = old { propagate_from(table, &owner); }
    if let Some((owner, true)) = new { propagate_from(table, &owner); }
    waiter
}

/// Rekey only the caller's task-owned blocked waiter; no global waiter scan.
pub(crate) fn rekey_blocked_task(table: &mut [PiState], task: &Arc<Task>) {
    let Some(blocked) = blocked_on(task) else { return };
    let Some(state_index) = find_id(table, blocked.lock_id) else { return };
    let Some(index) = waiter_index(&table[state_index], blocked.waiter_id) else { return };
    let key = sched::live::pi_boost::donor_key(task);
    if table[state_index].waiters[index].key() == key { return; }
    table[state_index].rekey_waiter(index, key, next_waiter_order());
    if let Some((owner, true)) = sync_owner_tree(&mut table[state_index]) {
        propagate_from(table, &owner);
    }
}

/// Whether adding `waiter -> owner` closes a task-owned blocked-on chain.
pub(crate) fn would_deadlock(table: &mut [PiState], waiter: &Arc<Task>,
                             owner: &Arc<Task>) -> bool {
    let epoch = NEXT_CHAIN_EPOCH.fetch_add(1, Ordering::Relaxed);
    let mut task = Arc::clone(owner);
    loop {
        if Arc::ptr_eq(&task, waiter) { return true; }
        let Some(blocked) = blocked_on(&task) else { return false };
        let Some(state_index) = find_id(table, blocked.lock_id) else { return true };
        let Some(index) = waiter_index(&table[state_index], blocked.waiter_id) else { return true };
        if table[state_index].waiters[index].revisit(epoch) { return true; }
        let Some(next) = table[state_index].owner.clone() else { return false };
        task = next;
    }
}

/// Detach every task edge before a state and its pinned nodes are retired.
pub(crate) fn retire_state(table: &mut [PiState], state_index: usize) -> Option<Arc<Task>> {
    let old = detach_owner(&mut table[state_index]);
    for index in 0..table[state_index].waiters.len() {
        if table[state_index].waiters[index].requeue_target.is_none() {
            table[state_index].unlink_waiter(index);
            clear_blocked(&table[state_index].waiters[index]);
        }
    }
    let changed_owner = old.and_then(|(owner, changed)| changed.then_some(owner));
    if let Some(owner) = changed_owner.as_ref() { propagate_from(table, owner); }
    changed_owner
}

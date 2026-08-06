use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::nft_expr::{self, Expr};
use super::generation;
use super::model::{
    ControlState, NamespaceState, NftChain, NftControlLock, NftObject, NftRule, NftSet,
    NftSetElem, NftTable, StoredRule,
};

#[derive(Clone)]
struct BatchBackup { namespace: u64, state: Option<NamespaceState> }

static CONTROL: NftControlLock<ControlState> = NftControlLock::new(ControlState::new());
static NFNL_SERIAL: NftControlLock<()> = NftControlLock::new(());
static BATCH_BACKUP: NftControlLock<Option<BatchBackup>> = NftControlLock::new(None);
static BATCH_OPEN: AtomicBool = AtomicBool::new(false);
static BATCH_DIRTY: AtomicBool = AtomicBool::new(false);
static BATCH_NAMESPACE: AtomicU64 = AtomicU64::new(0);
static NEXT_RULE_HANDLE: AtomicU64 = AtomicU64::new(1);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetRemoveError { Busy }

fn publish(control: &mut ControlState, namespace: u64) {
    if BATCH_OPEN.load(Ordering::Acquire) {
        debug_assert_eq!(BATCH_NAMESPACE.load(Ordering::Acquire), namespace);
        BATCH_DIRTY.store(true, Ordering::Release);
    } else {
        let state = control.namespace_mut(namespace);
        state.generation = state.generation.wrapping_add(1);
        generation::publish(control);
    }
}

/// Serialize one complete nfnetlink datagram, including its batch markers.
/// # C: O(1) uncontended; one context switch per contended round
/// # Sleeps: yes
pub(crate) fn nfnl_lock() -> sched::live::MutexGuard<'static, ()> { NFNL_SERIAL.lock() }

/// Snapshot one namespace's canonical state for an atomic nfnetlink batch. # C: O(namespace state)
pub(crate) fn batch_begin(namespace: u64) -> bool {
    if BATCH_OPEN.swap(true, Ordering::AcqRel) { return false; }
    let state = CONTROL.lock().namespace(namespace).cloned();
    *BATCH_BACKUP.lock() = Some(BatchBackup { namespace, state });
    BATCH_NAMESPACE.store(namespace, Ordering::Release);
    BATCH_DIRTY.store(false, Ordering::Release);
    true
}

/// Publish every mutation since `batch_begin` as one generation. # C: O(control state)
pub(crate) fn batch_commit(namespace: u64) -> bool {
    if !BATCH_OPEN.load(Ordering::Acquire)
        || BATCH_NAMESPACE.load(Ordering::Acquire) != namespace
    { return false; }
    BATCH_OPEN.store(false, Ordering::Release);
    let dirty = BATCH_DIRTY.swap(false, Ordering::AcqRel);
    let _ = BATCH_BACKUP.lock().take();
    if dirty {
        let mut control = CONTROL.lock();
        let state = control.namespace_mut(namespace);
        state.generation = state.generation.wrapping_add(1);
        generation::publish(&mut control);
    }
    true
}

/// Restore the pre-batch namespace without changing the active generation. # C: O(namespace state)
pub(crate) fn batch_abort() {
    let backup = BATCH_BACKUP.lock().take();
    if let Some(backup) = backup {
        let mut control = CONTROL.lock();
        if let Some(state) = backup.state { control.namespaces.insert(backup.namespace, state); }
        else { control.namespaces.remove(&backup.namespace); }
    }
    BATCH_DIRTY.store(false, Ordering::Release);
    BATCH_OPEN.store(false, Ordering::Release);
}

/// # C: O(log N_namespaces)
pub fn gen_current_in(namespace: u64) -> u32 {
    CONTROL.lock().namespace(namespace).map_or(0, |state| state.generation)
}

/// Initial-network-namespace generation. # C: O(log N_namespaces)
pub fn gen_current() -> u32 { gen_current_in(0) }

/// # C: O(1)
pub fn next_rule_handle() -> u64 { NEXT_RULE_HANDLE.fetch_add(1, Ordering::AcqRel) }

/// # C: O(log N_namespaces + log N_rules)
pub fn counter_get_in(namespace: u64, handle: u64) -> (u64, u64) {
    CONTROL.lock().namespace(namespace).and_then(|state| state.counters.get(&handle))
        .map_or((0, 0), |counter| counter.read())
}

/// Initial-network-namespace counter lookup. # C: O(log N_rules)
pub fn counter_get(handle: u64) -> (u64, u64) { counter_get_in(0, handle) }

/// # C: O(N)
pub fn table_insert_in(namespace: u64, table: NftTable) {
    let mut control = CONTROL.lock();
    let state = control.namespace_mut(namespace);
    if let Some(slot) = state.tables.iter_mut()
        .find(|old| old.family == table.family && old.name == table.name) { *slot = table; }
    else { state.tables.push(table); }
    publish(&mut control, namespace);
}

/// Initial-network-namespace table insertion. # C: O(N)
pub fn table_insert(table: NftTable) { table_insert_in(0, table); }

/// # C: O(N)
pub fn table_remove_in(namespace: u64, family: u8, name: &str) -> usize {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.tables.len();
    state.tables.retain(|table| !(table.family == family && table.name == name));
    let removed = before - state.tables.len();
    if removed != 0 {
        state.chains.retain(|chain| !(chain.table_family == family && chain.table_name == name));
        state.rules.retain(|rule| {
            !(rule.wire.table_family == family && rule.wire.table_name == name)
        });
        state.sets.retain(|set| !(set.table_family == family && set.table_name == name));
        state.set_elems.retain(|elem| {
            !(elem.table_family == family && elem.table_name == name)
        });
        state.objects.retain(|object| {
            !(object.table_family == family && object.table_name == name)
        });
        publish(&mut control, namespace);
    }
    removed
}

/// Initial-network-namespace table removal. # C: O(N)
pub fn table_remove(family: u8, name: &str) -> usize { table_remove_in(0, family, name) }

/// # C: O(N)
pub fn tables_snapshot_in(namespace: u64) -> Vec<NftTable> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| state.tables.clone())
}

/// Initial-network-namespace table snapshot. # C: O(N)
pub fn tables_snapshot() -> Vec<NftTable> { tables_snapshot_in(0) }

/// # C: O(N)
pub fn chain_insert_in(namespace: u64, chain: NftChain) {
    let mut control = CONTROL.lock();
    let state = control.namespace_mut(namespace);
    if let Some(slot) = state.chains.iter_mut().find(|old| {
        old.table_family == chain.table_family && old.table_name == chain.table_name
            && old.name == chain.name
    }) { *slot = chain; } else { state.chains.push(chain); }
    publish(&mut control, namespace);
}

/// Initial-network-namespace chain insertion. # C: O(N)
pub fn chain_insert(chain: NftChain) { chain_insert_in(0, chain); }

/// # C: O(N)
pub fn chain_remove_in(namespace: u64, family: u8, table: &str, chain: &str) -> usize {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.chains.len();
    state.chains.retain(|item| {
        !(item.table_family == family && item.table_name == table && item.name == chain)
    });
    let removed = before - state.chains.len();
    if removed != 0 {
        state.rules.retain(|rule| {
            !(rule.wire.table_family == family && rule.wire.table_name == table
                && rule.wire.chain_name == chain)
        });
        publish(&mut control, namespace);
    }
    removed
}

/// Initial-network-namespace chain removal. # C: O(N)
pub fn chain_remove(family: u8, table: &str, chain: &str) -> usize {
    chain_remove_in(0, family, table, chain)
}

/// # C: O(N)
pub fn chains_snapshot_in(namespace: u64) -> Vec<NftChain> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| state.chains.clone())
}

/// Initial-network-namespace chain snapshot. # C: O(N)
pub fn chains_snapshot() -> Vec<NftChain> { chains_snapshot_in(0) }

/// # C: O(N)
pub fn rule_insert_in(namespace: u64, rule: NftRule) -> Result<u64, nft_expr::ParseError> {
    let exprs: Vec<Expr> = nft_expr::parse_exprs_checked(&rule.raw_expr)?;
    let handle = rule.handle;
    let mut control = CONTROL.lock();
    {
        let state = control.namespace(namespace);
        for expr in &exprs {
            let Expr::Lookup { sreg, set, .. } = expr else { continue };
            let Some(bound) = state.and_then(|state| state.sets.iter().find(|candidate| {
                candidate.table_family == rule.table_family
                    && candidate.table_name == rule.table_name && candidate.name == *set
            })) else { return Err(nft_expr::ParseError::MissingSet) };
            if !nft_expr::register_load_valid(*sreg, bound.key_len as usize) {
                return Err(nft_expr::ParseError::Malformed);
            }
        }
    }
    let state = control.namespace_mut(namespace);
    state.rules.push(StoredRule { wire: rule, exprs });
    publish(&mut control, namespace);
    Ok(handle)
}

/// Initial-network-namespace rule insertion. # C: O(N)
pub fn rule_insert(rule: NftRule) -> Result<u64, nft_expr::ParseError> { rule_insert_in(0, rule) }

/// # C: O(N)
pub fn rule_remove_in(namespace: u64, family: u8, table: &str, chain: &str, handle: u64) -> usize {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.rules.len();
    state.rules.retain(|rule| {
        !(rule.wire.table_family == family && rule.wire.table_name == table
            && rule.wire.chain_name == chain && rule.wire.handle == handle)
    });
    let removed = before - state.rules.len();
    if removed != 0 { publish(&mut control, namespace); }
    removed
}

/// Initial-network-namespace rule removal. # C: O(N)
pub fn rule_remove(family: u8, table: &str, chain: &str, handle: u64) -> usize {
    rule_remove_in(0, family, table, chain, handle)
}

/// Remove all rules in one chain as one generation commit. # C: O(N)
pub(crate) fn rules_remove_in(namespace: u64, family: u8, table: &str, chain: &str) -> usize {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.rules.len();
    state.rules.retain(|rule| {
        !(rule.wire.table_family == family && rule.wire.table_name == table
            && rule.wire.chain_name == chain)
    });
    let removed = before - state.rules.len();
    if removed != 0 { publish(&mut control, namespace); }
    removed
}

/// # C: O(N)
pub fn rules_snapshot_in(namespace: u64) -> Vec<NftRule> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| {
        state.rules.iter().map(|rule| rule.wire.clone()).collect()
    })
}

/// Initial-network-namespace rule snapshot. # C: O(N)
pub fn rules_snapshot() -> Vec<NftRule> { rules_snapshot_in(0) }

/// # C: O(N)
pub fn set_insert_in(namespace: u64, set: NftSet) {
    let mut control = CONTROL.lock();
    let state = control.namespace_mut(namespace);
    if let Some(slot) = state.sets.iter_mut().find(|old| {
        old.table_family == set.table_family && old.table_name == set.table_name
            && old.name == set.name
    }) { *slot = set; } else { state.sets.push(set); }
    publish(&mut control, namespace);
}

/// Initial-network-namespace set insertion. # C: O(N)
pub fn set_insert(set: NftSet) { set_insert_in(0, set); }

/// # C: O(N)
pub fn set_remove_in(namespace: u64, family: u8, table: &str, set: &str)
    -> Result<usize, SetRemoveError> {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return Ok(0) };
    let bound = state.rules.iter().any(|rule| {
        rule.wire.table_family == family && rule.wire.table_name == table
            && rule.exprs.iter().any(|expr| matches!(expr,
                Expr::Lookup { set: name, .. } if name == set))
    });
    if bound { return Err(SetRemoveError::Busy); }
    let before = state.sets.len();
    state.sets.retain(|item| {
        !(item.table_family == family && item.table_name == table && item.name == set)
    });
    let removed = before - state.sets.len();
    if removed != 0 {
        state.set_elems.retain(|elem| {
            !(elem.table_family == family && elem.table_name == table && elem.set_name == set)
        });
        publish(&mut control, namespace);
    }
    Ok(removed)
}

/// Initial-network-namespace set removal. # C: O(N)
pub fn set_remove(family: u8, table: &str, set: &str) -> Result<usize, SetRemoveError> {
    set_remove_in(0, family, table, set)
}

/// # C: O(N)
pub fn sets_snapshot_in(namespace: u64) -> Vec<NftSet> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| state.sets.clone())
}

/// Initial-network-namespace set snapshot. # C: O(N)
pub fn sets_snapshot() -> Vec<NftSet> { sets_snapshot_in(0) }

/// # C: O(N)
pub fn set_elem_insert_in(namespace: u64, elem: NftSetElem) {
    set_elems_insert_in(namespace, alloc::vec![elem]);
}

/// Initial-network-namespace set-element insertion. # C: O(N)
pub fn set_elem_insert(elem: NftSetElem) { set_elem_insert_in(0, elem); }

/// Insert one netlink element list as one generation commit. # C: O(N*M)
pub(crate) fn set_elems_insert_in(namespace: u64, elems: Vec<NftSetElem>) {
    if elems.is_empty() { return; }
    let mut control = CONTROL.lock();
    let state = control.namespace_mut(namespace);
    for elem in elems {
        if let Some(slot) = state.set_elems.iter_mut().find(|old| {
            old.table_family == elem.table_family && old.table_name == elem.table_name
                && old.set_name == elem.set_name && old.key == elem.key
        }) { *slot = elem; } else { state.set_elems.push(elem); }
    }
    publish(&mut control, namespace);
}

/// # C: O(N)
pub fn set_elem_remove_in(namespace: u64, family: u8, table: &str, set: &str, key: &[u8]) -> usize {
    set_elems_remove_in(namespace, family, table, set, &[key.to_vec()])
}

/// Initial-network-namespace set-element removal. # C: O(N)
pub fn set_elem_remove(family: u8, table: &str, set: &str, key: &[u8]) -> usize {
    set_elem_remove_in(0, family, table, set, key)
}

/// Remove one netlink element list as one generation commit. # C: O(N*M)
pub(crate) fn set_elems_remove_in(
    namespace: u64,
    family: u8,
    table: &str,
    set: &str,
    keys: &[Vec<u8>],
) -> usize {
    if keys.is_empty() { return 0; }
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.set_elems.len();
    state.set_elems.retain(|elem| {
        elem.table_family != family || elem.table_name != table || elem.set_name != set
            || !keys.iter().any(|key| key == &elem.key)
    });
    let removed = before - state.set_elems.len();
    if removed != 0 { publish(&mut control, namespace); }
    removed
}

/// # C: O(N)
pub fn set_elems_snapshot_in(namespace: u64) -> Vec<NftSetElem> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| state.set_elems.clone())
}

/// Initial-network-namespace set-element snapshot. # C: O(N)
pub fn set_elems_snapshot() -> Vec<NftSetElem> { set_elems_snapshot_in(0) }

/// # C: O(N)
pub fn set_elem_lookup_in(
    namespace: u64,
    family: u8,
    table: &str,
    set: &str,
    key: &[u8],
) -> Option<Vec<u8>> {
    CONTROL.lock().namespace(namespace).and_then(|state| state.set_elems.iter().find(|elem| {
        elem.table_family == family && elem.table_name == table
            && elem.set_name == set && elem.key.as_slice() == key
    })).map(|elem| elem.data.clone())
}

/// Initial-network-namespace set-element lookup. # C: O(N)
pub fn set_elem_lookup(family: u8, table: &str, set: &str, key: &[u8]) -> Option<Vec<u8>> {
    set_elem_lookup_in(0, family, table, set, key)
}

/// # C: O(N)
pub fn object_insert_in(namespace: u64, object: NftObject) {
    let mut control = CONTROL.lock();
    let state = control.namespace_mut(namespace);
    if let Some(slot) = state.objects.iter_mut().find(|old| {
        old.table_family == object.table_family && old.table_name == object.table_name
            && old.name == object.name
    }) { *slot = object; } else { state.objects.push(object); }
    publish(&mut control, namespace);
}

/// Initial-network-namespace object insertion. # C: O(N)
pub fn object_insert(object: NftObject) { object_insert_in(0, object); }

/// # C: O(N)
pub fn object_remove_in(namespace: u64, family: u8, table: &str, object: &str) -> usize {
    let mut control = CONTROL.lock();
    let Some(state) = control.namespaces.get_mut(&namespace) else { return 0; };
    let before = state.objects.len();
    state.objects.retain(|item| {
        !(item.table_family == family && item.table_name == table && item.name == object)
    });
    let removed = before - state.objects.len();
    if removed != 0 { publish(&mut control, namespace); }
    removed
}

/// Initial-network-namespace object removal. # C: O(N)
pub fn object_remove(family: u8, table: &str, object: &str) -> usize {
    object_remove_in(0, family, table, object)
}

/// # C: O(N)
pub fn objects_snapshot_in(namespace: u64) -> Vec<NftObject> {
    CONTROL.lock().namespace(namespace).map_or_else(Vec::new, |state| state.objects.clone())
}

/// Initial-network-namespace object snapshot. # C: O(N)
pub fn objects_snapshot() -> Vec<NftObject> { objects_snapshot_in(0) }

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;

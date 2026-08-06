use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

#[derive(Clone, Debug)]
pub struct NftTable {
    pub family: u8,
    pub name:   String,
    pub flags:  u32,
}

#[derive(Clone, Debug)]
pub struct NftChain {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    pub hook:         Option<u32>,
    pub priority:     i32,
    pub policy:       u32,
}

#[derive(Clone, Debug)]
pub struct NftRule {
    pub table_family: u8,
    pub table_name:   String,
    pub chain_name:   String,
    pub handle:       u64,
    pub raw_expr:     Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NftSet {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    pub key_type:     u32,
    pub key_len:      u32,
    pub data_type:    u32,
    pub data_len:     u32,
    pub flags:        u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftSetElem {
    pub table_family: u8,
    pub table_name:   String,
    pub set_name:     String,
    pub key:          Vec<u8>,
    pub data:         Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NftObject {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    pub ty:           u32,
    pub data:         Vec<u8>,
}

/// nftables control state is read by NET_RX and changed from netlink process
/// context. Keep bottom-half exclusion in the lock type until rule generations
/// become immutable RCU publications.
pub(crate) struct NftBhLock<T>(Spinlock<T, SockLockClass>);

impl<T> NftBhLock<T> {
    const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    /// # C: O(1)
    pub(crate) fn lock(
        &self,
    ) -> sync::LockBhGuard<'_, T, SockLockClass, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

pub(crate) static TABLES: NftBhLock<Vec<NftTable>> = NftBhLock::new(Vec::new());
pub(crate) static CHAINS: NftBhLock<Vec<NftChain>> = NftBhLock::new(Vec::new());
pub(crate) static RULES: NftBhLock<Vec<NftRule>> = NftBhLock::new(Vec::new());
pub(crate) static SETS: NftBhLock<Vec<NftSet>> = NftBhLock::new(Vec::new());
static SET_ELEMS: NftBhLock<Vec<NftSetElem>> = NftBhLock::new(Vec::new());
pub(crate) static OBJECTS: NftBhLock<Vec<NftObject>> = NftBhLock::new(Vec::new());
static COUNTERS: NftBhLock<BTreeMap<u64, (u64, u64)>> = NftBhLock::new(BTreeMap::new());
static NFT_GEN: AtomicU32 = AtomicU32::new(0);
static HOOK_MASK: AtomicU32 = AtomicU32::new(0);
static HOOK_OVERFLOW: AtomicBool = AtomicBool::new(false);
static NEXT_RULE_HANDLE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn hook_bit(hook: u32) -> u32 { 1u32.checked_shl(hook).unwrap_or(0) }

fn publish_hook_mask(chains: &[NftChain]) {
    let mask = chains.iter().filter_map(|c| c.hook).fold(0, |mask, hook| mask | hook_bit(hook));
    let overflow = chains.iter().filter_map(|c| c.hook).any(|hook| hook_bit(hook) == 0);
    HOOK_MASK.store(mask, Ordering::Release);
    HOOK_OVERFLOW.store(overflow, Ordering::Release);
}

/// Whether a base chain is published for this hook. # C: O(1)
pub(crate) fn hook_active(hook: u32) -> bool {
    let bit = hook_bit(hook);
    if bit == 0 { HOOK_OVERFLOW.load(Ordering::Acquire) }
    else { HOOK_MASK.load(Ordering::Acquire) & bit != 0 }
}

/// # C: O(log N)
pub fn counter_bump(handle: u64, packets: u64, bytes: u64) {
    let mut g = COUNTERS.lock();
    let e = g.entry(handle).or_insert((0, 0));
    e.0 = e.0.wrapping_add(packets);
    e.1 = e.1.wrapping_add(bytes);
}

/// # C: O(log N)
pub fn counter_get(handle: u64) -> (u64, u64) {
    COUNTERS.lock().get(&handle).copied().unwrap_or((0, 0))
}

/// # C: O(1)
pub fn gen_current() -> u32 {
    NFT_GEN.load(Ordering::Acquire)
}

/// # C: O(1)
pub fn gen_bump() -> u32 {
    NFT_GEN.fetch_add(1, Ordering::AcqRel) + 1
}

/// # C: O(1)
pub fn next_rule_handle() -> u64 {
    NEXT_RULE_HANDLE.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
}

/// # C: O(N)
pub fn table_insert(t: NftTable) {
    let mut g = TABLES.lock();
    if let Some(i) = g.iter().position(|x| x.family == t.family && x.name == t.name) {
        g[i] = t;
    } else {
        g.push(t);
    }
}

/// # C: O(N)
pub fn table_remove(family: u8, name: &str) -> usize {
    let mut g = TABLES.lock();
    let before = g.len();
    g.retain(|x| !(x.family == family && x.name == name));
    before - g.len()
}

/// # C: O(N)
pub fn tables_snapshot() -> Vec<NftTable> { TABLES.lock().clone() }

/// # C: O(N)
pub fn chain_insert(c: NftChain) {
    let mut g = CHAINS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == c.table_family && x.table_name == c.table_name && x.name == c.name)
    { g[i] = c; } else { g.push(c); }
    publish_hook_mask(&g);
}

/// # C: O(N)
pub fn chain_remove(family: u8, table_name: &str, chain_name: &str) -> usize {
    let mut g = CHAINS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family && x.table_name == table_name && x.name == chain_name));
    publish_hook_mask(&g);
    before - g.len()
}

/// # C: O(N)
pub fn chains_snapshot() -> Vec<NftChain> { CHAINS.lock().clone() }

/// # C: O(1)
pub fn rule_insert(r: NftRule) -> u64 {
    let h = r.handle;
    RULES.lock().push(r);
    h
}

/// # C: O(N)
pub fn rule_remove(family: u8, table_name: &str, chain_name: &str, handle: u64) -> usize {
    let mut g = RULES.lock();
    let before = g.len();
    g.retain(|r| {
        !(r.table_family == family && r.table_name == table_name && r.chain_name == chain_name
            && r.handle == handle)
    });
    before - g.len()
}

/// # C: O(N)
pub fn rules_snapshot() -> Vec<NftRule> { RULES.lock().clone() }

/// # C: O(N)
pub fn set_insert(s: NftSet) {
    let mut g = SETS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == s.table_family && x.table_name == s.table_name && x.name == s.name)
    { g[i] = s; } else { g.push(s); }
}

/// # C: O(N)
pub fn set_remove(family: u8, table_name: &str, set_name: &str) -> usize {
    let mut g = SETS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family && x.table_name == table_name && x.name == set_name));
    before - g.len()
}

/// # C: O(N)
pub fn sets_snapshot() -> Vec<NftSet> { SETS.lock().clone() }

/// # C: O(N)
pub fn set_elem_insert(e: NftSetElem) {
    let mut g = SET_ELEMS.lock();
    if let Some(i) = g.iter().position(|x| {
        x.table_family == e.table_family
            && x.table_name == e.table_name
            && x.set_name == e.set_name
            && x.key == e.key
    }) {
        g[i] = e;
    } else {
        g.push(e);
    }
}

/// # C: O(N)
pub fn set_elem_remove(family: u8, table: &str, set: &str, key: &[u8]) -> usize {
    let mut g = SET_ELEMS.lock();
    let before = g.len();
    g.retain(|x| {
        !(x.table_family == family
            && x.table_name == table
            && x.set_name == set
            && x.key.as_slice() == key)
    });
    before - g.len()
}

/// # C: O(N)
pub fn set_elems_snapshot() -> Vec<NftSetElem> { SET_ELEMS.lock().clone() }

/// # C: O(N)
pub fn set_elem_lookup(family: u8, table: &str, set: &str, key: &[u8]) -> Option<Vec<u8>> {
    let g = SET_ELEMS.lock();
    g.iter()
        .find(|x| {
            x.table_family == family
                && x.table_name == table
                && x.set_name == set
                && x.key.as_slice() == key
        })
        .map(|x| x.data.clone())
}

/// # C: O(N)
pub fn object_insert(o: NftObject) {
    let mut g = OBJECTS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == o.table_family && x.table_name == o.table_name && x.name == o.name)
    { g[i] = o; } else { g.push(o); }
}

/// # C: O(N)
pub fn object_remove(family: u8, table_name: &str, obj_name: &str) -> usize {
    let mut g = OBJECTS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family && x.table_name == table_name && x.name == obj_name));
    before - g.len()
}

/// # C: O(N)
pub fn objects_snapshot() -> Vec<NftObject> { OBJECTS.lock().clone() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_state_lock_disables_bottom_halves_for_guard_lifetime() {
        sched::preempt::_test_reset();
        let lock = NftBhLock::new(7u32);
        {
            let guard = lock.lock();
            assert_eq!(*guard, 7);
            assert_eq!(sched::preempt::softirq_count(), sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }

    #[test]
    fn hook_mask_tracks_chain_publication() {
        let name = "hook-mask-state-test";
        let hook = crate::hook::NF_INET_PRE_ROUTING;
        let _ = chain_remove(2, name, name);
        chain_insert(NftChain {
            table_family: 2,
            table_name: name.into(),
            name: name.into(),
            hook: Some(hook),
            priority: 0,
            policy: crate::NFT_CHAIN_POLICY_ACCEPT,
        });
        assert!(hook_active(hook));
        assert_eq!(chain_remove(2, name, name), 1);
    }
}

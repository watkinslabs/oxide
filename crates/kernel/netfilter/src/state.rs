use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

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

pub(crate) static TABLES: Spinlock<Vec<NftTable>, SockLockClass> = Spinlock::new(Vec::new());
pub(crate) static CHAINS: Spinlock<Vec<NftChain>, SockLockClass> = Spinlock::new(Vec::new());
pub(crate) static RULES: Spinlock<Vec<NftRule>, SockLockClass> = Spinlock::new(Vec::new());
pub(crate) static SETS: Spinlock<Vec<NftSet>, SockLockClass> = Spinlock::new(Vec::new());
static SET_ELEMS: Spinlock<Vec<NftSetElem>, SockLockClass> = Spinlock::new(Vec::new());
pub(crate) static OBJECTS: Spinlock<Vec<NftObject>, SockLockClass> = Spinlock::new(Vec::new());
static COUNTERS: Spinlock<BTreeMap<u64, (u64, u64)>, SockLockClass> =
    Spinlock::new(BTreeMap::new());
static NFT_GEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static NEXT_RULE_HANDLE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
    NFT_GEN.load(core::sync::atomic::Ordering::Acquire)
}

/// # C: O(1)
pub fn gen_bump() -> u32 {
    NFT_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel) + 1
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
}

/// # C: O(N)
pub fn chain_remove(family: u8, table_name: &str, chain_name: &str) -> usize {
    let mut g = CHAINS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family && x.table_name == table_name && x.name == chain_name));
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

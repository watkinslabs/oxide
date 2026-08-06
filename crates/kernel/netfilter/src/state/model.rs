use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::nft_expr::Expr;

#[derive(Clone, Debug)]
pub struct NftTable {
    pub family: u8,
    pub name: String,
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct NftChain {
    pub table_family: u8,
    pub table_name: String,
    pub name: String,
    pub hook: Option<u32>,
    pub priority: i32,
    pub policy: u32,
}

#[derive(Clone, Debug)]
pub struct NftRule {
    pub table_family: u8,
    pub table_name: String,
    pub chain_name: String,
    pub handle: u64,
    pub raw_expr: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NftSet {
    pub table_family: u8,
    pub table_name: String,
    pub name: String,
    pub key_type: u32,
    pub key_len: u32,
    pub data_type: u32,
    pub data_len: u32,
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftSetElem {
    pub table_family: u8,
    pub table_name: String,
    pub set_name: String,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NftObject {
    pub table_family: u8,
    pub table_name: String,
    pub name: String,
    pub ty: u32,
    pub data: Vec<u8>,
}

/// Canonical nftables control-plane state. Netlink serializes mutations here,
/// then compiles and publishes one immutable packet-path generation.
#[derive(Clone)]
pub(super) struct ControlState {
    pub(super) namespaces: BTreeMap<u64, NamespaceState>,
}

#[derive(Clone)]
pub(super) struct NamespaceState {
    pub(super) generation: u32,
    pub(super) tables: Vec<NftTable>,
    pub(super) chains: Vec<NftChain>,
    pub(super) rules: Vec<StoredRule>,
    pub(super) sets: Vec<NftSet>,
    pub(super) set_elems: Vec<NftSetElem>,
    pub(super) objects: Vec<NftObject>,
    pub(super) counters: BTreeMap<u64, Arc<RuleCounter>>,
}

#[derive(Clone)]
pub(super) struct StoredRule {
    pub(super) wire: NftRule,
    pub(super) exprs: Vec<Expr>,
}

impl ControlState {
    pub(super) const fn new() -> Self { Self { namespaces: BTreeMap::new() } }

    pub(super) fn namespace_mut(&mut self, namespace: u64) -> &mut NamespaceState {
        self.namespaces.entry(namespace).or_insert_with(NamespaceState::new)
    }

    pub(super) fn namespace(&self, namespace: u64) -> Option<&NamespaceState> {
        self.namespaces.get(&namespace)
    }
}

impl NamespaceState {
    pub(super) fn new() -> Self {
        Self {
            generation: 0, tables: Vec::new(), chains: Vec::new(), rules: Vec::new(), sets: Vec::new(),
            set_elems: Vec::new(), objects: Vec::new(), counters: BTreeMap::new(),
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
mod control_lock {
    pub(super) type Lock<T> = sched::live::Mutex<T>;
    pub(super) type Guard<'a, T> = sched::live::MutexGuard<'a, T>;
    pub(super) const fn new<T>(value: T) -> Lock<T> { sched::live::Mutex::new(value) }
    // SAFETY: the nftables control plane is reachable only from schedulable
    // netlink process context and never from packet, softirq, or IRQ context.
    pub(super) fn lock<T>(lock: &Lock<T>) -> Guard<'_, T> { unsafe { lock.lock() } }
}

#[cfg(not(target_os = "oxide-kernel"))]
mod control_lock {
    pub(super) type Lock<T> = sync::Spinlock<T, sync::Socket>;
    pub(super) type Guard<'a, T> = sync::Guard<'a, T, sync::Socket>;
    pub(super) const fn new<T>(value: T) -> Lock<T> { sync::Spinlock::new(value) }
    pub(super) fn lock<T>(lock: &Lock<T>) -> Guard<'_, T> { lock.lock() }
}

pub(super) struct NftControlLock<T>(control_lock::Lock<T>);

impl<T> NftControlLock<T> {
    pub(super) const fn new(value: T) -> Self { Self(control_lock::new(value)) }

    /// Kernel control operations sleep on contention; hosted checks use their
    /// scheduler-free exclusion stand-in.
    /// # C: O(1) uncontended; one context switch per contended round
    /// # Sleeps: yes
    pub(super) fn lock(&self) -> control_lock::Guard<'_, T> { control_lock::lock(&self.0) }
}

pub(crate) struct RuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl RuleCounter {
    pub(super) fn new() -> Self {
        Self { packets: AtomicU64::new(0), bytes: AtomicU64::new(0) }
    }

    /// # C: O(1)
    pub(crate) fn bump(&self, packets: u64, bytes: u64) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// # C: O(1)
    pub(super) fn read(&self) -> (u64, u64) {
        (self.packets.load(Ordering::Relaxed), self.bytes.load(Ordering::Relaxed))
    }
}

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Namespace, Spinlock};

use crate::{callback, NamespaceIdentity, NetworkNamespace, NetworkNamespaceId,
    NetworkNamespaceRef};

const INIT_ID: NetworkNamespaceId = NetworkNamespaceId(0);
const INIT_NSFS_INO: u64 = 0x7200_0006;
const NSFS_INO_STRIDE: u64 = 0x100;
const MAX_ID: u64 = (u64::MAX - INIT_NSFS_INO) / NSFS_INO_STRIDE;

struct Registry {
    init: Option<NetworkNamespaceRef>,
    by_id: BTreeMap<NetworkNamespaceId, RegistryEntry>,
}

enum RegistryEntry {
    Live(Weak<NetworkNamespace>),
    TeardownClaimed,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static REGISTRY: Spinlock<Registry, Namespace> = Spinlock::new(Registry {
    init: None,
    by_id: BTreeMap::new(),
});

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocError { FinalDropCallbackMissing, IdExhausted }

fn next_identity() -> Result<NamespaceIdentity, AllocError> {
    let mut current = NEXT_ID.load(Ordering::Relaxed);
    loop {
        if current > MAX_ID { return Err(AllocError::IdExhausted); }
        match NEXT_ID.compare_exchange_weak(current, current + 1,
            Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(NamespaceIdentity {
                id: NetworkNamespaceId(current),
                nsfs_ino: INIT_NSFS_INO + current * NSFS_INO_STRIDE,
            }),
            Err(observed) => current = observed,
        }
    }
}

/// Return the immortal initial network namespace.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn initial() -> NetworkNamespaceRef {
    let mut registry = REGISTRY.lock();
    if let Some(namespace) = registry.init.as_ref() { return Arc::clone(namespace); }
    let namespace = Arc::new(NetworkNamespace {
        identity: NamespaceIdentity { id: INIT_ID, nsfs_ino: INIT_NSFS_INO },
        owner_user_ns: 0,
    });
    registry.by_id.insert(INIT_ID, RegistryEntry::Live(Arc::downgrade(&namespace)));
    registry.init = Some(Arc::clone(&namespace));
    namespace
}

/// Allocate and publish a network namespace owned by `owner_user_ns`.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn allocate(owner_user_ns: u64) -> Result<NetworkNamespaceRef, AllocError> {
    if !callback::installed() { return Err(AllocError::FinalDropCallbackMissing); }
    let identity = next_identity()?;
    let namespace = Arc::new(NetworkNamespace { identity, owner_user_ns });
    REGISTRY.lock().by_id.insert(identity.id,
        RegistryEntry::Live(Arc::downgrade(&namespace)));
    Ok(namespace)
}

/// Pin a live namespace by stable ID without reconstructing dead owners.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn lookup(id: NetworkNamespaceId) -> Option<NetworkNamespaceRef> {
    match REGISTRY.lock().by_id.get(&id) {
        Some(RegistryEntry::Live(namespace)) => namespace.upgrade(),
        Some(RegistryEntry::TeardownClaimed) | None => None,
    }
}

/// Pin a live namespace from a subsystem's stored numeric key. This never
/// reconstructs an owner after final drop. # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn lookup_u64(id: u64) -> Option<NetworkNamespaceRef> {
    lookup(NetworkNamespaceId(id))
}

/// Snapshot every currently live namespace as owned references.
/// # C: O(N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn live_snapshot() -> Vec<NetworkNamespaceRef> {
    REGISTRY.lock().by_id.values().filter_map(|entry| match entry {
        RegistryEntry::Live(namespace) => namespace.upgrade(),
        RegistryEntry::TeardownClaimed => None,
    }).collect()
}

/// Claim dead namespace IDs exactly once for deferred process-context teardown.
/// # C: O(N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn take_dead_namespace_ids() -> Vec<NetworkNamespaceId> {
    let mut registry = REGISTRY.lock();
    let dead: Vec<_> = registry.by_id.iter()
        .filter_map(|(id, entry)| {
            if *id == INIT_ID { return None; }
            match entry {
                RegistryEntry::Live(namespace) if namespace.strong_count() == 0 => Some(*id),
                RegistryEntry::Live(_) | RegistryEntry::TeardownClaimed => None,
            }
        })
        .collect();
    for id in &dead { registry.by_id.insert(*id, RegistryEntry::TeardownClaimed); }
    dead
}

/// Remove registry metadata after namespace-owned subsystem teardown. # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn finish_teardown(id: NetworkNamespaceId) -> bool {
    let mut registry = REGISTRY.lock();
    if !matches!(registry.by_id.get(&id), Some(RegistryEntry::TeardownClaimed)) {
        return false;
    }
    registry.by_id.remove(&id);
    true
}

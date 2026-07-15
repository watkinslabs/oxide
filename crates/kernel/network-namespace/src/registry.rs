use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Namespace, Spinlock};

use crate::{callback, NamespaceIdentity, NetworkNamespace, NetworkNamespaceId,
    NetworkNamespaceRef, NetworkNamespaceTeardown};

const INIT_ID: NetworkNamespaceId = NetworkNamespaceId(0);
const INIT_NSFS_INO: u64 = 0x7200_0006;
const NSFS_INO_STRIDE: u64 = 0x100;
const MAX_ID: u64 = (namespace_identity::MNT_INIT_NSFS_INO - INIT_NSFS_INO - 1)
    / NSFS_INO_STRIDE;

struct Registry {
    init: Option<NetworkNamespaceRef>,
    by_id: BTreeMap<NetworkNamespaceId, RegistryEntry>,
}

pub(crate) trait WeakOwner {
    type Strong;

    fn upgrade(&self) -> Option<Self::Strong>;
    fn strong_count(&self) -> usize;
}

impl<T> WeakOwner for Weak<T> {
    type Strong = Arc<T>;

    fn upgrade(&self) -> Option<Self::Strong> { Weak::upgrade(self) }
    fn strong_count(&self) -> usize { Weak::strong_count(self) }
}

pub(crate) enum RegistryEntry<W = Weak<NetworkNamespace>> {
    Live(W),
    TeardownClaimed,
}

impl<W: WeakOwner> RegistryEntry<W> {
    /// Pin a live owner unless teardown already claimed it. # C: O(1)
    pub(crate) fn lookup(&self) -> Option<W::Strong> {
        match self {
            Self::Live(owner) => owner.upgrade(),
            Self::TeardownClaimed => None,
        }
    }

    /// Atomically transition a dead entry into teardown ownership. # C: O(1)
    pub(crate) fn claim_if_dead(&mut self) -> bool {
        match self {
            Self::Live(owner) if owner.strong_count() == 0 => {
                *self = Self::TeardownClaimed;
                true
            }
            Self::Live(_) | Self::TeardownClaimed => false,
        }
    }

    /// Test whether teardown owns the registry entry. # C: O(1)
    pub(crate) fn is_claimed(&self) -> bool {
        matches!(self, Self::TeardownClaimed)
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static REGISTRY: Spinlock<Registry, Namespace> = Spinlock::new(Registry {
    init: None,
    by_id: BTreeMap::new(),
});

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocError { FinalDropCallbackMissing, IdExhausted, OwnerNotUserNamespace }

pub(crate) fn ns_id_error(error: namespace_identity::AllocError) -> AllocError {
    match error {
        namespace_identity::AllocError::IdExhausted => AllocError::IdExhausted,
        namespace_identity::AllocError::OwnerNotUserNamespace
        | namespace_identity::AllocError::ParentKindMismatch => AllocError::OwnerNotUserNamespace,
    }
}

fn next_identity() -> Result<NamespaceIdentity, AllocError> {
    let mut current = NEXT_ID.load(Ordering::Relaxed);
    loop {
        if current > MAX_ID { return Err(AllocError::IdExhausted); }
        match NEXT_ID.compare_exchange_weak(current, current + 1,
            Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(NamespaceIdentity {
                id: NetworkNamespaceId(current),
                ns_id: namespace_identity::allocate_ns_id()
                    .map_err(ns_id_error)?.as_u64(),
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
    let owner_user_namespace = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let mut registry = REGISTRY.lock();
    if let Some(namespace) = registry.init.as_ref() { return Arc::clone(namespace); }
    let namespace = Arc::new(NetworkNamespace {
        identity: NamespaceIdentity {
            id: INIT_ID,
            ns_id: namespace_identity::NET_INIT_NS_ID,
            nsfs_ino: INIT_NSFS_INO,
        },
        owner_user_namespace,
    });
    registry.by_id.insert(INIT_ID, RegistryEntry::Live(Arc::downgrade(&namespace)));
    registry.init = Some(Arc::clone(&namespace));
    namespace
}

/// Allocate and publish a network namespace owned by `owner_user_namespace`.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn allocate(owner_user_namespace: namespace_identity::NamespaceRef)
    -> Result<NetworkNamespaceRef, AllocError>
{
    if owner_user_namespace.kind() != namespace_identity::NamespaceKind::User {
        return Err(AllocError::OwnerNotUserNamespace);
    }
    if !callback::installed() { return Err(AllocError::FinalDropCallbackMissing); }
    let identity = next_identity()?;
    let namespace = Arc::new(NetworkNamespace { identity, owner_user_namespace });
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
    REGISTRY.lock().by_id.get(&id).and_then(RegistryEntry::lookup)
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
    REGISTRY.lock().by_id.values().filter_map(RegistryEntry::lookup).collect()
}

/// Claim dead namespace IDs exactly once for deferred process-context teardown.
/// # C: O(N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn take_dead_namespace_ids() -> Vec<NetworkNamespaceId> {
    let mut registry = REGISTRY.lock();
    let dead: Vec<_> = registry.by_id.iter_mut()
        .filter_map(|(id, entry)| {
            if *id == INIT_ID { return None; }
            if entry.claim_if_dead() { Some(*id) } else { None }
        })
        .collect();
    dead
}

/// Remove registry metadata after namespace-owned subsystem teardown. # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn finish_teardown(id: NetworkNamespaceId) -> bool {
    let mut registry = REGISTRY.lock();
    if !registry.by_id.get(&id).is_some_and(RegistryEntry::is_claimed) {
        return false;
    }
    registry.by_id.remove(&id);
    true
}

/// Acquire opaque ownership of an already-claimed namespace teardown. # C: O(log N)
pub fn teardown_owner(id: NetworkNamespaceId) -> Option<NetworkNamespaceTeardown> {
    REGISTRY.lock().by_id.get(&id).is_some_and(RegistryEntry::is_claimed)
        .then_some(NetworkNamespaceTeardown { id })
}

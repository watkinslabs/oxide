use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use sync::{Namespace, Spinlock};

use crate::{callback, NetworkNamespace, NetworkNamespaceId,
    NetworkNamespaceRef, NetworkNamespaceTeardown};
use crate::owner::{FinalDropPublication, FinalDropPublisher};

const INIT_ID: NetworkNamespaceId = NetworkNamespaceId(0);

struct Registry {
    init: Option<NetworkNamespaceRef>,
    by_id: BTreeMap<NetworkNamespaceId, RegistryEntry>,
}

pub trait WeakOwner {
    type Strong;

    fn upgrade(&self) -> Option<Self::Strong>;
}

impl<T> WeakOwner for Weak<T> {
    type Strong = Arc<T>;

    fn upgrade(&self) -> Option<Self::Strong> { Weak::upgrade(self) }
}

pub trait FinalDropCompleted {
    fn completed(&self) -> bool;
}

impl FinalDropCompleted for Arc<FinalDropPublication> {
    fn completed(&self) -> bool { FinalDropPublication::completed(self) }
}

pub enum RegistryEntry<W = Weak<NetworkNamespace>, P = Arc<FinalDropPublication>> {
    Live { owner: W, final_drop: P },
    TeardownClaimed,
}

impl<W: WeakOwner, P: FinalDropCompleted> RegistryEntry<W, P> {
    /// Pin a live owner unless teardown already claimed it. # C: O(1)
    pub fn lookup(&self) -> Option<W::Strong> {
        match self {
            Self::Live { owner, .. } => owner.upgrade(),
            Self::TeardownClaimed => None,
        }
    }

    /// Claim teardown only after the owner's final-drop publication. # C: O(1)
    pub fn claim_if_completed(&mut self) -> bool {
        match self {
            Self::Live { final_drop, .. } if final_drop.completed() => {
                *self = Self::TeardownClaimed;
                true
            }
            Self::Live { .. } | Self::TeardownClaimed => false,
        }
    }

    /// Test whether teardown owns the registry entry. # C: O(1)
    pub fn is_claimed(&self) -> bool {
        matches!(self, Self::TeardownClaimed)
    }
}

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

/// Return the immortal initial network namespace.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn initial() -> NetworkNamespaceRef {
    {
        let registry = REGISTRY.lock();
        if let Some(namespace) = registry.init.as_ref() { return Arc::clone(namespace); }
    }
    // Construct every allocating part before taking the publication lock.
    // The first BTree insertion allocates its root node and therefore may enter
    // direct reclaim; a single-vCPU kernel must never do that while REGISTRY is
    // held, because another task can then spin forever trying to resolve its
    // network namespace.
    let canonical = namespace_identity::initial(namespace_identity::NamespaceKind::Net).pin();
    let final_drop = Arc::new(FinalDropPublication::new());
    let final_drop_publisher = FinalDropPublisher::new(INIT_ID, Arc::clone(&final_drop));
    let namespace = Arc::new(NetworkNamespace {
        canonical, active: Spinlock::new(None), peer_ids: Spinlock::new(BTreeMap::new()),
        _final_drop: final_drop_publisher,
    });
    let mut initial_map = BTreeMap::new();
    initial_map.insert(INIT_ID, RegistryEntry::Live {
        owner: Arc::downgrade(&namespace), final_drop,
    });
    {
        let mut registry = REGISTRY.lock();
        if let Some(existing) = registry.init.as_ref() { return Arc::clone(existing); }
        assert!(registry.by_id.is_empty(), "network namespace registry published child before init");
        registry.by_id = initial_map;
        registry.init = Some(Arc::clone(&namespace));
    }
    *namespace.active.lock() = Some(namespace.canonical.activate());
    namespace
}

/// Allocate and publish a network namespace owned by `owner_user_namespace`.
/// # C: O(log N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn allocate<H: namespace_identity::NamespaceHandle>(owner_user_namespace: H)
    -> Result<NetworkNamespaceRef, AllocError>
{
    let owner = owner_user_namespace.get_active_ref().ok_or(AllocError::OwnerNotUserNamespace)?;
    if owner.kind() != namespace_identity::NamespaceKind::User {
        return Err(AllocError::OwnerNotUserNamespace);
    }
    if !callback::installed() { return Err(AllocError::FinalDropCallbackMissing); }
    let canonical = namespace_identity::allocate_inactive(namespace_identity::NamespaceKind::Net,
        owner, None).map_err(ns_id_error)?;
    let final_drop = Arc::new(FinalDropPublication::new());
    let id = NetworkNamespaceId(canonical.id().as_u64());
    let final_drop_publisher = FinalDropPublisher::new(id, Arc::clone(&final_drop));
    let namespace = Arc::new(NetworkNamespace {
        canonical, active: Spinlock::new(None), peer_ids: Spinlock::new(BTreeMap::new()),
        _final_drop: final_drop_publisher,
    });
    REGISTRY.lock().by_id.insert(namespace.id(),
        RegistryEntry::Live { owner: Arc::downgrade(&namespace), final_drop });
    *namespace.active.lock() = Some(namespace.canonical.activate());
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
/// Claim dead namespace IDs exactly once for deferred process-context teardown.
/// # C: O(N)
/// # Ctx: process; caller holds no lock ranked `Namespace` or higher
/// # Lk: takes `Namespace` (rank 75)
/// # Sleeps: no
pub fn take_dead_namespace_ids() -> alloc::vec::Vec<NetworkNamespaceId> {
    let mut registry = REGISTRY.lock();
    let dead: alloc::vec::Vec<_> = registry.by_id.iter_mut()
        .filter_map(|(id, entry)| {
            if *id == INIT_ID { return None; }
            if entry.claim_if_completed() { Some(*id) } else { None }
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

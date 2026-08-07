use crate::callback;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct FinalDropPublication { completed: AtomicBool }

impl FinalDropPublication {
    /// Create an unpublished final-drop completion token. # C: O(1)
    pub(crate) const fn new() -> Self { Self { completed: AtomicBool::new(false) } }
    /// Publish that the owning destructor completed namespace release. # C: O(1)
    pub(crate) fn publish(&self) { self.completed.store(true, Ordering::Release); }
    /// Observe the owning destructor's completion publication. # C: O(1)
    pub(crate) fn completed(&self) -> bool { self.completed.load(Ordering::Acquire) }
}

pub(crate) struct FinalDropPublisher {
    #[cfg(test)]
    id: NetworkNamespaceId,
    publication: Arc<FinalDropPublication>,
}

impl FinalDropPublisher {
    /// Bind final-drop publication to one namespace owner. # C: O(1)
    pub(crate) fn new(_id: NetworkNamespaceId, publication: Arc<FinalDropPublication>) -> Self {
        Self { #[cfg(test)] id: _id, publication }
    }
}

#[cfg(test)]
static DROP_HOOK: sync::Spinlock<Option<fn(NetworkNamespaceId)>, sync::Namespace> =
    sync::Spinlock::new(None);

#[cfg(test)]
pub(crate) fn set_drop_hook(hook: Option<fn(NetworkNamespaceId)>) { *DROP_HOOK.lock() = hook; }

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkNamespaceId(pub(crate) u64);

impl NetworkNamespaceId {
    /// Numeric key used by namespace-partitioned subsystem tables. # C: O(1)
    pub const fn as_u64(self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceTeardown {
    pub(crate) id: NetworkNamespaceId,
}

impl NetworkNamespaceTeardown {
    /// Namespace identity exclusively claimed for subsystem teardown. # C: O(1)
    pub fn id(&self) -> NetworkNamespaceId { self.id }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    pub id: NetworkNamespaceId,
    pub ns_id: u64,
    pub nsfs_ino: u64,
}

/// Result of assigning a caller-scoped peer namespace ID.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerIdError { Invalid, Exists }

pub struct NetworkNamespace {
    pub(crate) canonical: namespace_identity::NamespacePin,
    pub(crate) active: sync::Spinlock<Option<namespace_identity::NamespaceRef>, sync::Namespace>,
    /// Caller-scoped peer network-namespace IDs. The weak peer keeps this
    /// namespace from extending another namespace's lifetime.
    pub(crate) peer_ids: sync::Spinlock<BTreeMap<i32, alloc::sync::Weak<NetworkNamespace>>, sync::Namespace>,
    // Must remain last: its Drop publishes after all namespace-owned fields drop.
    pub(crate) _final_drop: FinalDropPublisher,
}

impl NetworkNamespace {
    /// Stable numeric identity used by namespace-keyed subsystem state. # C: O(1)
    pub fn id(&self) -> NetworkNamespaceId { NetworkNamespaceId(self.canonical.id().as_u64()) }

    /// Stable identity used by nsfs and global namespace enumeration. # C: O(1)
    pub fn identity(&self) -> NamespaceIdentity { NamespaceIdentity {
        id: self.id(), ns_id: self.ns_id(), nsfs_ino: self.canonical.nsfs_ino(),
    } }

    /// Linux global namespace-tree ID. # C: O(1)
    pub fn ns_id(&self) -> u64 { self.canonical.ns_id().as_u64() }

    /// User namespace that owned creation of this network namespace. # C: O(1)
    pub fn owner_user_namespace(&self) -> namespace_identity::NamespacePin {
        self.canonical.owner_user_namespace()
    }

    /// Pin the canonical network namespace identity without extending activity. # C: O(1)
    pub fn namespace_identity(&self) -> namespace_identity::NamespacePin {
        self.canonical.clone()
    }

    /// True for the immortal initial network namespace. # C: O(1)
    pub fn is_initial(&self) -> bool { self.canonical.is_initial() }

    /// Resolve `peer` as this namespace names it. Namespace IDs are local to
    /// the caller; a global namespace number is never an ABI substitute.
    /// # C: O(N peers)
    pub fn peer_id(&self, peer: &NetworkNamespace) -> Option<i32> {
        let mut ids = self.peer_ids.lock();
        ids.retain(|_, owner| owner.strong_count() != 0);
        ids.iter().find_map(|(id, owner)| owner.upgrade()
            .and_then(|candidate| core::ptr::eq(&*candidate, peer).then_some(*id)))
    }

    /// Resolve one caller-local namespace ID to its live peer owner.
    /// # C: O(1)
    pub fn peer_by_id(&self, id: i32) -> Option<Arc<NetworkNamespace>> {
        let mut ids = self.peer_ids.lock();
        ids.retain(|_, owner| owner.strong_count() != 0);
        ids.get(&id).and_then(alloc::sync::Weak::upgrade)
    }

    /// Snapshot caller-local peer IDs in deterministic numeric order.
    /// # C: O(N peers)
    pub fn peer_snapshot(&self) -> alloc::vec::Vec<(i32, Arc<NetworkNamespace>)> {
        let mut ids = self.peer_ids.lock();
        ids.retain(|_, owner| owner.strong_count() != 0);
        ids.iter().filter_map(|(id, owner)| owner.upgrade().map(|peer| (*id, peer))).collect()
    }

    /// Install one explicit peer-ID mapping. `RTM_NEWNSID` owns the request
    /// parser; this owner enforces the one-to-one namespace relation.
    /// # C: O(N peers)
    pub fn assign_peer_id(&self, peer: &Arc<NetworkNamespace>, id: i32)
        -> Result<(), PeerIdError>
    {
        if id < 0 { return Err(PeerIdError::Invalid); }
        let mut ids = self.peer_ids.lock();
        ids.retain(|_, owner| owner.strong_count() != 0);
        if ids.values().any(|owner| owner.upgrade()
            .is_some_and(|candidate| core::ptr::eq(&*candidate, &**peer))) {
            return Err(PeerIdError::Exists);
        }
        if ids.contains_key(&id) { return Err(PeerIdError::Exists); }
        ids.insert(id, Arc::downgrade(peer));
        Ok(())
    }
}

impl Drop for FinalDropPublisher {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            let hook = *DROP_HOOK.lock();
            if let Some(hook) = hook { hook(self.id); }
        }
        self.publication.publish();
        callback::notify();
    }
}

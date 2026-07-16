use crate::callback;
use alloc::sync::Arc;
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

pub struct NetworkNamespace {
    pub(crate) canonical: namespace_identity::NamespacePin,
    pub(crate) active: sync::Spinlock<Option<namespace_identity::NamespaceRef>, sync::Namespace>,
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

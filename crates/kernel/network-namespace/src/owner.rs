use alloc::sync::Arc;

use crate::callback;

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
    pub nsfs_ino: u64,
}

pub struct NetworkNamespace {
    pub(crate) identity: NamespaceIdentity,
    pub(crate) owner_user_namespace: namespace_identity::NamespaceRef,
}

impl NetworkNamespace {
    /// Stable numeric identity used by namespace-keyed subsystem state. # C: O(1)
    pub fn id(&self) -> NetworkNamespaceId { self.identity.id }

    /// Stable identity used by nsfs and global namespace enumeration. # C: O(1)
    pub fn identity(&self) -> NamespaceIdentity { self.identity }

    /// User namespace that owned creation of this network namespace. # C: O(1)
    pub fn owner_user_namespace(&self) -> namespace_identity::NamespaceRef {
        Arc::clone(&self.owner_user_namespace)
    }

    /// True for the immortal initial network namespace. # C: O(1)
    pub fn is_initial(&self) -> bool { self.identity.id.0 == 0 }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) { callback::notify(); }
}

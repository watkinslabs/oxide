use alloc::sync::Arc;

use namespace_identity::NamespaceRef;
use network_namespace::NetworkNamespaceRef;

/// Exact owner retained by an nsfs inode or namespace enumeration snapshot.
pub enum NsOwner {
    Cgroup(NamespaceRef), Ipc(NamespaceRef), Pid(NamespaceRef),
    Time(NamespaceRef), User(NamespaceRef), Uts(NamespaceRef),
    Mnt(vfs::mntns::MntNamespaceRef), Net(NetworkNamespaceRef),
}

impl NsOwner {
    /// Linux global namespace-tree ID. # C: O(1)
    pub(crate) fn ns_id(&self) -> u64 {
        match self {
            Self::Cgroup(v) | Self::Ipc(v) | Self::Pid(v) | Self::Time(v)
            | Self::User(v) | Self::Uts(v) => v.ns_id().as_u64(),
            Self::Mnt(v) => v.ns_id(), Self::Net(v) => v.identity().ns_id,
        }
    }

    /// Concrete namespace family. # C: O(1)
    pub(crate) fn kind(&self) -> crate::listns::ListNsKind {
        match self {
            Self::Cgroup(_) => crate::listns::ListNsKind::Cgroup,
            Self::Ipc(_) => crate::listns::ListNsKind::Ipc,
            Self::Pid(_) => crate::listns::ListNsKind::Pid,
            Self::Time(_) => crate::listns::ListNsKind::Time,
            Self::User(_) => crate::listns::ListNsKind::User,
            Self::Uts(_) => crate::listns::ListNsKind::Uts,
            Self::Mnt(_) => crate::listns::ListNsKind::Mnt,
            Self::Net(_) => crate::listns::ListNsKind::Net,
        }
    }

    /// Exact user namespace owning this namespace, including init owners. # C: O(1)
    pub(crate) fn owner_user_namespace(&self) -> NamespaceRef {
        match self {
            Self::Cgroup(v) | Self::Ipc(v) | Self::Pid(v) | Self::Time(v)
            | Self::User(v) | Self::Uts(v) => v.owner_user_namespace(),
            Self::Mnt(v) => v.owner_user_namespace(), Self::Net(v) => v.owner_user_namespace(),
        }
    }

    /// Clone this exact tagged owner. # C: O(1)
    pub(crate) fn clone_ref(&self) -> Self {
        match self {
            Self::Cgroup(v) => Self::Cgroup(Arc::clone(v)), Self::Ipc(v) => Self::Ipc(Arc::clone(v)),
            Self::Pid(v) => Self::Pid(Arc::clone(v)), Self::Time(v) => Self::Time(Arc::clone(v)),
            Self::User(v) => Self::User(Arc::clone(v)), Self::Uts(v) => Self::Uts(Arc::clone(v)),
            Self::Mnt(v) => Self::Mnt(Arc::clone(v)), Self::Net(v) => Self::Net(Arc::clone(v)),
        }
    }

    /// Stable nsfs inode carried by this owner. # C: O(1)
    pub(crate) fn ino(&self) -> vfs::Ino {
        match self {
            Self::Cgroup(v) | Self::Ipc(v) | Self::Pid(v) | Self::Time(v)
            | Self::User(v) | Self::Uts(v) => v.nsfs_ino(),
            Self::Mnt(v) => v.nsfs_ino(), Self::Net(v) => v.identity().nsfs_ino,
        }
    }

}

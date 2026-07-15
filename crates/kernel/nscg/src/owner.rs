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

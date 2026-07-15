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
            Self::Cgroup(v) => Self::Cgroup(v.clone()), Self::Ipc(v) => Self::Ipc(v.clone()),
            Self::Pid(v) => Self::Pid(v.clone()), Self::Time(v) => Self::Time(v.clone()),
            Self::User(v) => Self::User(v.clone()), Self::Uts(v) => Self::Uts(v.clone()),
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

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::registry;
use crate::{CGROUP_INIT_NSFS_INO, IPC_INIT_NSFS_INO, PID_INIT_NSFS_INO,
    TIME_INIT_NSFS_INO, USER_INIT_NSFS_INO, UTS_INIT_NSFS_INO};

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NamespaceKind { Cgroup, Ipc, Pid, Time, User, Uts }

impl NamespaceKind {
    /// Linux inode reserved for this initial namespace. # C: O(1)
    pub const fn initial_nsfs_ino(self) -> u64 {
        match self {
            Self::Cgroup => CGROUP_INIT_NSFS_INO,
            Self::Ipc    => IPC_INIT_NSFS_INO,
            Self::Pid    => PID_INIT_NSFS_INO,
            Self::Time   => TIME_INIT_NSFS_INO,
            Self::User   => USER_INIT_NSFS_INO,
            Self::Uts    => UTS_INIT_NSFS_INO,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NamespaceId(pub(crate) u64);

impl NamespaceId {
    /// Numeric namespace registry key. # C: O(1)
    pub const fn as_u64(self) -> u64 { self.0 }
}

pub type NamespaceRef = Arc<Namespace>;
pub type NamespaceFinalizer = fn(NamespaceKind, NamespaceId);

pub(crate) enum Owner {
    InitialUser,
    Ref(NamespaceRef),
}

pub struct Namespace {
    pub(crate) kind: NamespaceKind,
    pub(crate) id: NamespaceId,
    pub(crate) nsfs_ino: u64,
    pub(crate) owner_user_namespace: Owner,
    pub(crate) parent: Option<NamespaceRef>,
    pub(crate) finalizers: crate::sync::SpinLock<Vec<NamespaceFinalizer>>,
}

impl Namespace {
    /// Globally unique non-init namespace ID. # C: O(1)
    pub const fn id(&self) -> NamespaceId { self.id }

    /// Stable nsfs inode, including Linux's exact init constants. # C: O(1)
    pub const fn nsfs_ino(&self) -> u64 { self.nsfs_ino }

    /// Namespace family carried by this identity. # C: O(1)
    pub const fn kind(&self) -> NamespaceKind { self.kind }

    /// Exact user namespace that owns this namespace. # C: O(1), except first init
    pub fn owner_user_namespace(&self) -> NamespaceRef {
        match &self.owner_user_namespace {
            Owner::InitialUser => registry::initial(NamespaceKind::User),
            Owner::Ref(owner) => Arc::clone(owner),
        }
    }

    /// Retained hierarchical parent, when this namespace kind has one. # C: O(1)
    pub fn parent(&self) -> Option<NamespaceRef> { self.parent.as_ref().map(Arc::clone) }

    /// Whether this is the canonical initial owner for its kind. # C: O(1)
    pub const fn is_initial(&self) -> bool { self.id.0 == 0 }

    /// Attach subsystem teardown to this exact owner. Duplicate registration
    /// is idempotent. # C: O(N_finalizers)
    pub fn register_finalizer(&self, finalizer: NamespaceFinalizer) {
        let mut finalizers = self.finalizers.lock();
        if !finalizers.iter().any(|registered| *registered as usize == finalizer as usize) {
            finalizers.push(finalizer);
        }
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let finalizers = core::mem::take(&mut *self.finalizers.lock());
        for finalizer in finalizers { finalizer(self.kind, self.id); }
        registry::remove(self);
    }
}

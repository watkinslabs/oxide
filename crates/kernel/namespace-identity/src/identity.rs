use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::Deref;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::registry;

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NamespaceKind { Cgroup, Ipc, Mnt, Net, Pid, Time, User, Uts }

/// Linux `pidns_memfd_noexec_scope` values (`include/linux/pid_namespace.h`).
pub const PID_MEMFD_NOEXEC_SCOPE_EXEC: u8 = 0;
pub const PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL: u8 = 1;
pub const PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED: u8 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PidMemfdNoexecError { NotPidNamespace, OutOfRange, BelowParent }

impl NamespaceKind {
    pub(crate) const ALL: [Self; 8] = [Self::Cgroup, Self::Ipc, Self::Mnt,
        Self::Net, Self::Pid, Self::Time, Self::User, Self::Uts];

    pub(crate) const fn slot(self) -> usize {
        match self { Self::Cgroup => 0, Self::Ipc => 1, Self::Mnt => 2, Self::Net => 3,
            Self::Pid => 4, Self::Time => 5, Self::User => 6, Self::Uts => 7 }
    }

    /// Linux inode reserved for this initial namespace. # C: O(1)
    pub const fn initial_nsfs_ino(self) -> u64 {
        match self {
            Self::Cgroup => crate::CGROUP_INIT_NSFS_INO, Self::Ipc => crate::IPC_INIT_NSFS_INO,
            Self::Mnt => crate::MNT_INIT_NSFS_INO, Self::Net => crate::NET_INIT_NSFS_INO,
            Self::Pid => crate::PID_INIT_NSFS_INO, Self::Time => crate::TIME_INIT_NSFS_INO,
            Self::User => crate::USER_INIT_NSFS_INO, Self::Uts => crate::UTS_INIT_NSFS_INO,
        }
    }

    /// Linux global namespace-tree ID for this initial namespace. # C: O(1)
    pub const fn initial_ns_id(self) -> NsId {
        NsId(match self {
            Self::Ipc => crate::IPC_INIT_NS_ID, Self::Uts => crate::UTS_INIT_NS_ID,
            Self::User => crate::USER_INIT_NS_ID, Self::Pid => crate::PID_INIT_NS_ID,
            Self::Cgroup => crate::CGROUP_INIT_NS_ID, Self::Time => crate::TIME_INIT_NS_ID,
            Self::Net => crate::NET_INIT_NS_ID, Self::Mnt => crate::MNT_INIT_NS_ID,
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NsId(pub(crate) u64);
impl NsId { pub const fn as_u64(self) -> u64 { self.0 } }
impl NsId { pub const fn from_u64(value: u64) -> Self { Self(value) } }

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NamespaceId(pub(crate) u64);
impl NamespaceId { pub const fn as_u64(self) -> u64 { self.0 } }

pub struct NamespaceRef { pub(crate) inner: Arc<Namespace> }

impl NamespaceRef {
    pub(crate) fn new(inner: Arc<Namespace>) -> Self { Self { inner } }
    /// Compare exact canonical identities. # C: O(1)
    pub fn ptr_eq(left: &Self, right: &Self) -> bool { Arc::ptr_eq(&left.inner, &right.inner) }
    /// Create a weak identity handle whose upgrade acquires activity. # C: O(1)
    pub fn downgrade(owner: &Self) -> NamespaceWeak {
        NamespaceWeak { inner: Arc::downgrade(&owner.inner) }
    }
    /// Retain identity lifetime without retaining active-tree membership. # C: O(1)
    pub fn pin(&self) -> NamespacePin { NamespacePin { inner: Arc::clone(&self.inner) } }
    /// Active plus passive lifetime reference count. # C: O(1)
    pub fn strong_count(owner: &Self) -> usize { Arc::strong_count(&owner.inner) }
}

impl Clone for NamespaceRef { fn clone(&self) -> Self { registry::clone_active(self) } }
impl Deref for NamespaceRef { type Target = Namespace; fn deref(&self) -> &Namespace { &self.inner } }
impl Drop for NamespaceRef { fn drop(&mut self) { registry::release_active(&self.inner); } }

pub struct NamespaceWeak { inner: Weak<Namespace> }
impl NamespaceWeak {
    /// Pin this exact identity only while it remains active. # C: O(log N)
    pub fn upgrade(&self) -> Option<NamespacePin> { registry::upgrade_pin(&self.inner) }
    /// Whether passive or active lifetime ownership remains. # C: O(1)
    pub fn is_alive(&self) -> bool { self.inner.strong_count() != 0 }
}

pub struct NamespacePin { pub(crate) inner: Arc<Namespace> }
impl NamespacePin {
    pub(crate) fn from_arc(inner: Arc<Namespace>) -> Self { Self { inner } }
    /// Compare exact canonical identities. # C: O(1)
    pub fn ptr_eq(left: &Self, right: &Self) -> bool { Arc::ptr_eq(&left.inner, &right.inner) }
    /// Explicitly acquire active membership, including first activation. # C: O(depth)
    pub fn activate(&self) -> NamespaceRef { registry::acquire_active(Arc::clone(&self.inner)) }
    /// Acquire active membership only if already active. # C: O(log N)
    pub fn get_active(&self) -> Option<NamespaceRef> { registry::get_active(&self.inner) }
    /// Create a weak identity handle. # C: O(1)
    pub fn downgrade(owner: &Self) -> NamespaceWeak {
        NamespaceWeak { inner: Arc::downgrade(&owner.inner) }
    }
    /// Active plus passive lifetime reference count. # C: O(1)
    pub fn strong_count(owner: &Self) -> usize { Arc::strong_count(&owner.inner) }
}
impl Clone for NamespacePin { fn clone(&self) -> Self { Self::from_arc(Arc::clone(&self.inner)) } }
impl Deref for NamespacePin { type Target = Namespace; fn deref(&self) -> &Namespace { &self.inner } }

pub trait NamespaceHandle {
    /// Acquire explicit membership only when this handle names an active identity. # C: O(log N)
    fn get_active_ref(&self) -> Option<NamespaceRef>;
}

impl NamespaceHandle for NamespaceRef {
    fn get_active_ref(&self) -> Option<NamespaceRef> { Some(self.clone()) }
}

impl NamespaceHandle for NamespacePin {
    fn get_active_ref(&self) -> Option<NamespaceRef> { self.get_active() }
}

pub type NamespaceFinalizer = fn(NamespaceKind, NamespaceId);
pub(crate) enum Owner { InitialUser, Ref(NamespacePin) }

pub struct Namespace {
    pub(crate) kind: NamespaceKind,
    pub(crate) id: NamespaceId,
    pub(crate) ns_id: NsId,
    pub(crate) nsfs_ino: u64,
    pub(crate) owner_user_namespace: Owner,
    pub(crate) parent: Option<NamespacePin>,
    /// `struct pid_namespace::memfd_noexec_scope`; zero for non-PID kinds.
    pub(crate) pid_memfd_noexec_scope: AtomicU8,
    /// `struct pid_namespace`'s number space; inert for non-PID kinds.
    pub(crate) pid_numbers: crate::pid_numbers::PidNumberSpace,
    pub(crate) active: AtomicUsize,
    pub(crate) finalizers: crate::sync::SpinLock<Vec<NamespaceFinalizer>>,
}

impl Namespace {
    pub const fn id(&self) -> NamespaceId { self.id }
    pub const fn ns_id(&self) -> NsId { self.ns_id }
    pub const fn nsfs_ino(&self) -> u64 { self.nsfs_ino }
    pub const fn kind(&self) -> NamespaceKind { self.kind }
    pub fn owner_user_namespace(&self) -> NamespacePin {
        match &self.owner_user_namespace {
            Owner::InitialUser => registry::initial_pin(NamespaceKind::User),
            Owner::Ref(owner) => owner.clone(),
        }
    }
    pub fn parent(&self) -> Option<NamespacePin> { self.parent.clone() }
    /// Numbering authority this PID namespace owns. # C: O(1)
    pub fn pid_numbers(&self) -> &crate::pid_numbers::PidNumberSpace { &self.pid_numbers }
    pub const fn is_initial(&self) -> bool { self.id.0 == 0 }
    /// Effective `vm.memfd_noexec`, including every ancestor's floor.
    /// # C: O(PID namespace depth)
    pub fn pid_memfd_noexec_scope(&self) -> Result<u8, PidMemfdNoexecError> {
        if self.kind != NamespaceKind::Pid {
            return Err(PidMemfdNoexecError::NotPidNamespace);
        }
        let mut scope = self.pid_memfd_noexec_scope.load(Ordering::Acquire);
        let mut parent = self.parent();
        while let Some(namespace) = parent {
            scope = scope.max(namespace.pid_memfd_noexec_scope.load(Ordering::Acquire));
            parent = namespace.parent();
        }
        Ok(scope)
    }
    /// Update this PID namespace's local scope. Linux refuses values below the
    /// effective parent scope, so descendants cannot weaken an outer policy.
    /// # C: O(PID namespace depth)
    pub fn set_pid_memfd_noexec_scope(&self, scope: u8)
        -> Result<(), PidMemfdNoexecError>
    {
        if self.kind != NamespaceKind::Pid {
            return Err(PidMemfdNoexecError::NotPidNamespace);
        }
        if scope > PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED {
            return Err(PidMemfdNoexecError::OutOfRange);
        }
        if let Some(parent) = self.parent() {
            if scope < parent.pid_memfd_noexec_scope()? {
                return Err(PidMemfdNoexecError::BelowParent);
            }
        }
        self.pid_memfd_noexec_scope.store(scope, Ordering::Release);
        Ok(())
    }
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

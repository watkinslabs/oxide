use alloc::sync::Arc;
use core::any::Any;

use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::namei::Cred;

/// Retained opener credentials for one open file description.
pub struct FileCred {
    dac: Cred,
    user_namespace: NamespaceRef,
    cap_effective: u64,
    /// LSM-specific credential state.  VFS owns the lifetime and leaves the
    /// concrete policy object to the consumer, keeping this credential record
    /// independent from any one security module.
    security: Option<Arc<dyn Any + Send + Sync>>,
}

impl FileCred {
    /// Build an exact opener-credential snapshot. # C: O(1)
    pub fn new(dac: Cred, user_namespace: NamespaceRef, cap_effective: u64) -> Self {
        Self { dac, user_namespace, cap_effective, security: None }
    }

    /// Initial-user-namespace root snapshot for anonymous/internal files. # C: O(1)
    pub fn root() -> Self {
        Self::new(Cred::root(), namespace_identity::initial(NamespaceKind::User), u64::MAX)
    }

    /// DAC subset retained for existing `f_cred` users. # C: O(1)
    pub const fn dac(&self) -> &Cred { &self.dac }

    /// Exact opener user namespace retained by this file. # C: O(1)
    pub fn user_namespace(&self) -> &NamespaceRef { &self.user_namespace }

    /// Whether one capability was in the opener's effective set. # C: O(1)
    pub const fn has_cap(&self, capability: u32) -> bool {
        capability < u64::BITS && self.cap_effective & (1u64 << capability) != 0
    }

    /// Attach one immutable security credential to this file snapshot. # C: O(1)
    pub fn with_security<T>(mut self, security: Option<Arc<T>>) -> Self
    where T: Any + Send + Sync,
    {
        self.security = security.map(|security| security as Arc<dyn Any + Send + Sync>);
        self
    }

    /// Recover a security credential carried by this open file description. # C: O(1)
    pub fn security<T>(&self) -> Option<Arc<T>>
    where T: Any + Send + Sync,
    {
        self.security.clone()?.downcast::<T>().ok()
    }
}

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::any::{Any, TypeId};

use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::namei::Cred;

/// Retained opener credentials for one open file description.
pub struct FileCred {
    dac: Cred,
    user_namespace: NamespaceRef,
    cap_effective: u64,
    /// Composite file-security blob, keyed by each LSM's private blob type.
    /// Linux assigns every active LSM an offset in one composite allocation;
    /// the type key is the Rust equivalent of that offset and prevents one
    /// module from replacing another module's state.
    security: BTreeMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl FileCred {
    /// Build an exact opener-credential snapshot. # C: O(1)
    pub fn new(dac: Cred, user_namespace: NamespaceRef, cap_effective: u64) -> Self {
        Self { dac, user_namespace, cap_effective, security: BTreeMap::new() }
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

    /// Attach or clear this LSM's immutable file blob without disturbing any
    /// other LSM's slot.  Blob types must be private to their owning module,
    /// just as Linux assigns an offset to each registered LSM. # C: O(log LSMs)
    pub fn with_security<T>(mut self, security: Option<Arc<T>>) -> Self
    where T: Any + Send + Sync,
    {
        let slot = TypeId::of::<T>();
        if let Some(security) = security {
            self.security.insert(slot, security as Arc<dyn Any + Send + Sync>);
        } else {
            self.security.remove(&slot);
        }
        self
    }

    /// Recover one LSM's blob from the composite file-security state. # C: O(log LSMs)
    pub fn security<T>(&self) -> Option<Arc<T>>
    where T: Any + Send + Sync,
    {
        self.security.get(&TypeId::of::<T>())?.clone().downcast::<T>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FirstLsm(u32);
    struct SecondLsm(&'static str);

    #[test]
    fn security_modules_keep_independent_file_slots() {
        let cred = FileCred::root()
            .with_security(Some(Arc::new(FirstLsm(7))))
            .with_security(Some(Arc::new(SecondLsm("second"))));

        assert_eq!(cred.security::<FirstLsm>().unwrap().0, 7);
        assert_eq!(cred.security::<SecondLsm>().unwrap().0, "second");
    }

    #[test]
    fn clearing_one_security_slot_preserves_the_others() {
        let cred = FileCred::root()
            .with_security(Some(Arc::new(FirstLsm(7))))
            .with_security(Some(Arc::new(SecondLsm("second"))))
            .with_security::<FirstLsm>(None);

        assert!(cred.security::<FirstLsm>().is_none());
        assert_eq!(cred.security::<SecondLsm>().unwrap().0, "second");
    }
}

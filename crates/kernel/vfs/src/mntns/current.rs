use sync::{MountTable as MountClass, Spinlock};

use super::{initial, MntNamespaceRef};

/// Typed scheduler boundary for retaining the calling task's mount namespace.
pub type NsProvider = fn() -> MntNamespaceRef;

static CURRENT_NS_PROVIDER: Spinlock<Option<NsProvider>, MountClass> = Spinlock::new(None);

/// Install the current mount namespace provider. # C: O(1)
pub fn set_current_ns_provider(provider: NsProvider) {
    *CURRENT_NS_PROVIDER.lock() = Some(provider);
}

/// Retain the calling task's canonical mount namespace owner. # C: O(1)
pub fn current_ns_owner() -> MntNamespaceRef {
    let provider = *CURRENT_NS_PROVIDER.lock();
    match provider { Some(provider) => provider(), None => initial() }
}

/// Current namespace ID for read-only mount-table queries. # C: O(1)
pub fn current_ns() -> u64 { current_ns_owner().id() }

pub use current_ns_owner as current_namespace;

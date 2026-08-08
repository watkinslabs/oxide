// The identity one set of counters hangs off: Linux `struct ucounts`'
// `{ns, uid}` pair.

use namespace_identity::NamespaceId;

/// A `(user namespace, uid)` pair. The uid is the INTERNAL id (Linux
/// `kuid_t`), never a namespace-relative one — the same uid seen from two
/// namespaces is one account and must share one count.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UcountKey { pub ns: u64, pub uid: u32 }

impl UcountKey {
    /// # C: O(1)
    pub const fn new(ns: u64, uid: u32) -> Self { Self { ns, uid } }

    /// Key for a namespace named by its canonical identity. # C: O(1)
    pub fn in_namespace(ns: NamespaceId, uid: u32) -> Self { Self { ns: ns.as_u64(), uid } }

    /// uid 0 of the initial user namespace. `RLIMIT_NPROC` is never enforced
    /// against it — an explicit exemption — which is what keeps a root fork
    /// bomb from locking root out of the machine entirely. # C: O(1)
    pub const INIT_USER: Self = Self { ns: 0, uid: 0 };

    /// Whether this key is [`Self::INIT_USER`]. # C: O(1)
    pub const fn is_init_user(&self) -> bool {
        self.ns == Self::INIT_USER.ns && self.uid == Self::INIT_USER.uid
    }
}

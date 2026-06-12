// Shared UTS namespace registry (Linux refcounted `struct uts_namespace`).
//
// A UTS namespace owns a {hostname, domainname} pair shared by every task
// in it: a `sethostname`/`setdomainname` by one member is visible to all,
// `fork` inherits the id (shares the entry), and `setns` repoints a task at
// an existing namespace. id 0 is the init/global namespace — NOT stored
// here; the caller (syscalls) maps id 0 onto the global hostname statics so
// existing readers (/proc/sys/kernel/hostname, gethostname) are unchanged.
// Ids ≥ 1 live in this registry.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

struct UtsNs {
    hostname: Vec<u8>,
    domainname: Vec<u8>,
}

static UTS: sync::Spinlock<BTreeMap<u64, UtsNs>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Allocate a new UTS namespace seeded with `hostname`/`domainname` (a copy
/// of the parent ns's names at unshare/clone time). Returns the new id (≥1).
/// # C: O(log N)
pub fn uts_alloc(hostname: Vec<u8>, domainname: Vec<u8>) -> u64 {
    let id = NEXT.fetch_add(1, Ordering::AcqRel);
    UTS.lock().insert(id, UtsNs { hostname, domainname });
    id
}

/// Hostname of namespace `id` (≥1). `None` if the id is unknown.
/// # C: O(log N)
pub fn uts_hostname(id: u64) -> Option<Vec<u8>> {
    UTS.lock().get(&id).map(|u| u.hostname.clone())
}

/// Domainname of namespace `id` (≥1). `None` if the id is unknown.
/// # C: O(log N)
pub fn uts_domainname(id: u64) -> Option<Vec<u8>> {
    UTS.lock().get(&id).map(|u| u.domainname.clone())
}

/// Set the hostname of namespace `id` (≥1). No-op if the id is unknown.
/// # C: O(log N)
pub fn uts_set_hostname(id: u64, hostname: Vec<u8>) {
    if let Some(u) = UTS.lock().get_mut(&id) {
        u.hostname = hostname;
    }
}

/// Set the domainname of namespace `id` (≥1). No-op if the id is unknown.
/// # C: O(log N)
pub fn uts_set_domainname(id: u64, domainname: Vec<u8>) {
    if let Some(u) = UTS.lock().get_mut(&id) {
        u.domainname = domainname;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_then_get_set_roundtrip() {
        let id = uts_alloc(b"host-a".to_vec(), b"dom-a".to_vec());
        assert_eq!(uts_hostname(id).as_deref(), Some(&b"host-a"[..]));
        assert_eq!(uts_domainname(id).as_deref(), Some(&b"dom-a"[..]));
        uts_set_hostname(id, b"host-b".to_vec());
        uts_set_domainname(id, b"dom-b".to_vec());
        assert_eq!(uts_hostname(id).as_deref(), Some(&b"host-b"[..]));
        assert_eq!(uts_domainname(id).as_deref(), Some(&b"dom-b"[..]));
    }

    #[test]
    fn distinct_ids_are_independent() {
        let a = uts_alloc(b"a".to_vec(), Vec::new());
        let b = uts_alloc(b"b".to_vec(), Vec::new());
        assert_ne!(a, b);
        uts_set_hostname(a, b"changed".to_vec());
        assert_eq!(uts_hostname(b).as_deref(), Some(&b"b"[..]), "ns b unaffected by ns a write");
    }

    #[test]
    fn unknown_id_is_none() {
        assert!(uts_hostname(9_999_999).is_none());
    }
}

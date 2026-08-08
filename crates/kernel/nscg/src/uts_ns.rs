// UTS state keyed by canonical namespace identity.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use namespace_identity::{Namespace, NamespaceId, NamespaceKind, NamespaceRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtsNames {
    pub hostname: Vec<u8>,
    pub domainname: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UtsError { WrongKind, InitialOwner, StateExists, StateMissing }

static UTS: sync::Spinlock<BTreeMap<NamespaceId, UtsNames>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

fn owner_id(owner: &Namespace) -> Result<NamespaceId, UtsError> {
    if owner.kind() != NamespaceKind::Uts { return Err(UtsError::WrongKind); }
    if owner.is_initial() { return Err(UtsError::InitialOwner); }
    Ok(owner.id())
}

fn remove(kind: NamespaceKind, id: NamespaceId) {
    if kind == NamespaceKind::Uts { UTS.lock().remove(&id); }
}

/// Initialize state for one exact non-init UTS owner. # C: O(log N)
pub fn allocate(owner: &NamespaceRef, hostname: Vec<u8>, domainname: Vec<u8>)
    -> Result<(), UtsError>
{
    let id = owner_id(owner)?;
    let mut states = UTS.lock();
    if states.contains_key(&id) { return Err(UtsError::StateExists); }
    states.insert(id, UtsNames { hostname, domainname });
    drop(states);
    owner.register_finalizer(remove);
    Ok(())
}

/// Snapshot both names from one exact non-init UTS owner. # C: O(log N)
pub fn snapshot<H: core::ops::Deref<Target = Namespace>>(owner: &H) -> Result<UtsNames, UtsError> {
    let id = owner_id(owner)?;
    UTS.lock().get(&id).cloned().ok_or(UtsError::StateMissing)
}

/// Replace hostname for one exact non-init UTS owner. # C: O(log N)
pub fn set_hostname(owner: &NamespaceRef, hostname: Vec<u8>) -> Result<(), UtsError> {
    let id = owner_id(owner)?;
    let mut states = UTS.lock();
    let state = states.get_mut(&id).ok_or(UtsError::StateMissing)?;
    state.hostname = hostname;
    Ok(())
}

/// Replace domainname for one exact non-init UTS owner. # C: O(log N)
pub fn set_domainname(owner: &NamespaceRef, domainname: Vec<u8>) -> Result<(), UtsError> {
    let id = owner_id(owner)?;
    let mut states = UTS.lock();
    let state = states.get_mut(&id).ok_or(UtsError::StateMissing)?;
    state.domainname = domainname;
    Ok(())
}

#[cfg(test)]
pub(crate) fn contains(id: NamespaceId) -> bool {
    crate::test_support::assert_drop_isolation_held();
    UTS.lock().contains_key(&id)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> NamespaceRef {
        namespace_identity::allocate(NamespaceKind::Uts,
            namespace_identity::initial(NamespaceKind::User), None).unwrap()
    }

    #[test]
    fn clones_share_one_owner_state() {
        let owner = owner();
        let peer = owner.clone();
        allocate(&owner, b"host-a".to_vec(), b"dom-a".to_vec()).unwrap();
        set_hostname(&peer, b"host-b".to_vec()).unwrap();
        set_domainname(&owner, b"dom-b".to_vec()).unwrap();
        assert_eq!(snapshot(&peer).unwrap(), UtsNames {
            hostname: b"host-b".to_vec(), domainname: b"dom-b".to_vec(),
        });
    }

    #[test]
    fn exact_owners_are_isolated() {
        let first = owner();
        let second = owner();
        allocate(&first, b"first".to_vec(), Vec::new()).unwrap();
        allocate(&second, b"second".to_vec(), Vec::new()).unwrap();
        set_hostname(&first, b"changed".to_vec()).unwrap();
        assert_eq!(snapshot(&second).unwrap().hostname, b"second".to_vec());
    }

    #[test]
    fn owner_kind_and_init_are_validated() {
        let user = namespace_identity::initial(NamespaceKind::User);
        let init = namespace_identity::initial(NamespaceKind::Uts);
        assert_eq!(snapshot(&user), Err(UtsError::WrongKind));
        assert_eq!(snapshot(&init), Err(UtsError::InitialOwner));
    }

    #[test]
    fn final_owner_drop_removes_state() {
        let _isolation = crate::test_support::drop_isolation();
        let owner = owner();
        let id = owner.id();
        allocate(&owner, b"host".to_vec(), Vec::new()).unwrap();
        assert!(contains(id));
        drop(owner);
        assert!(!contains(id));
    }
}

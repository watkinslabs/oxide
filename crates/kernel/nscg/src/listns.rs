use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespacePin, NamespaceRef, NsId};

use crate::proc_ns::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsError { InvalidOwner, NoSuccessor }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsOwnerFilter { All, Current, NsId(u64) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsKind { Cgroup, Ipc, Mnt, Net, Pid, Time, User, Uts }

impl ListNsKind {
    pub const fn mask(self) -> u32 {
        match self {
            Self::Cgroup => CLONE_NEWCGROUP as u32, Self::Ipc => CLONE_NEWIPC as u32,
            Self::Mnt => CLONE_NEWNS as u32, Self::Net => CLONE_NEWNET as u32,
            Self::Pid => CLONE_NEWPID as u32, Self::Time => CLONE_NEWTIME as u32,
            Self::User => CLONE_NEWUSER as u32, Self::Uts => CLONE_NEWUTS as u32,
        }
    }

    fn identity(self) -> NamespaceKind {
        match self {
            Self::Cgroup => NamespaceKind::Cgroup, Self::Ipc => NamespaceKind::Ipc,
            Self::Mnt => NamespaceKind::Mnt, Self::Net => NamespaceKind::Net,
            Self::Pid => NamespaceKind::Pid, Self::Time => NamespaceKind::Time,
            Self::User => NamespaceKind::User, Self::Uts => NamespaceKind::Uts,
        }
    }
}

fn list_kind(kind: NamespaceKind) -> ListNsKind {
    match kind {
        NamespaceKind::Cgroup => ListNsKind::Cgroup, NamespaceKind::Ipc => ListNsKind::Ipc,
        NamespaceKind::Mnt => ListNsKind::Mnt, NamespaceKind::Net => ListNsKind::Net,
        NamespaceKind::Pid => ListNsKind::Pid, NamespaceKind::Time => ListNsKind::Time,
        NamespaceKind::User => ListNsKind::User, NamespaceKind::Uts => ListNsKind::Uts,
    }
}

pub struct ListNsEntry { owner: NamespacePin }
impl ListNsEntry {
    pub fn id(&self) -> u64 { self.owner.ns_id().as_u64() }
    pub fn kind(&self) -> ListNsKind { list_kind(self.owner.kind()) }
}

pub struct ListNsPage { entries: Vec<ListNsEntry> }
impl ListNsPage {
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn entry(&self, index: usize) -> Option<&ListNsEntry> { self.entries.get(index) }
    pub fn id(&self, index: usize) -> Option<u64> { self.entry(index).map(ListNsEntry::id) }
}

fn requested_owner(caller: &sched::Task, filter: ListNsOwnerFilter)
    -> Result<Option<NamespacePin>, ListNsError>
{
    match filter {
        ListNsOwnerFilter::All => Ok(None),
        ListNsOwnerFilter::Current => caller.namespace_owner(NamespaceKind::User)
            .map(|owner| Some(owner.pin())).ok_or(ListNsError::InvalidOwner),
        ListNsOwnerFilter::NsId(id) => namespace_identity::lookup_ns_id(NsId::from_u64(id))
            .filter(|owner| owner.kind() == NamespaceKind::User)
            .map(Some).ok_or(ListNsError::InvalidOwner),
    }
}

fn requested_kind(mask: u32) -> Option<ListNsKind> {
    [ListNsKind::Cgroup, ListNsKind::Ipc, ListNsKind::Mnt, ListNsKind::Net,
        ListNsKind::Pid, ListNsKind::Time, ListNsKind::User, ListNsKind::Uts]
        .into_iter().find(|kind| kind.mask() == mask)
}

fn current_exact(caller: &sched::Task, owner: &NamespacePin) -> bool {
    match owner.kind() {
        NamespaceKind::Mnt => caller.mount_namespace_snapshot()
            .is_some_and(|current| NamespacePin::ptr_eq(&current.namespace_identity(), owner)),
        NamespaceKind::Net => caller.network_namespace_snapshot()
            .is_some_and(|current| NamespacePin::ptr_eq(&current.namespace_identity(), owner)),
        kind => caller.namespace_owner(kind)
            .is_some_and(|current| NamespacePin::ptr_eq(&current.pin(), owner)),
    }
}

fn may_see_all(caller: &sched::Task) -> bool {
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let init_pid = namespace_identity::initial(NamespaceKind::Pid);
    caller.has_cap(sched::cap::SYS_ADMIN)
        && caller.namespace_owner(NamespaceKind::User)
            .is_some_and(|owner| NamespaceRef::ptr_eq(&owner, &init_user))
        && caller.namespace_owner(NamespaceKind::Pid)
            .is_some_and(|owner| NamespaceRef::ptr_eq(&owner, &init_pid))
}

fn candidates(cursor: NsId, mask: u32, owner: Option<&NamespacePin>) -> Vec<NamespacePin> {
    #[cfg(test)]
    crate::test_support::assert_registry_scan_held();
    if let Some(owner) = owner {
        return namespace_identity::active_owner_page(owner, cursor, usize::MAX);
    }
    if let Some(kind) = requested_kind(mask) {
        return namespace_identity::active_kind_page(kind.identity(), cursor, usize::MAX);
    }
    namespace_identity::active_page(cursor, usize::MAX)
}

/// Enumerate one page directly from canonical active indexes. # C: O(N)
pub fn listns_page(caller: &sched::Task, cursor: u64, mask: u32,
    filter: ListNsOwnerFilter, capacity: usize) -> Result<ListNsPage, ListNsError>
{
    let requested = requested_owner(caller, filter)?;
    let start = NsId::from_u64(if cursor == u64::MAX { 0 } else { cursor });
    let structural = candidates(start, mask, requested.as_ref());
    if cursor != 0 && cursor != u64::MAX && structural.is_empty() {
        return Err(ListNsError::NoSuccessor);
    }
    let privileged = may_see_all(caller);
    let entries = structural.into_iter()
        .filter(|owner| mask == 0 || list_kind(owner.kind()).mask() & mask != 0)
        .filter(|owner| privileged || current_exact(caller, owner))
        .take(capacity).map(|owner| ListNsEntry { owner }).collect();
    Ok(ListNsPage { entries })
}

#[cfg(test)]
mod tests;

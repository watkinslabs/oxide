use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::owner::NsOwner;
use crate::proc_ns::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsError { InvalidOwner, NoSuccessor }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsOwnerFilter { All, Current, NsId(u64) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsKind { Cgroup, Ipc, Mnt, Net, Pid, Time, User, Uts }

impl ListNsKind {
    /// Linux namespace-type bit used by listns filtering. # C: O(1)
    pub const fn mask(self) -> u32 {
        match self {
            Self::Cgroup => CLONE_NEWCGROUP as u32, Self::Ipc => CLONE_NEWIPC as u32,
            Self::Mnt => CLONE_NEWNS as u32, Self::Net => CLONE_NEWNET as u32,
            Self::Pid => CLONE_NEWPID as u32, Self::Time => CLONE_NEWTIME as u32,
            Self::User => CLONE_NEWUSER as u32, Self::Uts => CLONE_NEWUTS as u32,
        }
    }
}

/// One typed namespace ID retaining its exact concrete owner.
pub struct ListNsEntry { owner: NsOwner }

impl ListNsEntry {
    /// Linux global namespace-tree ID. # C: O(1)
    pub fn id(&self) -> u64 { self.owner.ns_id() }

    /// Concrete namespace family. # C: O(1)
    pub fn kind(&self) -> ListNsKind { self.owner.kind() }
}

/// One retained, sorted listns result page.
pub struct ListNsPage { entries: Vec<ListNsEntry> }

impl ListNsPage {
    /// Number of returned namespace IDs. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether no visible requested namespace fit this page. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Typed retained entry at `index`. # C: O(1)
    pub fn entry(&self, index: usize) -> Option<&ListNsEntry> { self.entries.get(index) }

    /// Linux global namespace-tree ID at `index`. # C: O(1)
    pub fn id(&self, index: usize) -> Option<u64> { self.entry(index).map(ListNsEntry::id) }
}

fn collect() -> Vec<ListNsEntry> {
    let mut entries = Vec::new();
    for namespace in namespace_identity::live_snapshot() {
        let owner = match namespace.kind() {
            NamespaceKind::Cgroup => NsOwner::Cgroup(namespace),
            NamespaceKind::Ipc => NsOwner::Ipc(namespace),
            NamespaceKind::Pid => NsOwner::Pid(namespace),
            NamespaceKind::Time => NsOwner::Time(namespace),
            NamespaceKind::User => NsOwner::User(namespace),
            NamespaceKind::Uts => NsOwner::Uts(namespace),
        };
        entries.push(ListNsEntry { owner });
    }
    entries.extend(vfs::mntns::live_snapshot().into_iter()
        .map(|owner| ListNsEntry { owner: NsOwner::Mnt(owner) }));
    entries.extend(network_namespace::live_snapshot().into_iter()
        .map(|owner| ListNsEntry { owner: NsOwner::Net(owner) }));
    entries.sort_unstable_by_key(ListNsEntry::id);
    entries
}

fn requested_owner(caller: &sched::Task, filter: ListNsOwnerFilter,
    entries: &[ListNsEntry]) -> Result<Option<NamespaceRef>, ListNsError>
{
    match filter {
        ListNsOwnerFilter::All => Ok(None),
        ListNsOwnerFilter::Current => caller.namespace_owner(NamespaceKind::User)
            .map(Some).ok_or(ListNsError::InvalidOwner),
        ListNsOwnerFilter::NsId(id) => entries.iter().find_map(|entry| match &entry.owner {
            NsOwner::User(owner) if owner.ns_id().as_u64() == id => Some(Arc::clone(owner)),
            _ => None,
        }).map(Some).ok_or(ListNsError::InvalidOwner),
    }
}

fn directly_owned(entry: &ListNsEntry, requested: &NamespaceRef) -> bool {
    if matches!(&entry.owner, NsOwner::User(owner) if Arc::ptr_eq(owner, requested)) {
        return false;
    }
    Arc::ptr_eq(&entry.owner.owner_user_namespace(), requested)
}

fn current_exact(caller: &sched::Task, owner: &NsOwner) -> bool {
    match owner {
        NsOwner::Cgroup(v) => caller.namespace_owner(NamespaceKind::Cgroup)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Ipc(v) => caller.namespace_owner(NamespaceKind::Ipc)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Pid(v) => caller.namespace_owner(NamespaceKind::Pid)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Time(v) => caller.namespace_owner(NamespaceKind::Time)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::User(v) => caller.namespace_owner(NamespaceKind::User)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Uts(v) => caller.namespace_owner(NamespaceKind::Uts)
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Mnt(v) => caller.mount_namespace_snapshot()
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
        NsOwner::Net(v) => caller.network_namespace_snapshot()
            .is_some_and(|current| Arc::ptr_eq(&current, v)),
    }
}

fn may_see_all(caller: &sched::Task) -> bool {
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let init_pid = namespace_identity::initial(NamespaceKind::Pid);
    caller.has_cap(sched::cap::SYS_ADMIN)
        && caller.namespace_owner(NamespaceKind::User)
            .is_some_and(|owner| Arc::ptr_eq(&owner, &init_user))
        && caller.namespace_owner(NamespaceKind::Pid)
            .is_some_and(|owner| Arc::ptr_eq(&owner, &init_pid))
}

fn structural(entry: &ListNsEntry, mask: u32, requested: Option<&NamespaceRef>) -> bool {
    if let Some(owner) = requested { return directly_owned(entry, owner); }
    mask.count_ones() != 1 || entry.kind().mask() == mask
}

/// Enumerate one Linux-shaped page from active namespace owner trees. Entries
/// retain exact owners through publication. # C: O(N log N)
pub fn listns_page(caller: &sched::Task, cursor: u64, mask: u32,
    filter: ListNsOwnerFilter, capacity: usize) -> Result<ListNsPage, ListNsError>
{
    let entries = collect();
    let requested = requested_owner(caller, filter, &entries)?;
    let start = if cursor == 0 { 0 } else {
        let minimum = cursor.wrapping_add(1);
        entries.iter().position(|entry| entry.id() >= minimum
            && structural(entry, mask, requested.as_ref()))
            .ok_or(ListNsError::NoSuccessor)?
    };
    let privileged = may_see_all(caller);
    let mut page = Vec::new();
    for entry in entries.into_iter().skip(start) {
        if !structural(&entry, mask, requested.as_ref()) { continue; }
        if mask != 0 && entry.kind().mask() & mask == 0 { continue; }
        if !privileged && !current_exact(caller, &entry.owner) { continue; }
        if page.len() == capacity { break; }
        page.push(entry);
    }
    Ok(ListNsPage { entries: page })
}

#[cfg(test)]
mod tests;

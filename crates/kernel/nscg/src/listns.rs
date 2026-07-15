use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::owner::NsOwner;
use crate::proc_ns::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsError { InvalidUserNamespace }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ListNsOwnerFilter { All, Current, NsfsIno(u64) }

struct ListNsEntry {
    owner: NsOwner,
}

impl ListNsEntry {
    fn id(&self) -> u64 { self.owner.ino() }
}

/// Retained, sorted point-in-time namespace enumeration.
pub struct ListNsSnapshot {
    entries: Vec<ListNsEntry>,
    _requested_owner: Option<NamespaceRef>,
}

impl ListNsSnapshot {
    /// Number of unique namespace IDs retained by this snapshot. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether this snapshot contains no namespace IDs. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Sorted namespace ID at `index`. # C: O(1)
    pub fn id(&self, index: usize) -> Option<u64> {
        self.entries.get(index).map(ListNsEntry::id)
    }

    /// First index whose namespace ID is greater than `last`. # C: O(log N)
    pub fn first_after(&self, last: u64) -> Option<usize> {
        let index = self.entries.partition_point(|entry| entry.id() <= last);
        (index < self.entries.len()).then_some(index)
    }
}

fn requested_owner(filter: ListNsOwnerFilter) -> Result<Option<NamespaceRef>, ListNsError> {
    match filter {
        ListNsOwnerFilter::All => Ok(None),
        ListNsOwnerFilter::Current => current_user_owner()
            .map(Some).ok_or(ListNsError::InvalidUserNamespace),
        ListNsOwnerFilter::NsfsIno(nsfs_ino) => {
            for tid in sched::registry::live_tids() {
                let Some(task) = sched::registry::lookup(tid) else { continue };
                let Some(owner) = task.namespace_owner(NamespaceKind::User) else { continue };
                if owner.nsfs_ino() == nsfs_ino { return Ok(Some(owner)); }
            }
            Err(ListNsError::InvalidUserNamespace)
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn current_user_owner() -> Option<NamespaceRef> {
    sched::live::current()?.namespace_owner(NamespaceKind::User)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_user_owner() -> Option<NamespaceRef> { None }

fn wanted(mask: u32, bit: u64) -> bool { mask == 0 || (mask & bit as u32) != 0 }

fn push(entries: &mut Vec<ListNsEntry>, owner: NsOwner, mask: u32, bit: u64) {
    if !wanted(mask, bit) { return; }
    entries.push(ListNsEntry { owner });
}

/// Enumerate one retained task-registry snapshot. Every returned ID keeps its
/// exact owner alive until `ListNsSnapshot` is dropped. # C: O(N_tasks log N)
pub fn listns_snapshot(mask: u32, filter: ListNsOwnerFilter)
    -> Result<ListNsSnapshot, ListNsError>
{
    let requested_owner = requested_owner(filter)?;
    let mut entries = Vec::new();
    for tid in sched::registry::live_tids() {
        let Some(task) = sched::registry::lookup(tid) else { continue };
        let Some(snapshot) = task.namespace_snapshot() else { continue };
        if requested_owner.as_ref().is_some_and(|requested|
            !Arc::ptr_eq(requested, &snapshot.user))
        {
            continue;
        }
        push(&mut entries, NsOwner::Mnt(snapshot.mount), mask, CLONE_NEWNS);
        push(&mut entries, NsOwner::Cgroup(snapshot.cgroup), mask, CLONE_NEWCGROUP);
        push(&mut entries, NsOwner::Uts(snapshot.uts), mask, CLONE_NEWUTS);
        push(&mut entries, NsOwner::Ipc(snapshot.ipc), mask, CLONE_NEWIPC);
        push(&mut entries, NsOwner::User(snapshot.user), mask, CLONE_NEWUSER);
        push(&mut entries, NsOwner::Pid(snapshot.pid), mask, CLONE_NEWPID);
        push(&mut entries, NsOwner::Time(snapshot.time), mask, CLONE_NEWTIME);
    }
    if wanted(mask, CLONE_NEWNET) {
        for namespace in network_namespace::live_snapshot() {
            if requested_owner.as_ref().is_some_and(|requested|
                !Arc::ptr_eq(requested, &namespace.owner_user_namespace()))
            {
                continue;
            }
            push(&mut entries, NsOwner::Net(namespace), mask, CLONE_NEWNET);
        }
    }
    entries.sort_unstable_by_key(ListNsEntry::id);
    entries.dedup_by_key(|entry| entry.id());
    Ok(ListNsSnapshot { entries, _requested_owner: requested_owner })
}

#[cfg(test)]
mod tests;

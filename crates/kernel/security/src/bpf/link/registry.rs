// The one BPF link id registry.
//
// Every fd-backed link kind — cgroup and LSM — draws its id from here, so
// LINK_GET_FD_BY_ID and LINK_GET_NEXT_ID see one id space rather than one
// per link kind. Entries are weak: a link whose last descriptor closed
// leaves a dead slot that the next lookup or walk prunes.
//
// Publication is two-phase. A reserved id is `Unsettled` and answers
// `-EAGAIN`: the object exists but the attachment it stands for has not
// been made observable, which is exactly the window a concurrent
// LINK_GET_FD_BY_ID must not be able to see through.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::InodeRef;

static NEXT_LINK_ID: AtomicU32 = AtomicU32::new(1);

pub(crate) enum LinkIdSlot {
    Unsettled,
    Settled(Weak<vfs::Inode>),
}

static LINKS_BY_ID: Spinlock<BTreeMap<u32, LinkIdSlot>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// Take the next free link id and mark it unsettled. # C: O(log links)
pub(crate) fn reserve_link_id() -> u32 {
    loop {
        let id = NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut links = LINKS_BY_ID.lock();
        if links.contains_key(&id) { continue; }
        links.insert(id, LinkIdSlot::Unsettled);
        return id;
    }
}

/// Publish a reserved id against its object. # C: O(log links)
pub(crate) fn settle_link_id(id: u32, inode: &InodeRef) {
    let old = LINKS_BY_ID.lock().insert(id, LinkIdSlot::Settled(Arc::downgrade(inode)));
    hal::kassert!(
        matches!(old, Some(LinkIdSlot::Unsettled)),
        "settling an unreserved BPF link ID"
    );
}

/// Release a reserved id whose object never came into existence.
/// # C: O(log links)
pub(crate) fn cancel_link_id(id: u32) {
    let mut links = LINKS_BY_ID.lock();
    if matches!(links.get(&id), Some(LinkIdSlot::Unsettled)) { links.remove(&id); }
}

/// Register an already-live link that has no reservation window: the
/// object and its attachment came into being together, so the id is
/// observable from the moment it exists. # C: O(log links)
pub(crate) fn publish_link_id(inode: &InodeRef) -> u32 {
    let id = reserve_link_id();
    settle_link_id(id, inode);
    id
}

/// Resolve a settled link by id. Id 0 and an unknown id are `-ENOENT`; a
/// reserved-but-unpublished id is `-EAGAIN`. # C: O(log links)
pub(crate) fn link_by_id(id: u32) -> Result<InodeRef, Errno> {
    if id == 0 { return Err(Errno::Enoent); }
    let mut links = LINKS_BY_ID.lock();
    match links.get(&id) {
        Some(LinkIdSlot::Unsettled) => Err(Errno::Eagain),
        Some(LinkIdSlot::Settled(link)) => match link.upgrade() {
            Some(inode) => Ok(inode),
            None => { links.remove(&id); Err(Errno::Enoent) }
        },
        None => Err(Errno::Enoent),
    }
}

/// Lowest live link id strictly above `start`. # C: O(live links)
pub(crate) fn next_live_link_id(start: u32) -> Option<u32> {
    let mut links = LINKS_BY_ID.lock();
    let id = links.range((core::ops::Bound::Excluded(start), core::ops::Bound::Unbounded))
        .find_map(|(id, slot)| match slot {
            LinkIdSlot::Settled(link) if link.strong_count() != 0 => Some(*id),
            _ => None,
        });
    links.retain(|_, slot| match slot {
        LinkIdSlot::Unsettled => true,
        LinkIdSlot::Settled(link) => link.strong_count() != 0,
    });
    id
}

/// Drop an id whose object is going away. # C: O(log links)
pub(crate) fn forget_link_id(id: u32) { LINKS_BY_ID.lock().remove(&id); }

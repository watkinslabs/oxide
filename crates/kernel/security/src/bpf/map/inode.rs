// Map object: the fd-backed inode and the map id registry.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

use super::super::{BPF_FD_MODE, ids};
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

/// Implemented map storage. `map_flags` retains the descriptor and
/// program-access contract; `MapStorage` owns the freeze/writer state.
pub struct BpfMapInode {
    pub id:          u32,
    pub map_type:    u32,
    pub(crate) storage: Arc<super::MapStorage>,
    pub max_entries: u32,
    pub key_size:    u32,
    pub value_size:  u32,
    pub map_flags:   u32,
}

static NEXT_MAP_ID: AtomicU32 = AtomicU32::new(1);
static MAPS_BY_ID: Spinlock<BTreeMap<u32, Weak<vfs::Inode>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

impl Drop for BpfMapInode {
    fn drop(&mut self) {
        let mut maps = MAPS_BY_ID.lock();
        if maps.get(&self.id).is_some_and(|weak| weak.strong_count() == 0) {
            maps.remove(&self.id);
        }
    }
}

/// # C: O(log maps)
pub(crate) fn next_map_id() -> u32 {
    loop {
        let id = NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut maps = MAPS_BY_ID.lock();
        if maps.get(&id).and_then(Weak::upgrade).is_none() { maps.remove(&id); return id; }
    }
}

/// # C: O(log maps)
pub(crate) fn map_by_id(id: u32) -> Option<InodeRef> {
    if id == 0 { return None; }
    let mut maps = MAPS_BY_ID.lock();
    let inode = maps.get(&id).and_then(Weak::upgrade);
    if inode.is_none() { maps.remove(&id); }
    inode
}

/// # C: O(live maps)
pub(crate) fn next_live_map_id(start: u32) -> Option<u32> {
    let mut maps = MAPS_BY_ID.lock();
    let id = maps.range((core::ops::Bound::Excluded(start), core::ops::Bound::Unbounded))
        .find_map(|(id, weak)| weak.upgrade().map(|_| *id));
    maps.retain(|_, weak| weak.strong_count() != 0);
    id
}

/// Build the `Arc<Inode>` for a freshly created BPF map. # C: O(1)
pub fn make_bpf_map_inode(m: BpfMapInode) -> InodeRef {
    let id = m.id;
    let mapping = m.storage.mmap_mapping();
    let builder = InodeBuilder::new(ids::INO_MAP, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .size(m.storage.mmap_size())
        .private(Arc::new(m));
    let inode = match mapping {
        Some(mapping) => builder.mapping(mapping).build(),
        None => builder.build(),
    };
    MAPS_BY_ID.lock().insert(id, Arc::downgrade(&inode));
    inode
}

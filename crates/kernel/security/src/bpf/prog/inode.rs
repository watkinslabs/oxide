// Loaded-program object: the fd-backed inode and the program id registry.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

use super::super::{BPF_FD_MODE, ids};

/// eBPF program loaded by `bpf(BPF_PROG_LOAD)`. Instruction bytes and
/// Linux program type stay coupled in the fd-backed inode's `i_private`.
pub struct BpfProgInode {
    pub id: u32,
    pub prog_type: u32,
    pub expected_attach_type: u32,
    /// Set only when verifier return-range analysis makes the expected
    /// attach direction part of the program's attach contract.
    pub enforce_expected_attach_type: bool,
    pub insns: Vec<u8>,
    /// Canonical program-owned map set. Relocation maps retain index order;
    /// explicit lifetime bindings append, and every entry pins its map.
    pub maps: Spinlock<Vec<InodeRef>, TaskListClass>,
}

static NEXT_PROG_ID: AtomicU32 = AtomicU32::new(1);
static PROGRAMS_BY_ID: Spinlock<BTreeMap<u32, Weak<vfs::Inode>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

impl Drop for BpfProgInode {
    fn drop(&mut self) {
        let mut programs = PROGRAMS_BY_ID.lock();
        if programs.get(&self.id).is_some_and(|weak| weak.strong_count() == 0) {
            programs.remove(&self.id);
        }
    }
}

fn next_prog_id() -> u32 {
    loop {
        let id = NEXT_PROG_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut programs = PROGRAMS_BY_ID.lock();
        match programs.get(&id).and_then(Weak::upgrade) {
            Some(_) => continue,
            None => {
                programs.remove(&id);
                return id;
            }
        }
    }
}

/// Resolve a live program by id. # C: O(log programs)
pub(crate) fn prog_by_id(id: u32) -> Option<InodeRef> {
    if id == 0 { return None; }
    let mut programs = PROGRAMS_BY_ID.lock();
    let inode = programs.get(&id).and_then(Weak::upgrade);
    if inode.is_none() { programs.remove(&id); }
    inode
}

/// Lowest live program id strictly above `start`, dropping dead entries as
/// the walk passes them. # C: O(live programs)
pub(crate) fn next_live_prog_id(start: u32) -> Option<u32> {
    let mut programs = PROGRAMS_BY_ID.lock();
    let id = programs.range((core::ops::Bound::Excluded(start), core::ops::Bound::Unbounded))
        .find_map(|(id, weak)| weak.upgrade().map(|_| *id));
    programs.retain(|_, weak| weak.strong_count() != 0);
    id
}

/// Build the `Arc<Inode>` for a loaded program (CharDev|0o600,
/// `i_size` = bytecode length). # C: O(1)
pub fn make_bpf_prog_inode(prog_type: u32, insns: Vec<u8>) -> InodeRef {
    make_bpf_prog_inode_with_meta(prog_type, 0, insns, Vec::new())
}

/// Build a loaded program with its attach contract and pinned map references.
/// # C: O(1)
pub fn make_bpf_prog_inode_with_meta(
    prog_type: u32,
    expected_attach_type: u32,
    insns: Vec<u8>,
    maps: Vec<InodeRef>,
) -> InodeRef {
    make_bpf_prog_inode_with_contract(prog_type, expected_attach_type, false, insns, maps)
}

/// Build a loaded program with the verifier-derived attach contract.
/// # C: O(1)
pub fn make_bpf_prog_inode_with_contract(
    prog_type: u32,
    expected_attach_type: u32,
    enforce_expected_attach_type: bool,
    insns: Vec<u8>,
    maps: Vec<InodeRef>,
) -> InodeRef {
    let size = insns.len() as u64;
    let id = next_prog_id();
    let inode = InodeBuilder::new(ids::INO_PROG, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .size(size)
        .private(Arc::new(BpfProgInode {
            id, prog_type, expected_attach_type, enforce_expected_attach_type,
            insns, maps: Spinlock::new(maps),
        }))
        .build();
    PROGRAMS_BY_ID.lock().insert(id, Arc::downgrade(&inode));
    inode
}

//! inode-D4 / superblock-D39: `SuperBlock::iput`'s last-ref (1→0) path routes
//! through the new defaulted `s_op` lifecycle hooks — `drop_inode` (keep vs
//! evict), `write_inode` (flush dirty metadata), `evict_inode` (terminal
//! clear). Default `drop_inode` = `generic_drop_inode` (evict iff
//! `i_nlink == 0 && i_count == 0`), so a still-linked inode is RETAINED cached
//! and an unlinked one is EVICTED; a backend may override all three.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vfs::inode::{Inode, I_CLEAR};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef, KResult,
    VfsError, I_FREEING,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tlcfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

/// Default `SuperOps` (statfs only) → default drop/write/evict_inode behaviour.
struct DefOps;
impl SuperOps for DefOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

/// Recording `SuperOps`: forces eviction and counts the hook calls.
struct RecOps { writes: Arc<AtomicUsize>, evicts: Arc<AtomicUsize> }
impl SuperOps for RecOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn drop_inode(&self, _i: &Inode) -> bool { true } // generic_delete_inode
    fn write_inode(&self, _i: &Inode, _wait: bool) -> KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst); Ok(())
    }
    fn evict_inode(&self, i: &Inode) {
        self.evicts.fetch_add(1, Ordering::SeqCst);
        i.set_state(I_FREEING | I_CLEAR, 0);
    }
}

fn sb_with(ops: Arc<dyn SuperOps>) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), ops, 0xABCD, 9, 4096, "tlcfs".into(), Arc::new(()))
}
fn reg(sb: &Arc<SuperBlock>, ino: u64, nlink: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(nlink).build()
}

/// Default `drop_inode`: a still-linked inode (`i_nlink > 0`) reaching i_count 0
/// is RETAINED — not marked freeing, still findable.
#[test]
fn default_retains_linked_inode_on_last_iput() {
    let sb = sb_with(Arc::new(DefOps));
    let i = sb.iget(11, || reg(&sb, 11, 1)); // i_count == 1, nlink == 1
    sb.iput(i.clone()); // 1 → 0, drop_inode == false (nlink 1)
    assert_eq!(i.i_state() & (I_FREEING | I_CLEAR), 0, "linked inode not evicted");
    assert!(sb.ilookup(11).is_some(), "retained in icache for reuse");
}

/// Default `drop_inode`: an UNLINKED inode (`i_nlink == 0`) reaching i_count 0
/// is EVICTED — `evict_inode` (default clear_inode) marks it freeing and the
/// icache slot is dropped.
#[test]
fn default_evicts_unlinked_inode_on_last_iput() {
    let sb = sb_with(Arc::new(DefOps));
    let i = sb.iget(12, || reg(&sb, 12, 0)); // nlink == 0
    sb.iput(i.clone()); // 1 → 0, drop_inode == true (nlink 0)
    assert_ne!(i.i_state() & I_FREEING, 0, "I_FREEING set by evict_inode");
    assert_ne!(i.i_state() & I_CLEAR, 0, "I_CLEAR set by evict_inode (clear_inode)");
    assert!(sb.ilookup(12).is_none(), "evicted slot removed from icache");
}

/// A non-last iput (count > 1) touches no hook.
#[test]
fn non_last_iput_runs_no_hook() {
    let w = Arc::new(AtomicUsize::new(0));
    let e = Arc::new(AtomicUsize::new(0));
    let sb = sb_with(Arc::new(RecOps { writes: w.clone(), evicts: e.clone() }));
    let i = sb.iget(13, || reg(&sb, 13, 1));
    i.igrab(); // count 1 → 2
    sb.iput(i.clone()); // 2 → 1, not last
    assert_eq!(w.load(Ordering::SeqCst), 0, "write_inode not called on non-last iput");
    assert_eq!(e.load(Ordering::SeqCst), 0, "evict_inode not called on non-last iput");
}

/// Overridden hooks fire on the last iput: write_inode then evict_inode.
#[test]
fn override_hooks_fire_on_last_iput() {
    let w = Arc::new(AtomicUsize::new(0));
    let e = Arc::new(AtomicUsize::new(0));
    let sb = sb_with(Arc::new(RecOps { writes: w.clone(), evicts: e.clone() }));
    let i = sb.iget(14, || reg(&sb, 14, 1)); // linked, but override forces evict
    sb.iput(i.clone()); // 1 → 0
    assert_eq!(w.load(Ordering::SeqCst), 1, "write_inode called once");
    assert_eq!(e.load(Ordering::SeqCst), 1, "evict_inode called once");
    assert_ne!(i.i_state() & I_FREEING, 0, "override evict marked freeing");
}

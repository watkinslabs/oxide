//! inode-i_state lifecycle: the `i_state` bit set on the per-SB icache covers
//! the full Linux eviction lifecycle, not just `I_NEW`/`I_DIRTY`/`I_FREEING`.
//! `I_WILL_FREE` (Linux `1<<4`, the `iput_final` pre-evict writeback window)
//! existed nowhere before, so the pervasive `(I_FREEING|I_WILL_FREE)`
//! dying-inode predicate Linux uses in `find_inode_fast` could not be
//! expressed and `ilookup`/`iget` would hand back a half-evicted inode.
//! This proves: the new `I_WILL_FREE`/`I_CLEAR` bits exist with the correct
//! Linux numeric reps, `SuperBlock::i_is_freeing` reports a dying inode,
//! `ilookup`/`iget` skip it, and `mark_inode_dirty`/`clear_inode` drive the
//! dirty + terminal states.

use std::sync::Arc;

use vfs::inode::{InodeBuilder, I_CLEAR, I_DIRTY_DATASYNC, I_DIRTY_PAGES, I_DIRTY_SYNC, I_WILL_FREE};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, KResult, VfsError, I_DIRTY,
    I_FREEING, I_NEW,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tstatefs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xBADCAFE, 7, 4096, "tstatefs".into(), Arc::new(()))
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Linux `include/linux/fs.h` numeric reps: the new bits sit at exactly the
/// Linux positions and `I_DIRTY` is the SYNC|DATASYNC|PAGES aggregate.
#[test]
fn i_state_bits_match_linux() {
    assert_eq!(I_DIRTY_SYNC, 1 << 0);
    assert_eq!(I_DIRTY_DATASYNC, 1 << 1);
    assert_eq!(I_DIRTY_PAGES, 1 << 2);
    assert_eq!(I_NEW, 1 << 3);
    assert_eq!(I_WILL_FREE, 1 << 4);
    assert_eq!(I_FREEING, 1 << 5);
    assert_eq!(I_CLEAR, 1 << 6);
    assert_eq!(I_DIRTY, I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES);
}

/// `I_WILL_FREE` marks the iput_final pre-evict window: `i_is_freeing` reports
/// the inode as dying and `ilookup` skips it (Linux `find_inode_fast`), even
/// though the `Arc` is still alive (held by the test). Clearing the bit
/// re-admits it.
#[test]
fn will_free_makes_inode_dying_and_unfindable() {
    let sb = sb();
    let _held = sb.iget(11, || file(11)); // keep the Arc alive past eviction marking
    assert!(!sb.i_is_freeing(11), "fresh inode is not freeing");
    assert_eq!(sb.ilookup(11).map(|i| i.ino()), Some(11), "findable before");

    sb.i_set_state(11, I_WILL_FREE, 0);
    assert!(sb.i_is_freeing(11), "I_WILL_FREE ⇒ i_is_freeing");
    assert!(sb.ilookup(11).is_none(), "ilookup skips a dying inode (I_WILL_FREE)");

    sb.i_set_state(11, 0, I_WILL_FREE); // writeback done, withdraw the marker
    assert!(!sb.i_is_freeing(11), "cleared ⇒ no longer freeing");
    assert_eq!(sb.ilookup(11).map(|i| i.ino()), Some(11), "findable again");
}

/// `I_FREEING` is the other half of the dying predicate; `iget` rebuilds
/// rather than returning the evicting inode (Linux skips it in find_inode_fast,
/// then allocates a fresh one).
#[test]
fn freeing_inode_is_rebuilt_by_iget() {
    let sb = sb();
    let first = sb.iget(12, || file(12));
    sb.i_set_state(12, I_FREEING, 0);
    assert!(sb.i_is_freeing(12), "marked freeing");
    let second = sb.iget(12, || file(12)); // must NOT hand back the freeing inode
    assert!(!Arc::ptr_eq(&first, &second), "iget rebuilds past a freeing slot");
    assert!(!sb.i_is_freeing(12), "rebuilt slot is live (not freeing)");
}

/// `mark_inode_dirty` (Linux `__mark_inode_dirty`) ORs only dirty bits; a
/// caller cannot smuggle a lifecycle bit through.
#[test]
fn mark_inode_dirty_sets_only_dirty_bits() {
    let sb = sb();
    let _i = sb.iget(13, || file(13));
    sb.mark_inode_dirty(13, I_DIRTY_SYNC | I_FREEING);
    assert_ne!(sb.i_state(13) & I_DIRTY_SYNC, 0, "dirty bit set");
    assert_eq!(sb.i_state(13) & I_FREEING, 0, "lifecycle bit masked out");
}

/// `clear_inode` (Linux fs/inode.c) is the terminal eviction state:
/// `I_FREEING | I_CLEAR`, every dirty bit dropped.
#[test]
fn clear_inode_is_terminal_state() {
    let sb = sb();
    let _i = sb.iget(14, || file(14));
    sb.mark_inode_dirty(14, I_DIRTY_PAGES);
    sb.clear_inode(14);
    let st = sb.i_state(14);
    assert_ne!(st & I_FREEING, 0, "I_FREEING set");
    assert_ne!(st & I_CLEAR, 0, "I_CLEAR set");
    assert_eq!(st & I_DIRTY, 0, "dirty bits cleared on terminal state");
}

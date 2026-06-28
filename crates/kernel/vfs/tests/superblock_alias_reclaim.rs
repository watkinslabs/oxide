//! Per-superblock inode-cache ALIAS lifecycle: the direct `i_drop_alias` /
//! `iforget` reclaim hooks (Linux `inode->i_dentry` unlink + `iput`/icache
//! removal). Validates the B2 (fd4dad65) alias-list + `Weak`-keyed icache
//! reclaim that ledger items D8/D15 (`i_dentry` alias list) and D20 (`s_inodes`
//! / inode cache) describe — the higher-level `d_add`/`d_drop` path is covered
//! by object_model.rs, but the SB-level `i_drop_alias` two branches
//! (reclaim-slot-when-empty-and-inode-gone vs keep-slot-while-inode-live) and
//! the raw `iforget` slot-removal hook had no direct regression. Proves-stale:
//! the methods already exist + pass; this pins their contract.
//!
//! No global state (per-SB icache + an unhashed `d_alloc` dentry only), so no
//! SERIAL guard is required.

use std::sync::{Arc, Weak};

use vfs::inode::Inode;
use vfs::superblock::{next_anon_dev, FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeRef, KResult, VfsError};

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "aliasfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_type: 0xA11A5, f_bsize: 4096, ..Default::default() }) }
}

/// Root directory inode; `i_sb` so `d_make_root` records the root alias.
struct RamDir { ino: u64, sb: Weak<SuperBlock> }
impl Inode for RamDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

/// A plain file inode whose only strong ref the test owns, so dropping it makes
/// the icache `Weak` go dead (Linux `i_count == 0`).
struct RamFile { ino: u64 }
impl Inode for RamFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn mount() -> Arc<SuperBlock> {
    let sb = SuperBlock::new(
        Arc::new(RamFsType), Arc::new(RamFsOps),
        0xA11A5, next_anon_dev(), 4096, "aliasfs".into(), Arc::new(()),
    );
    let root = Arc::new(RamDir { ino: 2, sb: Arc::downgrade(&sb) });
    vfs::d_make_root(root, &sb); // installs s_root, gives a parent for d_alloc
    sb
}

#[test]
fn i_drop_alias_removes_one_name_keeps_the_other() {
    let sb = mount();
    let root = sb.s_root().expect("s_root");
    let inode: InodeRef = Arc::new(RamFile { ino: 11 });
    // Two distinct names (hardlinks) for the one inode.
    let a = vfs::d_alloc(&root, "a");
    let b = vfs::d_alloc(&root, "b");
    sb.i_add_alias(&inode, &a);
    sb.i_add_alias(&inode, &b);
    assert_eq!(sb.i_aliases(11).len(), 2, "two names recorded for ino 11");
    // Drop ONE name; the other survives (unlink of one hardlink).
    sb.i_drop_alias(11, &a);
    let left = sb.i_aliases(11);
    assert_eq!(left.len(), 1, "one alias remains after dropping name 'a'");
    assert!(Arc::ptr_eq(&left[0], &b), "the surviving alias is name 'b'");
    // Inode still cached: a live alias (b) keeps the slot.
    assert!(sb.ilookup(11).is_some(), "inode slot retained while a name lives");
}

#[test]
fn i_drop_alias_keeps_slot_while_inode_still_live() {
    let sb = mount();
    let root = sb.s_root().expect("s_root");
    let inode: InodeRef = Arc::new(RamFile { ino: 12 });
    let a = vfs::d_alloc(&root, "only");
    sb.i_add_alias(&inode, &a);
    // Drop the LAST name but keep the inode Arc alive: the slot must survive
    // because its `Weak` still upgrades (Linux keeps an aliasless-but-referenced
    // inode resident).
    sb.i_drop_alias(12, &a);
    assert!(sb.i_aliases(12).is_empty(), "no names left after last drop");
    assert!(sb.ilookup(12).is_some(), "slot kept: inode Arc still live");
    drop(inode);
    // Now the Weak is dead AND the alias list is empty → the next sweep reclaims.
    assert!(sb.ilookup(12).is_none(), "dead inode no longer resolves");
}

#[test]
fn i_drop_alias_reclaims_slot_when_empty_and_inode_gone() {
    let sb = mount();
    let root = sb.s_root().expect("s_root");
    let inode: InodeRef = Arc::new(RamFile { ino: 13 });
    let a = vfs::d_alloc(&root, "x");
    sb.i_add_alias(&inode, &a);
    assert!(sb.ilookup(13).is_some(), "slot present after add");
    // Kill the inode FIRST (last `Arc` gone), THEN drop its last alias: the
    // empty-list-and-dead-inode branch of `i_drop_alias` removes the slot.
    drop(inode);
    sb.i_drop_alias(13, &a);
    assert!(sb.i_aliases(13).is_empty(), "alias list empty");
    assert!(sb.ilookup(13).is_none(), "slot reclaimed (inode gone + no aliases)");
}

#[test]
fn iforget_drops_cache_slot_even_with_live_ref() {
    let sb = mount();
    // `iforget` is the raw icache-removal hook: it drops the slot regardless of a
    // still-live inode `Arc` (Linux `iput`/cache-evict removing the hash slot).
    let held: InodeRef = sb.iget(21, || Arc::new(RamFile { ino: 21 }));
    assert!(sb.ilookup(21).is_some(), "iget cached the inode");
    sb.iforget(21);
    assert!(sb.ilookup(21).is_none(), "iforget removed the slot");
    assert_eq!(held.ino(), 21, "the held inode Arc is still usable after iforget");
}

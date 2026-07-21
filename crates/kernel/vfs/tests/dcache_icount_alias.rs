//! inode-D3 / D37: the DCACHE counts its inode holds. When a dcache primitive
//! binds an inode to a dentry (`d_add`/`d_instantiate`/`d_make_root`/…) the
//! dentry takes ONE `i_count` reference (`grab_inode_hold` → `igrab`); when the
//! dentry lets go (`d_delete` → `set_inode(None)`, or `Dentry::drop`) it releases
//! that reference (`dentry_iput` → `SuperBlock::iput`). This makes `i_count`
//! track (dentry aliases + open files), so the `iput` 1→0 path (drop_inode →
//! evict_inode) runs at the right time: an unlinked (`nlink == 0`) inode is
//! evicted only once its LAST counted holder (alias or open file) goes away — a
//! still-referenced inode is never evicted (no UAF). The RAW `Dentry::new`
//! constructor stays UNcounted, so the open-`File` igrab/iput path (proved by
//! `file_iput_igrab`) is unchanged and never double-counted.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    d_add, d_alloc, d_instantiate, d_make_root, default_file_ops, default_inode_ops, mk_mode,
    File, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "ticfs" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xF11D, 7, 4096, "ticfs".into(), Arc::new(()))
}
fn inode(sb: &Arc<SuperBlock>, ino: u64, ft: FileType, nlink: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(ft, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(nlink).build()
}
/// A root dentry over a fresh directory inode, for use as a `d_add` parent.
fn root(sb: &Arc<SuperBlock>) -> Arc<vfs::Dentry> {
    d_make_root(inode(sb, 1, FileType::Directory, 2), sb)
}

/// A dcache `d_add` bind takes one `i_count` reference; a `d_delete` (sole-user
/// negative transition) releases it. A still-linked inode (`nlink > 0`) is
/// RETAINED on release, not evicted.
#[test]
fn d_add_bind_bumps_and_release_lowers_icount() {
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, 20, FileType::Regular, 1); // born i_count == 1, nlink 1
    assert_eq!(ino.i_count(), 1, "fresh inode born i_count == 1");

    let d = d_add(&r, "f", ino.clone());
    assert_eq!(ino.i_count(), 2, "d_add bind took one counted i_count ref");
    assert!(d.holds_icount(), "dentry records its counted hold");

    vfs::dcache::d_delete(&d); // sole user → set_inode(None) → release
    assert_eq!(ino.i_count(), 1, "alias release lowered i_count");
    assert!(!d.holds_icount(), "released dentry no longer counted");
    assert!(sb.ilookup(20).is_some(), "nlink>0 → retained, not evicted");
}

/// A lookup's born/iget reference is released after `d_add`; the fresh dentry
/// must already own the durable count and inode alias before that release.
#[test]
fn fresh_d_add_keeps_inode_live_after_lookup_iput() {
    const LOOKUP_INO: u64 = 25;
    const DENTRY_HOLD: u32 = 1;
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, LOOKUP_INO, FileType::Regular, 1);

    let d = d_add(&r, "lookup", ino.clone());
    assert!(d.holds_icount(), "fresh d_add took the dentry count");
    assert_eq!(sb.i_aliases(LOOKUP_INO).len(), 1, "fresh d_add recorded its alias");
    vfs::file::iput(ino.clone());

    assert!(d.inode().is_some(), "lookup iput cannot evict a live dentry inode");
    assert!(d.holds_icount(), "dentry retains its durable inode count");
    assert_eq!(ino.i_count(), DENTRY_HOLD, "only the dentry count remains");
}

/// `d_instantiate` of a sole-owned dentry, then DROPPING the dentry, exercises
/// the `Dentry::drop` → `dentry_iput` release path (vs the `d_delete` path).
#[test]
fn dentry_drop_releases_counted_hold() {
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, 23, FileType::Regular, 1);
    let dd = d_alloc(&r, "k"); // negative, sole-owned by us (not cached in parent)
    d_instantiate(&dd, ino.clone());
    assert_eq!(ino.i_count(), 2, "d_instantiate took the counted hold");
    assert!(dd.holds_icount());

    // D12: Dentry::drop now DEFERS the counted-hold release via call_rcu
    // (Linux __d_free). The release lands after an RCU grace period, not
    // synchronously at drop.
    drop(dd); // last Arc → Dentry::drop → call_rcu(dentry_iput)
    assert_eq!(ino.i_count(), 2, "D12: release is deferred past a grace period, not immediate");
    vfs::rcu_barrier(); // flush the deferred reclaim
    assert_eq!(ino.i_count(), 1, "Dentry::drop released the counted hold after the grace period");
}

/// D12: the dentry's final inode reclaim (`iput`) is routed through an RCU
/// grace period — deferred at drop, run by the drain, with no leak. Mirrors
/// Linux `__d_free` via `call_rcu`.
#[test]
fn dentry_drop_defers_iput_to_grace_then_no_leak() {
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, 24, FileType::Regular, 1);
    let d = d_alloc(&r, "z");
    d_instantiate(&d, ino.clone());
    assert_eq!(ino.i_count(), 2, "instantiate took the counted hold");

    drop(d);
    // BEFORE a grace period: the reclaim has NOT run (deferred).
    assert_eq!(ino.i_count(), 2, "iput deferred — not run before a grace period");

    // AFTER a grace period (drained): the reclaim ran exactly once. No leak.
    vfs::rcu_barrier();
    assert_eq!(ino.i_count(), 1, "deferred iput ran exactly once after the grace period");
}

/// The eviction keystone: once the creator's `iget`/born reference is released
/// (Linux: consumed/transferred at instantiate), the LAST dentry alias drop of
/// an `nlink == 0` inode drives `i_count` 1→0 → `drop_inode` (nlink 0) →
/// `evict_inode` → the icache slot is dropped.
#[test]
fn last_alias_drop_of_unlinked_inode_evicts() {
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, 21, FileType::Regular, 0); // nlink 0 (unlinked-on-create)
    let d = d_add(&r, "g", ino.clone()); // count: born1 + grab = 2

    // Model the create/lookup caller transferring its born/iget reference to the
    // dentry (Linux `d_instantiate` consumes it): release that one ref.
    sb.iput(ino.clone()); // 2 → 1 (prior 2 ⇒ not last, no evict)
    assert_eq!(ino.i_count(), 1);
    assert!(sb.ilookup(21).is_some(), "still held by the alias → alive");

    vfs::dcache::d_delete(&d); // last alias → set_inode(None) → iput → 1 → 0 → evict
    assert!(sb.ilookup(21).is_none(), "last alias drop of nlink==0 inode evicted it");
}

/// An inode with an OPEN `File` is NOT evicted when its dentry alias drops — the
/// file's independent `i_count` hold keeps it alive; eviction waits for the file
/// close (the genuinely last reference).
#[test]
fn open_file_blocks_eviction_on_dentry_drop() {
    let sb = sb();
    let r = root(&sb);
    let ino = inode(&sb, 22, FileType::Regular, 0); // nlink 0
    let d = d_add(&r, "h", ino.clone()); // born1 + grab = 2
    let file = File::new(ino.clone(), d.clone(), OpenFlags::O_RDWR); // igrab = 3

    sb.iput(ino.clone()); // creator ref transfer: 3 → 2
    assert_eq!(ino.i_count(), 2);

    vfs::dcache::d_delete(&d); // alias drop: 2 → 1. File still holds → NOT evicted.
    assert!(sb.ilookup(22).is_some(), "open File keeps the unlinked inode alive");
    assert_eq!(ino.i_count(), 1, "only the open-file hold remains");

    drop(file); // last hold (file close) → iput → 1 → 0 → evict
    assert!(sb.ilookup(22).is_none(), "file close evicts the unlinked inode");
}

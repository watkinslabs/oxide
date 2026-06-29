//! superblock-D20 (`s_inodes` list): the per-superblock inode set is now
//! walkable as Linux `super_block.s_inodes` — `s_inodes()` returns every LIVE
//! cached inode in `ino` order, `for_each_inode` walks it without holding the
//! icache lock (so a callback may re-enter), and `nr_cached_inodes` reports slot
//! occupancy. Before this the icache was reachable only by single-`ino`
//! `iget`/`ilookup` — there was no ordered list view for quota/fsnotify/sync
//! sweeps to iterate.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::InodeBuilder;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, SuperBlock};

struct ListFs;
impl FileSystem for ListFs {
    fn name(&self) -> &str { "listfs" }
}

fn make_ramfile(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(ListFs), None, next_anon_dev(), String::from("listfs"))
}

#[test]
fn empty_sb_has_no_inodes() {
    let sb = sb();
    assert!(sb.s_inodes().is_empty());
    assert_eq!(sb.nr_cached_inodes(), 0);
}

#[test]
fn s_inodes_returns_live_inodes_in_ino_order() {
    let sb = sb();
    // Insert out of order; the BTreeMap-backed list must come back ascending.
    let _a = sb.iget(30, || make_ramfile(30));
    let _b = sb.iget(10, || make_ramfile(10));
    let _c = sb.iget(20, || make_ramfile(20));
    let inos: Vec<u64> = sb.s_inodes().iter().map(|i| i.ino()).collect();
    assert_eq!(inos, vec![10, 20, 30], "s_inodes is ino-ordered");
    assert_eq!(sb.nr_cached_inodes(), 3);
}

#[test]
fn s_inodes_skips_dead_slots() {
    let sb = sb();
    let _live = sb.iget(10, || make_ramfile(10));
    drop(sb.iget(20, || make_ramfile(20))); // only Arc dropped → Weak dead
    // The dead inode's slot lingers (lazy reclaim) but is NOT a live inode.
    let inos: Vec<u64> = sb.s_inodes().iter().map(|i| i.ino()).collect();
    assert_eq!(inos, vec![10], "dead-Weak slot excluded from the live list");
    // ...while nr_cached_inodes still counts the un-reclaimed slot occupancy.
    assert_eq!(sb.nr_cached_inodes(), 2, "slot still occupies the cache until touched");
}

#[test]
fn for_each_inode_visits_every_live_inode() {
    let sb = sb();
    let _a = sb.iget(1, || make_ramfile(1));
    let _b = sb.iget(2, || make_ramfile(2));
    let _c = sb.iget(3, || make_ramfile(3));
    let mut sum = 0u64;
    sb.for_each_inode(|i| sum += i.ino());
    assert_eq!(sum, 6, "callback ran once per live inode");
}

#[test]
fn for_each_inode_callback_may_reenter_sb() {
    let sb = sb();
    let _a = sb.iget(5, || make_ramfile(5));
    // The walk snapshots + drops the icache lock before the callback, so an
    // ilookup inside the body must not self-deadlock.
    let mut found = false;
    sb.for_each_inode(|i| { if sb.ilookup(i.ino()).is_some() { found = true; } });
    assert!(found, "re-entrant ilookup inside for_each_inode succeeds");
}

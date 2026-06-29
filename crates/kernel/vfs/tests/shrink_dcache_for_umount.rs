//! Umount-time FORCE teardown of a whole superblock dentry tree
//! (`shrink_dcache_for_umount`, Linux `fs/dcache.c` `do_one_tree`).
//!
//! [`vfs::dcache::shrink_dcache_sb`] is the GENTLE per-sb prune: it evicts only
//! UNUSED (`d_count == 0`) dentries and leaves in-use ones cached. That is wrong
//! for unmount — the mount is going away, so every dentry rooted at `s_root`
//! must be detached even if a holder still owns a reference. `shrink_dcache_for_umount`
//! is the aggressive teardown: it `mark_dead`s + `d_drop`s the ENTIRE tree
//! (root + every descendant) REGARDLESS of `d_count`, so no name resolves
//! afterward; the in-use dentry's memory frees when its holder finally `dput`s.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::{dget, dput, shrink_dcache_for_umount, shrink_dcache_sb};
use vfs::fs::FileSystem;
use vfs::inode::InodeRef;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Dentry, FileType, KResult, SbStatFs, SuperBlock, SuperOps};

/// Directory inode (default ops — its `lookup` is never exercised; the test
/// builds the dcache tree with explicit inodes via `d_add`).
fn dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}

struct NoopOps;
impl SuperOps for NoopOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn put_super(&self) {}
}

struct Fs;
impl FileSystem for Fs {
    fn name(&self) -> &str { "umountdc" }
    fn magic(&self) -> u64 { 0x554d }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(NoopOps)) }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(Fs), None, next_anon_dev(), String::from("umountdc"))
}

// Tests share the process-global dcache hash table + LRU; serialize so sibling
// tests' d_add/dput mutations can't race the force-teardown.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

fn root_in(sb: &Arc<SuperBlock>) -> Arc<Dentry> {
    vfs::dcache::d_make_root(dir(1), sb)
}

// The whole tree — including IN-USE dentries the gentle shrinker would keep —
// is detached: every name misses afterward, and the count covers root+subtree.
#[test]
fn force_detaches_entire_tree_including_in_use() {
    let _g = guard();
    let sb = sb();
    let r = root_in(&sb);
    let a = vfs::dcache::d_add(&r, "a", dir(10));
    let b = vfs::dcache::d_add(&a, "b", dir(11));
    let c = vfs::dcache::d_add(&b, "c", dir(12));
    let sib = vfs::dcache::d_add(&a, "d", dir(13));
    // Pin `c` (deep) and `b` so the GENTLE shrinker would refuse them.
    let hold_c = dget(&c);
    let hold_b = dget(&b);
    assert!(c.d_count() > 0 && b.d_count() > 0);

    // Sanity: gentle per-sb prune leaves the in-use path cached (motivates the
    // force variant). It reclaims at most the unused leaf `d`.
    let gentle = shrink_dcache_sb(&sb);
    assert!(gentle <= 1, "gentle shrink keeps in-use dentries, freed {gentle}");
    assert!(a.cached_child("b").is_some(), "in-use `b` survives gentle prune");

    // Re-add the unused sibling if the gentle pass took it, so the force count
    // is deterministic: root + a + b + c + d == 5.
    if a.cached_child("d").is_none() { vfs::dcache::d_add(&a, "d", dir(13)); }

    let detached = shrink_dcache_for_umount(&sb);
    assert_eq!(detached, 5, "root + a + b + c + d all detached");

    // No name resolves; in-use dentries are forgotten from their parents too.
    assert!(r.cached_child("a").is_none(), "`a` detached from root");
    assert!(a.cached_child("b").is_none(), "in-use `b` detached from `a`");
    assert!(b.cached_child("c").is_none(), "in-use `c` detached from `b`");
    assert!(a.cached_child("d").is_none(), "`d` detached from `a`");
    assert!(c.is_dead() && b.is_dead(), "in-use dentries stamped dead");
    assert!(vfs::dcache::d_lookup(&r, "a").is_none(), "global hash miss after umount");

    // Holders still own valid Arcs; their final dput just releases memory and
    // does NOT re-kill (dead count never returns to 0).
    let _ = sib;
    dput(hold_c);
    dput(hold_b);
}

// An sb whose root was never installed (or already torn down) detaches nothing.
#[test]
fn no_root_detaches_nothing() {
    let _g = guard();
    let sb = sb();
    assert_eq!(shrink_dcache_for_umount(&sb), 0, "no s_root -> nothing to do");
}

// A single-node tree (bare root, no children) detaches exactly the root.
#[test]
fn bare_root_detaches_one() {
    let _g = guard();
    let sb = sb();
    let _r = root_in(&sb);
    assert_eq!(shrink_dcache_for_umount(&sb), 1, "just the root");
}

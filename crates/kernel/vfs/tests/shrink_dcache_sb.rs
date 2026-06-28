//! dcache-LRU per-superblock reclaim (`shrink_dcache_sb`, Linux `fs/dcache.c`).
//!
//! The global [`vfs::dcache::shrink_dcache`] is a count-bounded two-hand-clock
//! shrinker that respects the `D_REFERENCED` bit, and `shrink_dcache_parent`
//! prunes one subtree. NEITHER evicts "every unused dentry of ONE superblock"
//! — the operation remount and per-sb `drop_caches` need. `shrink_dcache_sb`
//! is the aggressive per-sb prune: it ignores the referenced bit, evicts every
//! UNUSED (`d_count == 0`) dentry whose `d_sb` is the target sb, and leaves
//! in-use dentries AND dentries of OTHER superblocks untouched.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::{dget, dput, shrink_dcache_sb};
use vfs::fs::FileSystem;
use vfs::inode::InodeRef;
use vfs::superblock::next_anon_dev;
use vfs::{Dentry, FileType, KResult, SbStatFs, SuperBlock, SuperOps, VfsError};

struct Dir { ino: u64 }
impl vfs::Inode for Dir {
    fn ino(&self) -> u64 { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }

struct NoopOps;
impl SuperOps for NoopOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn put_super(&self) {}
}

struct Fs;
impl FileSystem for Fs {
    fn name(&self) -> &str { "shrinksb" }
    fn magic(&self) -> u64 { 0x5348 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(NoopOps)) }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(Fs), None, next_anon_dev(), String::from("shrinksb"))
}

// These tests share the process-global dcache LRU list; serialize so concurrent
// d_add/dput LRU mutations from sibling tests can't race the per-sb eviction count.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

/// Build a root dentry whose `d_sb` is `sb`; children inherit the sb.
fn root_in(sb: &Arc<SuperBlock>) -> Arc<Dentry> {
    vfs::dcache::d_make_root(dir(1), sb)
}

// A fresh dentry made unused (dget→dput-to-0) lands on the LRU; shrink_dcache_sb
// evicts every such dentry of the target sb and reports the count.
#[test]
fn evicts_all_unused_dentries_of_sb() {
    let _g = guard();
    let sb = sb();
    let r = root_in(&sb);
    let mut kids = Vec::new();
    for i in 0..50u32 {
        let c = vfs::dcache::d_add_negative(&r, &format!("n{i}"));
        let g = dget(&c); // count 1
        dput(g);          // back to 0 -> LRU
        kids.push(c);
    }
    let freed = shrink_dcache_sb(&sb);
    assert_eq!(freed, 50, "every unused dentry of the sb evicted in one pass");
    // Evicted dentries are unhashed + forgotten by the parent.
    for i in 0..50u32 {
        assert!(r.cached_child(&format!("n{i}")).is_none(), "n{i} still cached");
    }
}

// An IN-USE dentry (d_count > 0) of the target sb is NOT evicted.
#[test]
fn in_use_dentry_survives() {
    let _g = guard();
    let sb = sb();
    let r = root_in(&sb);
    let pinned = vfs::dcache::d_add_negative(&r, "pinned");
    let hold = dget(&pinned); // count 1 (held -> never on the LRU)
    let unused = vfs::dcache::d_add_negative(&r, "unused");
    let g = dget(&unused); dput(g); // -> LRU at count 0
    let freed = shrink_dcache_sb(&sb);
    assert_eq!(freed, 1, "only the unused dentry");
    assert!(r.cached_child("pinned").is_some(), "in-use dentry survived");
    assert!(r.cached_child("unused").is_none(), "unused dentry evicted");
    assert!(pinned.d_count() > 0);
    dput(hold);
}

// Dentries of a DIFFERENT superblock are left untouched.
#[test]
fn other_sb_dentries_untouched() {
    let _g = guard();
    let sb_a = sb();
    let sb_b = sb();
    let ra = root_in(&sb_a);
    let rb = root_in(&sb_b);
    let a = vfs::dcache::d_add_negative(&ra, "a");
    let b = vfs::dcache::d_add_negative(&rb, "b");
    for c in [&a, &b] { let g = dget(c); dput(g); } // both on LRU at count 0
    let freed = shrink_dcache_sb(&sb_a);
    assert_eq!(freed, 1, "only sb_a's dentry evicted");
    assert!(ra.cached_child("a").is_none(), "sb_a dentry evicted");
    assert!(rb.cached_child("b").is_some(), "sb_b dentry untouched");
}

//! dcache DCACHE_DONTCACHE: a dentry marked `d_mark_dontcache` (Linux, from an
//! `I_DONTCACHE` inode) is NOT retained on the LRU at the final `dput` — Linux
//! `retain_dentry` returns false for it — so it is killed (unhashed + forgotten)
//! the instant it goes unused, instead of lingering cached for the shrinker.

use std::sync::Arc;

use vfs::dentry::Dentry;
use vfs::inode::Inode;
use vfs::{d_add, dget, dput, FileType, InodeRef, KResult, VfsError};

struct Dir { ino: u64 }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }

// Control: an ordinary hashed dentry dropped to zero is RETAINED on the LRU
// (stays hashed + cached) — the shrinker reclaims it later.
#[test]
fn ordinary_hashed_dentry_is_retained_on_lru() {
    let r = Dentry::new_root(dir(1));
    let c = d_add(&r, "keep", dir(10)); // hashed, d_count 0
    let g = dget(&c);                   // 0 -> 1
    dput(g);                            // 1 -> 0: retained (hashed, not dontcache)
    assert!(c.is_hashed(), "retained dentry stays hashed");
    assert!(c.is_on_lru(), "retained dentry joins the LRU");
    assert!(r.cached_child("keep").is_some(), "still cached under the parent");
}

// DCACHE_DONTCACHE: same hashed dentry, but marked dontcache → the final dput
// kills it (unhashed, forgotten, never on the LRU).
#[test]
fn dontcache_dentry_is_killed_at_final_dput() {
    let r = Dentry::new_root(dir(2));
    let c = d_add(&r, "drop", dir(20)); // hashed, d_count 0
    assert!(c.is_hashed());
    c.set_dontcache(true);
    assert!(c.is_dontcache());

    let g = dget(&c); // 0 -> 1
    dput(g);          // 1 -> 0: DONTCACHE ⇒ dentry_kill, NOT lru_add

    assert!(!c.is_on_lru(), "dontcache dentry never joins the LRU");
    assert!(c.is_unhashed(), "dontcache dentry is unhashed at final dput");
    assert!(c.is_dead(), "kill stamped LOCKREF_DEAD");
    assert!(r.cached_child("drop").is_none(), "forgotten from the parent's d_subdirs");
}

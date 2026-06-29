//! dcache: `d_delete` (Linux fs/dcache.c). After a successful unlink/rmdir the
//! FS calls `d_delete` on the victim dentry. Linux turns a SOLE-USER dentry
//! NEGATIVE while keeping it HASHED (a cached miss, `dentry_unlink_inode`), and
//! UNHASHES (`d_drop`) a dentry that is SHARED (`d_count > 1`) or whose
//! `d_op->d_delete` opts out of caching negatives (`DCACHE_OP_DELETE`).
//!
//! Driven against a real ramfs SuperBlock so `i_sb()` resolves and the
//! `i_dentry` alias list (the inode↔dentry back-link) is exercised.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::d_delete;
use vfs::dentry::DentryOps;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dentry, FileType, InodeRef, KResult};

// These tests mutate the process-global dcache hash table; serialize them.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}
fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()))
}

// A pseudo-fs that opts out of caching negatives: d_op->d_delete returns true,
// so d_delete must DROP (unhash) rather than keep the dentry negative.
static DROP_OPS: DentryOps = DentryOps {
    d_delete: Some(|_d| true),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};

// SOLE-USER + default ops: d_delete turns the dentry NEGATIVE and keeps it
// HASHED so a later lookup of the absent name hits the cached miss.
#[test]
fn sole_user_becomes_cached_negative() {
    let _g = guard();
    let sb = mount_ramfs(1);
    let root = Dentry::new_root(ramdir(&sb, 2));
    let inode: InodeRef = ramfile(&sb, 50);
    let d = vfs::d_add(&root, "f", inode);
    assert!(d.is_hashed() && !d.is_negative(), "starts positive + hashed");
    assert_eq!(sb.i_aliases(50).len(), 1, "alias recorded");
    assert_eq!(d.d_count(), 0, "sole user (no extra holders)");

    d_delete(&d);

    assert!(d.is_negative(), "inode detached -> negative");
    assert!(d.is_hashed(), "kept hashed as a cached miss");
    assert_eq!(sb.i_aliases(50).len(), 0, "inode alias dropped");
    assert!(root.cached_child("f").is_some(), "still in parent d_subdirs");
    let hit = vfs::d_lookup(&root, "f").expect("negative cached miss is found");
    assert!(Arc::ptr_eq(&hit, &d) && hit.is_negative(), "lookup returns the negative");
}

// d_op->d_delete == true (DCACHE_OP_DELETE): d_delete DROPS (unhash + forget)
// instead of caching a negative, so a later lookup re-walks (misses the cache).
#[test]
fn d_op_delete_drops_instead_of_caching() {
    let _g = guard();
    let sb = mount_ramfs(2);
    let root = Dentry::new_root(ramdir(&sb, 2)).set_d_op(&DROP_OPS);
    let inode: InodeRef = ramfile(&sb, 60);
    let d = vfs::d_add(&root, "g", inode);
    assert!(d.is_hashed() && d.d_op().is_some(), "child inherited DROP_OPS");
    assert_eq!(sb.i_aliases(60).len(), 1);

    d_delete(&d);

    assert!(!d.is_hashed(), "DCACHE_OP_DELETE -> unhashed, not cached");
    assert!(root.cached_child("g").is_none(), "forgotten from parent d_subdirs");
    assert_eq!(sb.i_aliases(60).len(), 0, "inode alias dropped");
    assert!(vfs::d_lookup(&root, "g").is_none(), "lookup misses -> re-walk");
}

// SHARED (d_count > 1): another walker holds the positive view, so d_delete
// must DROP (unhash) rather than yank the inode out from under them.
#[test]
fn shared_dentry_is_dropped_not_negated() {
    let _g = guard();
    let sb = mount_ramfs(3);
    let root = Dentry::new_root(ramdir(&sb, 2));
    let inode: InodeRef = ramfile(&sb, 70);
    let d = vfs::d_add(&root, "h", inode);
    let h1 = vfs::dget(&d);
    let h2 = vfs::dget(&d);
    assert_eq!(d.d_count(), 2, "two extra holders -> shared");

    d_delete(&d);

    assert!(!d.is_hashed(), "shared dentry unhashed");
    assert!(!d.is_negative(), "inode left intact for the other users");
    assert!(vfs::d_lookup(&root, "h").is_none(), "no new lookup resurrects it");
    vfs::dput(h1);
    vfs::dput(h2);
}

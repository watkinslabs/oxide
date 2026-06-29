//! dcache-D: `d_prune_aliases` (Linux fs/dcache.c). Drop the UNUSED dentry
//! aliases of an inode an FS is forcing out of cache, leaving in-use (open /
//! CWD-held) aliases pinned. Driven against a real ramfs SuperBlock so
//! `i_sb()` resolves and the `i_dentry` alias list (hard-link aliases) works.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::dcache::d_prune_aliases;
use vfs::inode::Inode;
use vfs::{InodeBuilder, InodeOps, default_file_ops, default_inode_ops, mk_mode};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

/// Directory backend: child map lives in `i_private`; the namespace `lookup`
/// reads it off the concrete inode.
struct RamDirData { kids: Mutex<BTreeMap<String, InodeRef>> }
struct RamDirOps;
impl InodeOps for RamDirOps {
    fn lookup(&self, inode: &Inode, n: &str) -> KResult<InodeRef> {
        inode.private::<RamDirData>().unwrap().kids.lock().unwrap().get(n).cloned().ok_or(VfsError::Enoent)
    }
}

fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(RamDirOps), default_file_ops())
        .sb(Arc::downgrade(sb))
        .private(Arc::new(RamDirData { kids: Mutex::new(BTreeMap::new()) }))
        .build()
}
fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb))
        .build()
}

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    let sb = SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()));
    vfs::d_make_root(ramdir(&sb, 2), &sb);
    sb
}

// A hard-linked file (one inode, three names). All aliases unused → all pruned;
// the alias list empties and every dentry is unhashed + forgotten by its parent.
#[test]
fn prune_drops_all_unused_hardlink_aliases() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let inode: InodeRef = ramfile(&sb, 50);
    let a = vfs::d_add(&root, "a", inode.clone());
    let b = vfs::d_add(&root, "b", inode.clone());
    let c = vfs::d_add(&root, "c", inode.clone());
    assert_eq!(sb.i_aliases(50).len(), 3, "three hard-link aliases recorded");
    assert!(a.is_hashed() && b.is_hashed() && c.is_hashed());

    let freed = d_prune_aliases(&inode);
    assert_eq!(freed, 3, "all three unused aliases pruned");
    assert_eq!(sb.i_aliases(50).len(), 0, "alias list emptied");
    // d_drop side effects: unhashed + forgotten from the parent's d_subdirs.
    assert!(!a.is_hashed() && !b.is_hashed() && !c.is_hashed());
    assert!(root.cached_child("a").is_none());
    assert!(root.cached_child("b").is_none());
    assert!(root.cached_child("c").is_none());
    assert!(vfs::d_lookup(&root, "a").is_none());
}

// An in-use alias (d_count > 0, e.g. an open fd or CWD) is pinned and survives;
// only the unused sibling names are pruned.
#[test]
fn prune_pins_in_use_alias() {
    let sb = mount_ramfs(2);
    let root = sb.s_root().unwrap();
    let inode: InodeRef = ramfile(&sb, 60);
    let held = vfs::d_add(&root, "held", inode.clone());
    let _gone1 = vfs::d_add(&root, "gone1", inode.clone());
    let _gone2 = vfs::d_add(&root, "gone2", inode.clone());
    assert_eq!(sb.i_aliases(60).len(), 3);

    let hold = vfs::dget(&held); // d_count 1 -> in use
    assert_eq!(held.d_count(), 1);

    let freed = d_prune_aliases(&inode);
    assert_eq!(freed, 2, "only the two unused siblings pruned");
    let surv = sb.i_aliases(60);
    assert_eq!(surv.len(), 1, "the in-use alias survives");
    assert!(Arc::ptr_eq(&surv[0], &held));
    assert!(held.is_hashed(), "pinned alias stays hashed/cached");
    assert!(root.cached_child("held").is_some());
    assert!(root.cached_child("gone1").is_none());
    assert!(root.cached_child("gone2").is_none());
    vfs::dput(hold);
}

// Idempotent: a second prune after everything is unused/pruned is a no-op (0),
// and prune of an inode that never had an alias returns 0.
#[test]
fn prune_idempotent_and_no_alias_noop() {
    let sb = mount_ramfs(3);
    let root = sb.s_root().unwrap();
    let inode: InodeRef = ramfile(&sb, 70);
    let _a = vfs::d_add(&root, "x", inode.clone());
    assert_eq!(d_prune_aliases(&inode), 1);
    assert_eq!(d_prune_aliases(&inode), 0, "second prune is a no-op");

    let never: InodeRef = ramfile(&sb, 71); // no dentry ever made
    assert_eq!(d_prune_aliases(&never), 0, "no aliases -> nothing pruned");
}

// An sb-less inode tracks no aliases — prune is a graceful 0, no panic.
#[test]
fn prune_sbless_inode_graceful() {
    let inode: InodeRef = InodeBuilder::new(99, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build();
    let _d: Option<Arc<Dentry>> = None;
    assert_eq!(d_prune_aliases(&inode), 0);
}

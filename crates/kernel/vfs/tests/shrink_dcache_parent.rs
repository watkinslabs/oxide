//! dcache-D24: `shrink_dcache_parent` (Linux fs/dcache.c). Prune the UNUSED
//! dentries in the subtree under a given parent — the per-subtree counterpart
//! of the global `shrink_dcache` (remount / umount of a subtree / pre-rmdir
//! prune). An in-use descendant pins the path to it: its unused ancestors are
//! NOT prunable while a live child survives. Driven against a real ramfs
//! SuperBlock so `i_sb()` + the `i_dentry` alias list resolve.

use std::sync::Arc;

use vfs::dcache::shrink_dcache_parent;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{d_add, d_lookup, dget, dput, Dentry, FileType, InodeRef, KResult};

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

// Directory / regular inodes bound to the ramfs sb so `i_sb()` + the `i_dentry`
// alias list resolve. Default ops — the prune walks the dcache, never
// `inode.lookup`.
fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}
fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    let sb = SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()));
    vfs::d_make_root(ramdir(&sb, 2), &sb);
    sb
}

// Build:  root / a(dir) / { b(dir)/c(file), d(file) }  via the cache builders.
fn build_tree(sb: &Arc<SuperBlock>) -> (Arc<Dentry>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>) {
    let root = sb.s_root().unwrap();
    let a = d_add(&root, "a", ramdir(sb, 10));
    let b = d_add(&a, "b", ramdir(sb, 11));
    let c = d_add(&b, "c", ramfile(sb, 12));
    let d = d_add(&a, "d", ramfile(sb, 13));
    (root, a, b, c, d)
}

// With nothing in use, the entire subtree under `a` is pruned; `a` itself
// survives (we prune what is UNDER parent, not parent), with an empty subtree.
#[test]
fn prunes_whole_unused_subtree() {
    let sb = mount_ramfs(1);
    let (root, a, b, c, _d) = build_tree(&sb);
    assert!(d_lookup(&a, "b").is_some());
    assert!(d_lookup(&b, "c").is_some());

    let freed = shrink_dcache_parent(&a);
    assert_eq!(freed, 3, "b, c, d all unused -> all pruned");

    // Subtree gone from both the per-parent index and the global hash table.
    assert!(a.cached_child("b").is_none());
    assert!(a.cached_child("d").is_none());
    assert!(d_lookup(&a, "b").is_none());
    assert!(d_lookup(&b, "c").is_none());
    assert_eq!(c.flags() & vfs::dentry::D_HASHED, 0, "leaf unhashed");
    // `a` survives, still reachable under root.
    assert!(d_lookup(&root, "a").is_some());
    assert!(a.children_snapshot().is_empty());
}

// An in-use descendant pins the path to it: `c` is held (d_count>0), so `b`
// (its parent) survives, while the unused sibling `d` is still pruned.
#[test]
fn in_use_descendant_pins_its_ancestors() {
    let sb = mount_ramfs(2);
    let (_root, a, b, c, _d) = build_tree(&sb);
    let held = dget(&c); // pin the leaf — d_count == 1
    assert_eq!(c.d_count(), 1);

    let freed = shrink_dcache_parent(&a);
    assert_eq!(freed, 1, "only the unused sibling `d` is prunable");

    // The pinned path survives.
    assert!(a.cached_child("b").is_some(), "b kept: live child c");
    assert!(b.cached_child("c").is_some(), "c kept: in use");
    assert!(d_lookup(&b, "c").is_some());
    // The unused sibling went away.
    assert!(a.cached_child("d").is_none());
    assert!(d_lookup(&a, "d").is_none());

    dput(held);
}

// Empty parent -> nothing to prune, zero freed, parent untouched.
#[test]
fn empty_parent_prunes_nothing() {
    let sb = mount_ramfs(3);
    let root = sb.s_root().unwrap();
    let leaf = d_add(&root, "x", ramfile(&sb, 20));
    assert_eq!(shrink_dcache_parent(&leaf), 0);
    assert!(d_lookup(&root, "x").is_some(), "parent itself never pruned");
}

// `kernfs_dentry_operations` (Linux `fs/kernfs/dir.c`): the `d_revalidate` hook
// every dentry cached under a `PseudoDir` carries.
//
// A pseudo-fs entry is owned by the tree, not by the dcache. Hot-unplug removes
// the entry and a later re-registration installs a DIFFERENT object under the
// SAME name (a rebound driver republishes `/dev/input/event0`, a re-probed
// device republishes its `/sys` node). Without this hook the first walk's inode
// is served forever, so `open(2)` reaches the dead object and reports `ENODEV`
// even though the name now belongs to a live one.
//
// Decision logic is ungated and unit-tested: `entry_is_current` answers the
// Linux question set — node deactivated (removed), moved, or renamed — as one
// identity comparison against the parent directory's CURRENT child.

use alloc::sync::Arc;

use vfs::dentry::{Dentry, DentryOps};
use vfs::{Inode, InodeRef};

use crate::tree::{PseudoDir, PseudoEntry};

/// `d_op` for every dentry the dcache caches below a [`PseudoDir`]. Installed by
/// `i_op->child_d_op` on each child and inherited by the whole subtree.
pub static KERNFS_DENTRY_OPS: DentryOps = DentryOps {
    d_revalidate: Some(kernfs_revalidate),
    d_hash: None, d_compare: None, d_weak_revalidate: None, d_delete: None,
    d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};

/// The pseudo-fs directory backing `inode`, if it is one. # C: O(1)
fn pseudo_dir(inode: &Inode) -> Option<&PseudoDir> { inode.private::<PseudoDir>() }

/// Drop the inode-cache slots of entries a removal detached from `dir`'s tree,
/// so a later re-registration under the same inode number resolves to the NEW
/// object instead of the evicted one. No-op for a tree with no superblock (the
/// devtmpfs shape), which caches nothing by inode number. # C: O(N)
pub(crate) fn forget_detached(dir: &PseudoDir, detached: &[InodeRef]) {
    let sb = dir.sb.lock().clone();
    let Some(sb) = sb.upgrade() else { return };
    for inode in detached { sb.iforget(inode.ino()); }
}

/// Whether `cached` still names the tree NODE published at `name` under `dir`.
///
/// Node identity, never inode identity: a directory's `vfs::Inode` is a
/// rebuildable view of its node (the inode cache holds only a weak slot, so an
/// eviction mints a fresh inode for the same live directory), while the node
/// itself lives as long as the tree publishes it. Comparing inodes would report
/// a live, mounted-on directory as stale and unhash it, orphaning the mount.
/// Removal, replacement, rename, and move all change the node under a name,
/// which is the Linux `kernfs_dop_revalidate` question set. `None` for `cached`
/// is a negative dentry, valid only while the name is still absent.
/// # C: O(log N_children)
pub(crate) fn entry_is_current(dir: &PseudoDir, name: &str, cached: Option<&InodeRef>) -> bool {
    enum Node { Dir(Arc<PseudoDir>), Leaf(InodeRef) }
    let published = dir.children.lock().get(name).map(|entry| match entry {
        PseudoEntry::Dir(child)  => Node::Dir(Arc::clone(child)),
        PseudoEntry::Leaf(inode) => Node::Leaf(InodeRef::clone(inode)),
    });
    match (published, cached) {
        (None, None) => true,
        (Some(Node::Dir(child)), Some(cached)) => cached
            .private::<PseudoDir>()
            .is_some_and(|node| core::ptr::eq(node, Arc::as_ptr(&child))),
        (Some(Node::Leaf(leaf)), Some(cached)) => Arc::ptr_eq(&leaf, cached),
        _ => false,
    }
}

/// Linux `kernfs_dop_revalidate`: a cached pseudo-fs dentry is valid only while
/// its parent directory still publishes exactly this object under this name.
/// A dentry whose parent is not a pseudo-fs directory (the mount root reached
/// through another filesystem) is left alone. # C: O(log N_children)
fn kernfs_revalidate(d: &Arc<Dentry>, _reval: bool) -> bool {
    let Some(parent) = d.parent() else { return true };
    let Some(parent_inode) = parent.inode() else { return false };
    let Some(dir) = pseudo_dir(&parent_inode) else { return true };
    entry_is_current(dir, d.name(), d.inode().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::dir_ino;

    const TEST_FSID: u64 = 0x5000_0000_0000_00ff;
    const TEST_MAGIC: u64 = 0x5245_5641;

    fn test_superblock(fs: &Arc<crate::PseudoFs>) -> Arc<vfs::superblock::SuperBlock> {
        use vfs::fs::{FileSystem, FsFlags, FsType};
        let ty: Arc<dyn vfs::FileSystemType> = FsType::new(
            "kernfs", TEST_MAGIC, FsFlags::empty(),
            alloc::boxed::Box::new(|_, _, _, _, _| unreachable!("not mounted through ->mount")),
        );
        vfs::fs::superblock_from_filesystem(
            ty, Arc::clone(fs) as Arc<dyn FileSystem>, fs.root(),
            alloc::string::String::from("kernfs"), 0,
        ).expect("kernfs test superblock")
    }

    fn leaf(ino: u64) -> InodeRef {
        vfs::InodeBuilder::new(
            ino,
            vfs::mk_mode(vfs::FileType::CharDev, 0o600),
            vfs::default_inode_ops(),
            vfs::default_file_ops(),
        ).build()
    }

    fn root() -> Arc<PseudoDir> { PseudoDir::new_root(dir_ino("/reval"), TEST_FSID) }

    #[test]
    fn a_published_entry_revalidates_against_its_own_inode() {
        let dir = root();
        let node = leaf(1);
        dir.insert_path("event0", InodeRef::clone(&node));
        assert!(entry_is_current(&dir, "event0", Some(&node)));
    }

    #[test]
    fn a_removed_entry_invalidates_the_cached_inode() {
        let dir = root();
        let node = leaf(2);
        dir.insert_path("event0", InodeRef::clone(&node));
        assert_eq!(dir.remove_subtree_inodes("event0").len(), 1);
        assert!(!entry_is_current(&dir, "event0", Some(&node)),
            "hot-unplug must invalidate the cached dentry");
    }

    /// The rebind case: the name comes back carrying a DIFFERENT object while
    /// keeping the same inode number, exactly as a republished evdev node does.
    #[test]
    fn a_republished_entry_invalidates_the_previous_generation() {
        let dir = root();
        let first = leaf(3);
        dir.insert_path("event0", InodeRef::clone(&first));
        dir.remove_subtree_inodes("event0");
        let second = leaf(3);
        dir.insert_path("event0", InodeRef::clone(&second));
        assert!(!entry_is_current(&dir, "event0", Some(&first)),
            "the previous generation's dentry must not survive a republish");
        assert!(entry_is_current(&dir, "event0", Some(&second)));
    }

    #[test]
    fn a_negative_entry_is_valid_only_while_the_name_is_absent() {
        let dir = root();
        assert!(entry_is_current(&dir, "event0", None));
        dir.insert_path("event0", leaf(4));
        assert!(!entry_is_current(&dir, "event0", None));
    }

    #[test]
    fn a_renamed_entry_invalidates_the_old_name() {
        let dir = root();
        let node = leaf(5);
        dir.insert_path("event0", InodeRef::clone(&node));
        dir.op_rename("event0", &dir, "event1", 0).expect("rename");
        assert!(!entry_is_current(&dir, "event0", Some(&node)));
        assert!(entry_is_current(&dir, "event1", Some(&node)));
    }

    #[test]
    fn a_directory_child_revalidates_by_its_own_identity() {
        let dir = root();
        dir.ensure_dir_path("input");
        let child = dir.lookup_path("input").expect("child dir");
        assert!(entry_is_current(&dir, "input", Some(&child)));
        assert_eq!(dir.remove_subtree_inodes("input").len(), 1);
        assert!(!entry_is_current(&dir, "input", Some(&child)));
    }

    /// The inode cache holds only a weak slot, so an eviction makes the next
    /// `i_op->lookup` mint a FRESH inode for the same live directory. Comparing
    /// inodes here reported `/sys/fs` stale, unhashed it, and orphaned the
    /// cgroup2 mount beneath it — every service then failed to create its
    /// cgroup. The node, not its inode view, is the identity.
    #[test]
    fn a_directory_whose_inode_view_was_rebuilt_is_still_current() {
        let fs = crate::PseudoFs::new("kernfs", TEST_MAGIC);
        let root = Arc::clone(fs.root_dir());
        root.ensure_dir_path("fs");
        let sb = test_superblock(&fs);
        let first = root.lookup_path("fs").expect("directory view");
        sb.iforget(first.ino()); // cache pressure drops the weak slot
        let second = root.lookup_path("fs").expect("rebuilt directory view");
        assert!(!Arc::ptr_eq(&first, &second), "eviction mints a new inode view");
        assert!(entry_is_current(&root, "fs", Some(&first)),
            "a live directory stays current across an inode-cache eviction");
        assert!(entry_is_current(&root, "fs", Some(&second)));
    }

    #[test]
    fn an_unrelated_name_never_matches_a_cached_inode() {
        let dir = root();
        dir.insert_path("event0", leaf(6));
        assert!(!entry_is_current(&dir, "event0", Some(&leaf(6))),
            "identity, not inode number, decides");
    }
}

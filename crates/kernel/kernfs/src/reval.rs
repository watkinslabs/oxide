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

/// The inode `i_op->lookup` would currently resolve `name` to under `dir`,
/// WITHOUT taking the `iget` reference a real lookup owes. Mirrors the cache-hit
/// half of `iget` for an SB-bearing tree so the comparison below sees the same
/// object identity a walk would install. # C: O(log N_children)
pub(crate) fn peek_child(dir: &PseudoDir, name: &str) -> Option<InodeRef> {
    let entry = {
        let children = dir.children.lock();
        match children.get(name)? {
            PseudoEntry::Dir(child) => Ok(Arc::clone(child)),
            PseudoEntry::Leaf(inode) => Err(InodeRef::clone(inode)),
        }
    };
    let inode = match entry { Ok(child) => child.as_inode(), Err(leaf) => leaf };
    match dir.sb.lock().upgrade() {
        Some(sb) => Some(sb.ilookup(inode.ino()).unwrap_or(inode)),
        None => Some(inode),
    }
}

/// Drop the inode-cache slots of entries a removal detached from `dir`'s tree,
/// so a later re-registration under the same inode number resolves to the NEW
/// object instead of the evicted one. No-op for a tree with no superblock (the
/// devtmpfs/sysfs shape), which caches nothing by inode number. # C: O(N)
pub(crate) fn forget_detached(dir: &PseudoDir, detached: &[InodeRef]) {
    let Some(sb) = dir.sb.lock().upgrade() else { return };
    for inode in detached { sb.iforget(inode.ino()); }
}

/// Whether `cached` is still the object the tree publishes at `name` under
/// `dir`. `None` for `cached` is a negative dentry, valid only while the name
/// is still absent. Removal, replacement, rename, and move all change the
/// answer, which is the Linux `kernfs_dop_revalidate` question set.
/// # C: O(log N_children)
pub(crate) fn entry_is_current(dir: &PseudoDir, name: &str, cached: Option<&InodeRef>) -> bool {
    match (peek_child(dir, name), cached) {
        (None, None) => true,
        (Some(current), Some(cached)) => Arc::ptr_eq(&current, cached),
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
    use alloc::string::String;

    const TEST_FSID: u64 = 0x5000_0000_0000_00ff;

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

    #[test]
    fn an_unrelated_name_never_matches_a_cached_inode() {
        let dir = root();
        dir.insert_path("event0", leaf(6));
        assert!(!entry_is_current(&dir, "event0", Some(&leaf(6))),
            "identity, not inode number, decides");
        let _ = String::new();
    }
}

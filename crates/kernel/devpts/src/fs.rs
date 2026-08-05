// One devpts superblock's state: root, mount options, and live PTY indices.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use kernfs::PseudoDir;
use sync::{Spinlock, TaskList};
use vfs::{InodeRef, SuperBlock};

use crate::ids::{DEVPTS_FSID, DEVPTS_MAGIC};
use crate::index::PtsIndices;
use crate::mount_opts::PtsMountOpts;

/// State owned by one devpts superblock.
pub struct DevptsFs {
    root: Arc<PseudoDir>,
    opts: PtsMountOpts,
    indices: Spinlock<PtsIndices, TaskList>,
    self_ref: Weak<DevptsFs>,
}

impl DevptsFs {
    /// Build an independent mount instance with its own root and allocator.
    /// # C: O(MAX_PTY_PAIRS / 64)
    pub fn new(opts: PtsMountOpts) -> Arc<Self> {
        Arc::new_cyclic(|me| {
            let root = PseudoDir::new_root(kernfs::dir_ino("/dev/pts"), DEVPTS_FSID);
            root.insert_path("ptmx", crate::inodes::make_pts_ptmx_inode(opts.ptmxmode));
            Self { root, opts, indices: Spinlock::new(PtsIndices::new()), self_ref: me.clone() }
        })
    }

    /// The instance root directory. # C: O(1)
    pub fn root_dir(&self) -> &Arc<PseudoDir> { &self.root }

    /// This instance's immutable mount options. # C: O(1)
    pub fn opts(&self) -> PtsMountOpts { self.opts }

    /// Lowest free index allowed by this instance's `max=`. # C: O(max / 64)
    pub(crate) fn alloc_index(&self) -> vfs::KResult<u32> {
        self.indices.lock().alloc(self.opts.max).ok_or(vfs::VfsError::Enospc)
    }

    /// Remove a slave and return its index to this instance. # C: O(log N)
    pub(crate) fn release_pair(&self, idx: u32) {
        let _ = self.root.remove_leaf(&idx.to_string());
        self.indices.lock().free(idx);
    }

    /// The already-created slave inode for `idx`. # C: O(log N)
    pub fn slave_inode(&self, idx: u32) -> Option<InodeRef> {
        self.root.lookup_path(&idx.to_string())
    }
}

impl vfs::fs::FileSystem for DevptsFs {
    fn name(&self) -> &str { "devpts" }
    fn magic(&self) -> u64 { DEVPTS_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.as_inode()) }
    fn set_sb(&self, sb: Weak<SuperBlock>) -> vfs::KResult<()> {
        self.root.set_sb(sb.clone());
        if let (Some(sb), Some(me)) = (sb.upgrade(), self.self_ref.upgrade()) {
            sb.set_fs_info(me);
        }
        Ok(())
    }
    fn show_options(&self) -> String { crate::mount_opts::show_options(&self.opts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inodes::allocate_pair;

    fn opts(data: &str) -> PtsMountOpts {
        crate::mount_opts::opts_for_mount(data, &[]).expect("valid options")
    }

    #[test]
    fn two_mounts_own_disjoint_options_roots_and_index_spaces() {
        let a = DevptsFs::new(opts("mode=600,max=1"));
        let b = DevptsFs::new(opts("mode=666,max=1"));
        let aa = allocate_pair(&a, 11, 1000, 1000).expect("a index zero");
        let bb = allocate_pair(&b, 22, 2000, 2000).expect("b index zero");
        assert_eq!((aa.index(), bb.index()), (0, 0));
        assert_eq!(a.slave_inode(0).and_then(|i| i.perm()), Some(0o600));
        assert_eq!(b.slave_inode(0).and_then(|i| i.perm()), Some(0o666));
        assert!(!Arc::ptr_eq(&a.root, &b.root));
    }

    #[test]
    fn dropping_an_uninstalled_allocation_removes_the_node_and_reuses_the_index() {
        let fs = DevptsFs::new(opts("max=1"));
        let first = allocate_pair(&fs, 7, 0, 0).expect("first");
        assert!(fs.slave_inode(0).is_some());
        drop(first);
        assert!(fs.slave_inode(0).is_none());
        assert_eq!(allocate_pair(&fs, 7, 0, 0).expect("reused").index(), 0);
    }

    #[test]
    fn committed_pair_frees_only_after_both_endpoint_counts_reach_zero() {
        let fs = DevptsFs::new(opts("max=1"));
        let mut allocation = allocate_pair(&fs, 7, 0, 0).expect("pair");
        let pair = allocation.pair();
        pair.open_endpoint(true, false).expect("master open");
        pair.open_endpoint(false, false).expect("slave open");
        allocation.commit();
        assert!(pair.close_endpoint(true));
        pair.release_if_unused();
        assert!(fs.slave_inode(0).is_some(), "slave fd still holds the pair live");
        assert!(pair.close_endpoint(false));
        pair.release_if_unused();
        assert!(fs.slave_inode(0).is_none());
        assert_eq!(allocate_pair(&fs, 7, 0, 0).expect("reused after last close").index(), 0);
    }
}

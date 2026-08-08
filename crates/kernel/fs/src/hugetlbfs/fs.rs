// One mounted hugetlbfs instance.

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use pmm::hugetlb;
use sync::{Inode as InodeClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{InodeRef, KResult};

use super::accounting::HugetlbfsSb;
use super::dir::{as_dir, make_dir_inode};
use super::limits::ROOT_INO;
use super::mount_opts::parse_opts;
use super::uapi::HUGETLBFS_MAGIC;

/// One mounted hugetlbfs instance. Owns its own inode tree under its
/// SuperBlock; there is no shared registry and no baked mount path.
pub struct HugetlbfsFs {
    root: InodeRef,
    sb:   Spinlock<Weak<SuperBlock>, InodeClass>,
    acct: Arc<HugetlbfsSb>,
}

impl HugetlbfsFs {
    /// Build an instance from a `mount(2)` `-o` option string.
    ///
    /// An option the mount cannot be given fails the mount with that option's
    /// own error, rather than mounting a filesystem that quietly ignores it.
    /// # C: O(len(data)) + O(min_size pages)
    pub fn from_mount_data(data: &str) -> KResult<Arc<Self>> {
        let opts = parse_opts(data)?;
        let pool_max = hugetlb::nr_hugepages(opts.size());
        let acct = HugetlbfsSb::from_opts(&opts, pool_max)?;
        Ok(Self::with_accounting(acct))
    }

    /// Build an instance over already-resolved accounting — the kernel-private
    /// mount's route in. # C: O(1)
    pub(super) fn with_accounting(acct: Arc<HugetlbfsSb>) -> Arc<Self> {
        acct.charge_inode(); // the root inode itself counts
        let (uid, gid) = acct.owner();
        let root = make_dir_inode(ROOT_INO, acct.mode(), uid, gid, Weak::new(), acct.clone());
        Arc::new(Self { root, sb: Spinlock::new(Weak::new()), acct })
    }

    /// This instance's root inode. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
}

impl vfs::fs::FileSystem for HugetlbfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "hugetlbfs" }
    /// # C: O(1)
    fn magic(&self) -> u64 { HUGETLBFS_MAGIC }
    /// The reference marks hugetlbfs id-mappable and does NOT mark it
    /// user-namespace mountable: a mount reserves pages from a global pool, so
    /// an unprivileged namespace cannot be allowed to create one. # C: O(1)
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_ALLOW_IDMAP }
    /// A hugetlbfs block IS a huge page — this is what makes `stat` report
    /// `st_blksize` as the size a write to the file must be aligned to.
    /// # C: O(1)
    fn block_size(&self) -> u32 { self.acct.huge_size().bytes() as u32 }
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(HugetlbfsSuperOps { acct: self.acct.clone() }))
    }
    /// # C: O(1)
    fn show_options(&self) -> String { self.acct.show_options() }
    /// `fill_super` back-stamp: record the SB so the root and every child
    /// derive `fsid` from `s_dev`. # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) -> KResult<()> {
        *self.sb.lock() = sb.clone();
        if let Some(d) = as_dir(&self.root) { d.set_sb(sb); }
        Ok(())
    }
}

/// `super_operations` for a hugetlbfs mount.
pub struct HugetlbfsSuperOps { acct: Arc<HugetlbfsSb> }
impl vfs::SuperOps for HugetlbfsSuperOps {
    /// `hugetlbfs_statfs` — block counts only for a mount with a size ceiling,
    /// because a mount without one has no total to report. # C: O(1)
    fn statfs(&self) -> KResult<vfs::SbStatFs> { Ok(self.acct.statfs()) }
}

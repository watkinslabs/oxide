//! `vfs::fs::FileSystem` impl for kernel-side procfs.
//!
//! procfs is fully per-component: its mount root is the `ProcRootInode`
//! singleton (`static_files::proc_root`), and resolution proceeds via
//! `ProcRootInode::lookup` → `ProcPidDirInode::lookup` (`d_lookup →
//! i_op->lookup → d_add`). No whole-path `FileSystem::lookup`.

use alloc::sync::Arc;

/// PROC_SUPER_MAGIC (linux/magic.h) — procfs `f_type`/`s_magic`.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// `PAGE_SIZE` — procfs statfs `f_bsize` (Linux `proc_fill_super` → `s_blocksize
/// = PAGE_SIZE`). # C: O(1)
const PAGE_SIZE: u32 = 4096;

/// FileSystem trait impl. Read-only. The mount table crosses into procfs
/// at `root()` and the namei walker resolves every component below it
/// through the procfs inode tree.
pub struct ProcfsFs;

/// `super_operations` for procfs. procfs is a zero-sized pseudo filesystem:
/// `statfs(2)` reports the magic + `PAGE_SIZE` block size and zero block/inode
/// counts (Linux `simple_statfs`, fs/libfs.c, used by `proc_fill_super`).
struct ProcfsSuperOps;
impl vfs::SuperOps for ProcfsSuperOps {
    /// `simple_statfs`: f_type=PROC_SUPER_MAGIC, f_bsize=PAGE_SIZE, all
    /// block/inode counts 0 (f_namelen=NAME_MAX is filled by the syscall layer).
    /// # C: O(1)
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> {
        Ok(vfs::SbStatFs {
            f_type:  PROC_SUPER_MAGIC,
            f_bsize: PAGE_SIZE,
            ..Default::default()
        })
    }
}

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// PROC_SUPER_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { PROC_SUPER_MAGIC }
    /// Install zero-sized pseudo-fs statfs (`simple_statfs`) as this SB's `s_op`
    /// so `statfs(2)`/`df` report PROC_SUPER_MAGIC + PAGE_SIZE, not the generic
    /// synthetic figures. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(Arc::new(ProcfsSuperOps)) }
    /// Mount root = the `ProcRootInode` singleton. The path walk crosses
    /// into the procfs mount and resolves `/proc/<name>`, `/proc/self`,
    /// `/proc/<pid>/<leaf>`, `/proc/net`, `/proc/sys` per-component via
    /// `ProcRootInode::lookup` + `ProcPidDirInode::lookup` — no whole-path
    /// synthesis.
    /// # C: O(1)
    fn root(&self) -> Option<vfs::InodeRef> {
        Some(crate::static_files::proc_root() as vfs::InodeRef)
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &ProcfsFs }

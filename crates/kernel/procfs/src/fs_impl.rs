//! `vfs::fs::FileSystem` impl for kernel-side procfs.
//!
//! procfs is fully per-component: its mount root is the `ProcRootInode`
//! singleton (`static_files::proc_root`), and resolution proceeds via
//! `ProcRootInode::lookup` → `ProcPidDirInode::lookup` (`d_lookup →
//! i_op->lookup → d_add`). No whole-path `FileSystem::lookup`.

/// FileSystem trait impl. Read-only. The mount table crosses into procfs
/// at `root()` and the namei walker resolves every component below it
/// through the procfs inode tree.
pub struct ProcfsFs;

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// PROC_SUPER_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x9fa0 }
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

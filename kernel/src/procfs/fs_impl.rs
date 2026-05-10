//! `vfs::fs::FileSystem` impl for kernel-side procfs. Lives in
//! kernel/ because `lookup_dynamic` reaches into sched + the
//! kernel's per-pid inode table.

use super::lookup_dynamic;

/// FileSystem trait impl. Read-only; only `lookup` is meaningful.
pub struct ProcfsFs;

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// # C: O(1) for static entries, O(N_tasks) for /proc/<pid>/*.
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> { lookup_dynamic(path) }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &ProcfsFs }

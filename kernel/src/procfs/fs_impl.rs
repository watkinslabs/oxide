//! `vfs::fs::FileSystem` impl for kernel-side procfs. Lives in
//! kernel/ because `lookup_dynamic` reaches into sched + the
//! kernel's per-pid inode table.

use super::lookup_dynamic;

/// FileSystem trait impl. Read-only.
///
/// Static /proc files (`/proc/version`, `/proc/cpuinfo`,
/// `/proc/sys/...`) are registered into the unified devfs key/value
/// table at boot by `procfs::static_files::init`. We check that
/// first, then fall back to `lookup_dynamic` for per-pid
/// `/proc/<pid>/*` synthesis.
pub struct ProcfsFs;

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// # C: O(1) for static entries, O(N_tasks) for /proc/<pid>/*.
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> {
        if let Some(i) = devfs::lookup(path) { return Some(i); }
        lookup_dynamic(path)
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &ProcfsFs }

//! `vfs::fs::FileSystem` impl for kernel-side procfs. Lives in
//! kernel/ because `lookup_dynamic` reaches into sched + the
//! kernel's per-pid inode table.

use crate::live::lookup_dynamic;

/// FileSystem trait impl. Read-only.
///
/// Static /proc files (`/proc/version`, `/proc/cpuinfo`,
/// `/proc/sys/...`) are registered into the unified devfs key/value
/// table at boot by `crate::static_files::init`. We check that
/// first, then fall back to `lookup_dynamic` for per-pid
/// `/proc/<pid>/*` synthesis.
pub struct ProcfsFs;

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// PROC_SUPER_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x9fa0 }
    /// # C: O(1) for static entries, O(N_tasks) for /proc/<pid>/*.
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> {
        // /proc is a real directory tree: ProcRootInode owns its static children
        // (cpuinfo/meminfo/…). A single-component /proc/<name> resolves through
        // the root's own lookup (static files + self + pid dirs). Multi-component
        // (/proc/<pid>/<leaf>, /proc/self/<leaf>, /proc/sys/*) falls to devfs +
        // per-pid synthesis.
        if path == "/proc" { return devfs::lookup("/proc"); }
        if let Some(rest) = path.strip_prefix("/proc/") {
            if !rest.is_empty() && !rest.contains('/') {
                if let Some(root) = devfs::lookup("/proc") {
                    if let Ok(child) = root.lookup(rest) { return Some(child); }
                }
            }
        }
        if let Some(i) = devfs::lookup(path) { return Some(i); }
        lookup_dynamic(path)
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &ProcfsFs }

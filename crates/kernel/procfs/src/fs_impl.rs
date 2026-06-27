//! `vfs::fs::FileSystem` impl for kernel-side procfs. Lives in
//! kernel/ because `lookup_dynamic` reaches into sched + the
//! kernel's per-pid inode table.

use crate::live::lookup_dynamic;
use vfs::Inode;

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
        // procfs OWNS /proc: resolve through the real root singleton (the dir
        // inode that owns the static-file children), NOT the devfs registry — a
        // mounted filesystem must not live in devfs (the old devfs::register
        // "/proc" conflicted with the devfs tree auto-creating a /proc dir for
        // /proc/net/* etc). Single-component /proc/<name> → root's own lookup.
        let root = crate::static_files::proc_root();
        if path == "/proc" { return Some(root as vfs::InodeRef); }
        if let Some(rest) = path.strip_prefix("/proc/") {
            if !rest.is_empty() && !rest.contains('/') {
                if let Ok(child) = root.lookup(rest) { return Some(child); }
            }
        }
        // Multi-component: /proc/<pid>/<leaf> + /proc/self/<leaf> synthesized;
        // /proc/net/* and /proc/sys/* resolve via the procfs-owned subtree.
        // Do not apply the caller's chroot here: this lookup is already inside
        // the mounted procfs instance, so chroot-prefixing would hide
        // `/proc/sys/kernel/domainname` from sandboxed services.
        if let Some(i) = devfs::lookup_no_chroot(path) { return Some(i); }
        lookup_dynamic(path)
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &ProcfsFs }

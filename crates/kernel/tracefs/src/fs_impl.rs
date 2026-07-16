//! `vfs::fs::FileSystem` impls for tracefs (`/sys/kernel/tracing`), debugfs
//! (`/sys/kernel/debug`), and configfs (`/sys/kernel/config`). Mirror `ProcfsFs`: own a superblock with
//! the right magic and delegate path resolution to the devfs subtree that
//! `tracefs::init` (and the debugfs static files) populate. Registering
//! these in the unified mount table — instead of the old admit-noop that
//! returned 0 without a `vfs::mount::register` — is what makes them appear
//! in `/proc/self/mountinfo` and pass libmount's post-mount verify +
//! statfs `f_type` magic detection (`docs/16`). Without it `mount(2)`
//! returned 0 but the mount was invisible, so the helper's verify failed
//! and it exited 32 (sys-kernel-debug.mount / sys-kernel-tracing.mount).

use vfs::InodeRef;

pub const TRACEFS_SUPER_MAGIC: u64 = 0x7472_6163;
pub const DEBUGFS_SUPER_MAGIC: u64 = 0x6462_6720;

/// tracefs. `TRACEFS_MAGIC` (linux/magic.h).
pub struct TracefsFs;

impl vfs::fs::FileSystem for TracefsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "tracefs" }
    /// TRACEFS_MAGIC.
    /// # C: O(1)
    fn magic(&self) -> u64 { TRACEFS_SUPER_MAGIC }
    /// Mount root = the `/sys/kernel/tracing` devfs directory. A non-`None`
    /// root is what the path walk crosses into (so opening/statfs INTO the
    /// mount works) and what makes the mount a real, non-empty entry the
    /// post-mount verify accepts. `tracefs::init` registers the dir.
    /// # C: O(components)
    fn root(&self) -> Option<InodeRef> {
        Some(crate::trace_root().as_inode())
    }
}

/// debugfs. `DEBUGFS_MAGIC` (linux/magic.h).
pub struct DebugfsFs;

impl vfs::fs::FileSystem for DebugfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "debugfs" }
    /// DEBUGFS_MAGIC.
    /// # C: O(1)
    fn magic(&self) -> u64 { DEBUGFS_SUPER_MAGIC }
    /// Mount root = the `/sys/kernel/debug` devfs directory (registered by
    /// `tracefs::init`). debugfs is empty here, but a real directory root is
    /// required so the walk crosses into the mount and the post-mount verify
    /// accepts it. # C: O(components)
    fn root(&self) -> Option<InodeRef> {
        Some(crate::debug_root().as_inode())
    }
}

/// configfs. `CONFIGFS_MAGIC` (linux/magic.h).
pub struct ConfigfsFs;

impl vfs::fs::FileSystem for ConfigfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "configfs" }
    /// CONFIGFS_MAGIC.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x6265_6570 }
    /// Mount root = the shared `/sys/kernel/config` configfs tree. # C: O(1)
    fn root(&self) -> Option<InodeRef> {
        Some(crate::config_root().as_inode())
    }
}

//! FileSystem trait — per `docs/16` mount-table abstraction.
//!
//! Each FS backend (ext4 rootfs, devfs, procfs, tmpfs) implements
//! this trait. The kernel mount table (`vfs::mount`, R67) holds an
//! `Arc<dyn FileSystem>` per mount point and routes path lookup to
//! the longest-prefix-match instance.
//!
//! Tier-2 work fns per `docs/53§3`: no `SyscallArgs`, no
//! `sched::current()`, returns `KResult<T>` with typed `T`.

extern crate alloc;
use alloc::string::String;
use crate::inode::InodeRef;
use crate::types::VfsError;

/// `KResult<T>` is the VFS error envelope. Aliased here for
/// convenience inside trait bodies.
pub type KResult<T> = core::result::Result<T, VfsError>;

/// Filesystem instance per `16§2`. One impl per backend; one or
/// more instances per kernel (each registered to a mount point).
pub trait FileSystem: Send + Sync {
    /// Human-readable FS-type name. `"ext4"`, `"tmpfs"`, `"devfs"`,
    /// `"procfs"`. Used for `/proc/mounts` and error messages.
    /// # C: O(1)
    fn name(&self) -> &str;

    /// Resolve `path` (relative to this FS's mount point) to an
    /// `InodeRef`. Returns `None` if no such name exists.
    /// # C: depends on FS — typically O(path-component-count).
    fn lookup(&self, path: &str) -> Option<InodeRef>;

    /// Create a new regular file at `path` with permission `mode`.
    /// Default: read-only FS returns `Erofs`.
    /// # C: depends on FS.
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (path, mode);
        Err(VfsError::Erofs)
    }

    /// Remove the regular file at `path`. Default: `Erofs`.
    /// # C: depends on FS.
    fn unlink(&self, path: &str) -> KResult<()> {
        let _ = path;
        Err(VfsError::Erofs)
    }

    /// Rename `from` to `to`. Both paths are relative to this FS.
    /// Default: `Erofs`.
    /// # C: depends on FS.
    fn rename(&self, from: &str, to: &str) -> KResult<()> {
        let _ = (from, to);
        Err(VfsError::Erofs)
    }

    /// `/proc/mounts`-style description: `<src> <mnt> <fstype> <opts>`.
    /// Default returns "(unknown) (unknown) <name> ro".
    /// # C: O(1)
    fn mounts_line(&self, mount_point: &str) -> String {
        let mut s = String::new();
        s.push_str("none ");
        s.push_str(mount_point);
        s.push(' ');
        s.push_str(self.name());
        s.push_str(" ro 0 0\n");
        s
    }
}

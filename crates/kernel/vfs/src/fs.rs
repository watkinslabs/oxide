//! FileSystem trait — per `docs/16` mount-table abstraction.
//!
//! Each FS backend (ext4 rootfs, devfs, procfs, tmpfs) implements
//! this trait. The kernel mount table (`vfs::mount`, R67) holds an
//! `Arc<dyn FileSystem>` per mount point and routes path lookup to
//! the longest-prefix-match instance.
//!
//! work fns per `docs/53§3`: no `SyscallArgs`, no
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

    /// Superblock `s_magic` (linux/magic.h) reported by `statfs(2)` /
    /// `fstatfs(2)` `f_type`. systemd & friends detect fs type by this
    /// magic (cgroup2=0x63677270, tmpfs=0x01021994, proc=0x9fa0, …), so
    /// every real backend must override. `0` = "no opinion": the statfs
    /// classifier then falls through to its path-prefix table.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0 }

    /// Root inode of this mounted filesystem — the `super_block::s_root`
    /// of `docs/16§2`. The dentry path-walk (`docs/16§3`) switches to this
    /// inode when it crosses into the mount, then resolves every component
    /// below it via `Inode::lookup` (`d_lookup → i_op->lookup → d_add`).
    /// Every real backend overrides this (or publishes a per-mount root via
    /// `mount::register_bind`'s `m.root`); `None` only for a marker fs whose
    /// root inode is carried by the mount table instead.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { None }

    /// Create a new regular file at `path` with permission `mode`.
    /// Default: read-only FS returns `Erofs`.
    /// # C: depends on FS.
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (path, mode);
        Err(VfsError::Erofs)
    }

    /// Create an anonymous (`O_TMPFILE`) regular inode on THIS fs. `dir`
    /// is the directory (relative to this mount) the file would live in —
    /// disk FSes use it to pick an allocation group; in-memory FSes
    /// ignore it. The inode has no directory entry (nlink=0) and is
    /// reclaimed when its last fd drops. Must be dispatched on the fs that
    /// actually backs the path: `O_TMPFILE` on /run|/tmp|/dev/shm is tmpfs,
    /// not the ext4 rootfs. Default: read-only/unsupported FS returns Erofs.
    /// # C: depends on FS.
    fn create_anonymous(&self, dir: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (dir, mode);
        Err(VfsError::Erofs)
    }

    /// Remove the regular file at `path`. Default: `Erofs`.
    /// # C: depends on FS.
    fn unlink(&self, path: &str) -> KResult<()> {
        let _ = path;
        Err(VfsError::Erofs)
    }

    /// Hardlink `target` to `link` within this filesystem. Both paths are
    /// absolute during the mount-table transition; mature backends may treat
    /// them as mount-relative once every caller passes stripped names.
    /// Default: read-only / unsupported FS returns `Erofs`.
    /// # C: depends on FS.
    fn link(&self, target: &str, link: &str) -> KResult<()> {
        let _ = (target, link);
        Err(VfsError::Erofs)
    }

    /// Materialize an unnamed inode, e.g. `linkat(fd, "", path,
    /// AT_EMPTY_PATH)`, into this filesystem. Backends must reject inodes
    /// from another filesystem with `Exdev`.
    /// # C: depends on FS.
    fn link_inode(&self, inode: InodeRef, link: &str) -> KResult<()> {
        let _ = (inode, link);
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
    /// Default uses the fs name as the source and `rw,relatime` opts
    /// (our boot mounts are all writable); override for richer opts.
    /// # C: O(1)
    fn mounts_line(&self, mount_point: &str) -> String {
        let mut s = String::new();
        s.push_str(self.name());
        s.push(' ');
        s.push_str(mount_point);
        s.push(' ');
        s.push_str(self.name());
        s.push_str(" rw,relatime 0 0\n");
        s
    }
}

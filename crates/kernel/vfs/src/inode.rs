// `Inode` trait per `16§2`. Trait-object backed (`Arc<dyn Inode>`) so
// every FS impl (tmpfs / ext4 / procfs / devfs) shares one VFS surface.
//
// Subset for v1; the full ~30-method surface in spec lands as each
// FS-specific consumer needs it. Path resolution + FdTable +
// File::read/write are the immediate users — they need: ino /
// file_type / size / lookup / read / write / readdir.

extern crate alloc;
use alloc::sync::Arc;

use crate::types::{FileType, Ino, KResult, VfsError};

/// Per-component lookup hit. Negative dentries (`name` exists in cache
/// but resolves to no inode) are signalled by returning
/// `Err(VfsError::Enoent)` from `lookup`.
pub type InodeRef = Arc<dyn Inode>;

/// `16§2` Inode trait — v1 subset.
pub trait Inode: Send + Sync {
    /// Optional downcast hook. Returns `Some(self)` for inode
    /// types whose syscall handlers need to recover a concrete
    /// state struct from an `InodeRef` (e.g. POSIX MQ pulling
    /// `MqQueue` out of an `MqInode` behind a fd). Default returns
    /// `None`. Concrete impls that need it override with
    /// `Some(self)` (requires the impl type be `'static`, which
    /// every kernel inode is).
    /// # C: O(1)
    fn as_any(&self) -> Option<&dyn core::any::Any> { None }

    /// # C: O(1)
    fn ino(&self) -> Ino;

    /// # C: O(1)
    fn file_type(&self) -> FileType;

    /// # C: O(1)
    fn size(&self) -> u64;

    /// Resolve `name` within this inode (must be a directory). Returns
    /// `Err(Enotdir)` for non-directory inodes; `Err(Enoent)` for
    /// missing names.
    /// # C: depends on FS impl
    fn lookup(&self, name: &str) -> KResult<InodeRef>;

    /// Read into `buf` starting at byte offset `off`. Returns the
    /// number of bytes actually read; `0` indicates EOF. Default impl
    /// returns `Err(Eisdir)` for directory inodes.
    /// # C: depends on FS impl
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Eisdir)
    }

    /// Non-blocking read variant per `15§5` (O_NONBLOCK). Returns
    /// `Err(Eagain)` if data would not be immediately available
    /// without parking. Default impl delegates to `read()`, which
    /// is correct for inodes that never block (regular files,
    /// tmpfs, procfs/sysfs static files). Inodes whose `read()`
    /// can park (pipes, ptys, ttys, sockets) override this to
    /// return EAGAIN instead of sleeping.
    /// # C: depends on FS impl
    fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(off, buf)
    }

    /// Non-blocking write variant per `15§5` (O_NONBLOCK). Returns
    /// `Err(Eagain)` if the destination buffer is full and the
    /// write would have to park. Default impl delegates to
    /// `write()`. Pipes / sockets / ptys override.
    /// # C: depends on FS impl
    fn write_nonblock(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(off, buf)
    }

    /// Write `buf` starting at byte offset `off`. Returns the number
    /// of bytes actually written. Default impl returns `Err(Eisdir)`.
    /// # C: depends on FS impl
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Eisdir)
    }

    /// Resolve a symbolic link to its target path bytes. Returns
    /// the literal target without further resolution; the path
    /// walker handles recursive follow + RESOLVE_NO_SYMLINKS.
    /// Default impl returns `Err(Einval)` for non-symlink inodes
    /// (matching Linux readlink(2) error on a non-symlink).
    /// # C: O(target_len)
    fn readlink(&self) -> KResult<alloc::vec::Vec<u8>> {
        Err(VfsError::Einval)
    }

    /// Truncate the file to `len` bytes per `truncate(2)` /
    /// `ftruncate(2)`. Default impl returns `Erofs`. tmpfs honours
    /// it; static / pseudo inodes don't.
    /// # C: depends on FS impl
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Create a child directory `name` with permission `mode` within
    /// this directory inode (Linux `inode_operations->mkdir`). Returns
    /// the new directory's inode. Default returns `Erofs` so static /
    /// read-only dir inodes reject `mkdir(2)`; writable pseudo-FS
    /// (cgroupfs) and tmpfs override. `Eexist` if `name` already
    /// exists; `Enotdir` if `self` is not a directory.
    /// # C: depends on FS impl
    fn mkdir(&self, _name: &str, _mode: u32) -> KResult<InodeRef> {
        Err(VfsError::Erofs)
    }

    /// Remove the empty child directory `name` (Linux
    /// `inode_operations->rmdir`). Default `Erofs`. `Enoent` if
    /// missing; `Enotempty` (mapped to `Einval` where the envelope
    /// lacks it) if the child still has entries/members.
    /// # C: depends on FS impl
    fn rmdir(&self, _name: &str) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Create a regular child file `name` (Linux `inode_operations->
    /// create`). Returns the new inode. Default `Erofs`. `Eexist` if
    /// present; `Enotdir` if `self` isn't a directory.
    /// # C: depends on FS impl
    fn create_child(&self, _name: &str, _mode: u32) -> KResult<InodeRef> {
        Err(VfsError::Erofs)
    }

    /// Remove the child file `name` (Linux `inode_operations->unlink`).
    /// Default `Erofs`. `Enoent` if missing; `Eisdir` if it's a dir.
    /// # C: depends on FS impl
    fn unlink_child(&self, _name: &str) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Create a symlink child `name` whose target text is `target`
    /// (Linux `inode_operations->symlink`). Default `Erofs`.
    /// # C: depends on FS impl
    fn symlink_child(&self, _name: &str, _target: &[u8]) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Create a device/FIFO/socket child `name` (Linux
    /// `inode_operations->mknod`). `mode` carries the `S_IF*` type +
    /// perm bits; `rdev` the packed major/minor. Default `Erofs`.
    /// # C: depends on FS impl
    fn mknod_child(&self, _name: &str, _mode: u16, _rdev: u32) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Iterate child entries of a directory. `off` is the cookie from
    /// a previous call; `0` starts from the beginning. The callback
    /// returns `false` to stop early. Default impl returns
    /// `Err(Enotdir)`.
    /// # C: depends on FS impl
    fn readdir(
        &self,
        _off: u64,
        _f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        Err(VfsError::Enotdir)
    }

    /// Non-blocking readiness query. Returns a bitmask of
    /// `POLL_*` flags telling whether read/write would succeed
    /// without blocking. Default = always readable + writable
    /// (synthetic / static inodes never block).
    /// # C: O(1)
    fn poll(&self) -> u32 { POLL_IN | POLL_OUT }

    /// F181: per-Inode subscriber list for targeted epoll wakes.
    /// Default `None` falls back to the global epoll-broadcast wake
    /// (notify_epoll_waiters). Inodes whose event sites can issue
    /// targeted wakes (InetSocket, future Pipe/Tty) override to
    /// return Some — `epoll_ctl(ADD)` then subscribes the calling
    /// epoll, and the inode's event sites call
    /// `self.poll_subscribers().unwrap().notify()` to wake only
    /// subscribers instead of every epoll on the system.
    /// # C: O(1)
    fn poll_subscribers(&self) -> Option<&crate::PollSubscribers> { None }

    /// Per-FS metadata accessors. Defaults return `None` (i.e. "the
    /// kernel-side `inode_times` overlay or the statx fallback owns
    /// the answer"). Per-FS impls override with `Some(stored_value)` —
    /// using `None` rather than 0 lets a real impl legitimately
    /// express atime=0 / perm=0o000 / uid=0 without being mistaken
    /// for "fall through".
    /// # C: O(1)
    fn mtime(&self) -> Option<u64> { None }
    /// # C: O(1)
    fn atime(&self) -> Option<u64> { None }
    /// # C: O(1)
    fn ctime(&self) -> Option<u64> { None }

    /// Update the inode's atime/mtime/ctime. `None` for a time field
    /// means "leave alone" (UTIME_OMIT). Default returns `Erofs` so
    /// pseudo-fs without their own store fall through to the kernel's
    /// `inode_times` overlay at the syscall layer.
    /// # C: O(1)
    fn set_times(&self, _atime: Option<u64>, _mtime: Option<u64>, _ctime: u64) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Permission bits — low 12 bits of mode (rwx + suid/sgid/sticky).
    /// `None` = no per-FS override; statx applies its 0o600 fallback.
    /// # C: O(1)
    fn perm(&self) -> Option<u16> { None }

    /// Owner uid. `None` = no per-FS override.
    /// # C: O(1)
    fn uid(&self) -> Option<u32> { None }

    /// Owner gid. `None` = no per-FS override.
    /// # C: O(1)
    fn gid(&self) -> Option<u32> { None }

    /// `chmod(2)` backend. Default `Erofs` → overlay handles it.
    /// # C: O(1)
    fn set_perm(&self, _perm: u16) -> KResult<()> { Err(VfsError::Erofs) }

    /// `chown(2)` backend. Default `Erofs` → overlay handles it.
    /// # C: O(1)
    fn set_owner(&self, _uid: u32, _gid: u32) -> KResult<()> { Err(VfsError::Erofs) }
}

/// `poll(2)` event bitmasks. Numeric reps match Linux exactly.
pub const POLL_IN:    u32 = 0x0001;  // POLLIN  — readable
pub const POLL_OUT:   u32 = 0x0004;  // POLLOUT — writable
pub const POLL_HUP:   u32 = 0x0010;  // POLLHUP — peer closed
pub const POLL_ERR:   u32 = 0x0008;  // POLLERR — io error
pub const POLL_PRI:   u32 = 0x0002;  // POLLPRI — urgent (TCP OOB)
pub const POLL_RDHUP: u32 = 0x2000;  // POLLRDHUP — peer-closed-write

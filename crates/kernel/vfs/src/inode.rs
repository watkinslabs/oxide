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
///
/// CONCEPTUAL `i_op` / `i_fop` SPLIT (Linux `inode_operations` vs
/// `file_operations`). This kernel keeps ONE trait object per inode (the
/// trait-object model: `Arc<dyn Inode>`), so the two Linux vtables are not
/// separate types — but the methods group into the same two families and a
/// reader/auditor should treat them as such:
///   * `i_op` (inode_operations — namespace/metadata ops keyed on a DIRECTORY
///     or the inode's identity): `lookup`, `mkdir`, `rmdir`, `create_child`,
///     `unlink_child`, `symlink_child`, `mknod_child`, `readlink`,
///     `set_perm`/`set_owner`/`set_times`, `truncate`, and the metadata
///     accessors (`perm`/`uid`/`gid`/`mtime`/`atime`/`ctime`/`rdev`/`nlink`/
///     `size`/`fsid`/`blksize`/`statfs_magic`).
///   * `i_fop` (file_operations — per-open data-path ops): `read`/`write`,
///     `read_nonblock`/`write_nonblock`, `readdir`, `poll`/`poll_file`,
///     `mmap_shared_frame`, `on_open`/`on_release`, `fdinfo_extra`,
///     `fcntl_seals`, `poll_subscribers`.
/// `i_sb`/`ino`/`as_any` are the shared object-model identity (Linux `struct
/// inode` core). Splitting into two physical traits is deferred — it buys no
/// behaviour and doubles the per-FS impl surface (131 impls). Documented here
/// so the grouping is explicit without over-refactoring.
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

    /// `i_sb` — owning superblock backref (Linux `inode->i_sb`). `None`
    /// during the WP6 migration (backends not yet converted to own a
    /// `SuperBlock`); converted FSes return `Some(sb)` so `fsid()` and
    /// `statfs` derive from the real superblock. # C: O(1)
    fn i_sb(&self) -> Option<alloc::sync::Arc<crate::superblock::SuperBlock>> { None }

    /// Superblock / mount identity (Linux `st_dev` analog). Inodes on
    /// the same filesystem return the same value; distinct filesystems
    /// return distinct values. Used by `name_to_handle_at`'s `mount_id`
    /// and mount-point detection (`is_mount_point` compares a path's id
    /// to its parent's). Derives from `i_sb().s_dev` once the FS owns a
    /// SuperBlock; default `0` = the root/ext4 domain. Pseudo filesystems
    /// not yet SB-backed override it directly so a mount boundary is
    /// observable — without it, systemd's cgroup walk never finds the
    /// `/sys/fs/cgroup` boundary and loops forever.
    /// # C: O(1)
    fn fsid(&self) -> u64 { self.i_sb().map(|s| s.s_dev).unwrap_or(0) }

    /// Link count reported through stat/statx. Filesystems with real
    /// metadata should override this with their stored inode link count.
    /// The default matches Linux's baseline shape: non-directories have
    /// one link, an empty directory has "." and its parent's entry.
    /// # C: O(1)
    fn nlink(&self) -> u32 {
        if matches!(self.file_type(), FileType::Directory) { 2 } else { 1 }
    }

    /// Preferred I/O block size reported through stat/statx. Filesystems
    /// with a superblock or device block size should override it.
    /// # C: O(1)
    fn blksize(&self) -> u32 { 4096 }

    /// Filesystem magic for anonymous or pathless inodes reported by
    /// `fstatfs(2)`. Mounted filesystems normally report through their mount's
    /// `FileSystem::magic`; anonymous descriptor families such as pidfd have no
    /// stable pathname, so the inode itself supplies the superblock magic.
    /// `0` means "use the path/mount based fallback".
    /// # C: O(1)
    fn statfs_magic(&self) -> u64 { 0 }

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

    /// `i_op->get_link` (Linux `fs/namei.c`) — the VFS symlink-resolution entry
    /// the path walker and `readlink(2)` call. Default delegates to `readlink`
    /// (the storage primitive), so backends overriding `readlink` need no
    /// further change; a backend with a page-cached or RCU link can override
    /// `get_link` directly. # C: O(target_len)
    fn get_link(&self) -> KResult<alloc::vec::Vec<u8>> { self.readlink() }

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

    /// Readiness query that knows the caller's per-fd read cursor (`File::pos`).
    /// Needed for append-only streams whose readability depends on whether the
    /// reader has caught up to the head — notably `/dev/kmsg`, where the
    /// position-less `poll()` defaults to always-`POLL_IN` and busy-loops
    /// systemd's journald epoll. Default forwards to `poll()`.
    /// # C: O(1)
    fn poll_file(&self, pos: u64) -> u32 { let _ = pos; self.poll() }

    /// Linux per-file `show_fdinfo`: file-type-specific lines appended to
    /// `/proc/<pid>/fdinfo/<n>` AFTER the generic `pos/flags/mnt_id/ino`.
    /// A pidfd emits `Pid:`/`NSpid:` (kernel/pid.c `pidfd_show_fdinfo`);
    /// glibc/systemd `pidfd_get_pid()` parses the `Pid:` line and reports
    /// ENOTTY when it is missing. Default = no extra lines. # C: O(1)
    fn fdinfo_extra(&self, _out: &mut alloc::vec::Vec<u8>) {}

    /// `i_mapping` — the inode's `address_space` (Linux `inode->i_mapping`):
    /// the ONE per-inode page cache, keyed by page index, shared by every
    /// mapper of this inode. `Some` for inodes whose data lives in persistent
    /// page-cache frames (tmpfs/shmem now; regular files as ext4 opts in);
    /// `None` (default) for inodes without a frame-backed cache. The mmap
    /// fault path and `InodeFileBacking` route through this so two `mmap()`s
    /// of one inode share one address space (not two per-backing caches).
    /// # C: O(1)
    fn i_mapping(&self) -> Option<&dyn crate::mapping::AddressSpaceOps> { None }

    /// `MAP_SHARED` page-cache frame for page-aligned file offset `off`.
    /// Returns the persistent backing PMM frame so a shared mapping aliases
    /// the file's own storage (Linux shmem / page cache) — user writes
    /// propagate to the file and to every other mapper. The default forwards
    /// to `i_mapping()` (the per-inode address space): `Some(pa)` when the
    /// inode has a frame-backed cache, else `None` → the fault handler copies
    /// via `read` into a fresh private frame (correct for `MAP_PRIVATE`; the
    /// only option for backings without page-frame storage).
    /// # C: O(log N_pages)
    fn mmap_shared_frame(&self, off: u64) -> Option<u64> {
        self.i_mapping().and_then(|m| m.shared_frame(off))
    }

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

    /// Device number (`dev_t`, packed `(major<<8)|minor` Linux legacy
    /// encoding) for a char/block device node. `0` = not a device / no
    /// number. Linux devtmpfs nodes carry their real `dev_t` from the
    /// driver model; `stat`/`fstat`/`statx` report it as `st_rdev`.
    /// Non-device inodes leave this 0.
    /// # C: O(1)
    fn rdev(&self) -> u32 { 0 }

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

    /// `i_op->getattr` (Linux `fs/stat.c`) — assemble the `Kstat` stat/statx
    /// report. Default `generic_fillattr` reads the trait accessors, merges the
    /// kernel `inode_times` overlay, and applies the mount idmap to the owner
    /// ids. Backends with native metadata (ext4) override. # C: O(1)
    fn getattr(&self, idmap: &crate::idmap::Idmap, overlay: Option<crate::inode_times::InodeTimes>)
        -> crate::getattr::Kstat
    {
        crate::getattr::generic_fillattr(self, idmap, overlay)
    }

    /// `i_op->setattr` (Linux `fs/attr.c`) — apply a prepared `Iattr` to the
    /// inode's native metadata. Default `simple_setattr` (via the existing
    /// `set_perm`/`set_owner`/`set_times`/`truncate` primitives) returns `Erofs`
    /// for inodes without native storage, so the kernel `notify_change` falls
    /// back to its metadata overlay. # C: O(1)
    fn setattr(&self, idmap: &crate::idmap::Idmap, ia: &crate::setattr::Iattr) -> KResult<()> {
        crate::setattr::simple_setattr(self, idmap, ia)
    }

    /// Open-time hook per Linux `file_operations->open`. Fired by the
    /// open path after path resolution, before the `File`/fd is built, so
    /// a driver can reject the open. Default `Ok`. pty SLAVE overrides to
    /// return `Eio` while the pair is `TIOCSPTLCK`-locked (Linux
    /// `pts_unix98_lookup` returns `-EIO` on a locked slave — glibc/musl
    /// `unlockpt` clears it before the slave is opened).
    /// # C: O(1)
    fn on_open(&self) -> KResult<()> { Ok(()) }

    /// Last-close ("release") hook per Linux `file_operations->release`.
    /// Fired by `File`'s Drop when the final fd referencing one open
    /// file description closes (incl. on process exit, when the fd
    /// table drops its `Arc<File>`s). dup'd fds share the `Arc<File>`,
    /// so this fires exactly once per open description — the Linux
    /// release point. Default no-op; pty MASTER overrides to hang up
    /// the slave (master close → slave EOF/EIO). MUST NOT panic and
    /// MUST NOT block (called from Drop, possibly on the exit path).
    /// # C: O(1)
    fn on_release(&self) {}

    /// Per-close flush hook per Linux `file_operations->flush`. Fired by
    /// `FdTable::close`/`dup2`-replace/cloexec-drop on EVERY `close(2)`
    /// of an fd referencing this open description (not only the last —
    /// that is `on_release`). Default no-op. MUST NOT panic or block.
    /// # C: O(1)
    fn on_flush(&self) {}

    /// memfd file-sealing state (`fcntl(F_ADD_SEALS/F_GET_SEALS)`,
    /// `docs/19`). `Some(&seals)` only for a sealable memfd (created with
    /// `MFD_ALLOW_SEALING`); `None` for every other inode, where
    /// `F_ADD_SEALS`/`F_GET_SEALS` is `EINVAL`. The bits are
    /// `F_SEAL_{SEAL,SHRINK,GROW,WRITE,FUTURE_WRITE}`; the FS enforces
    /// WRITE on `write`, SHRINK/GROW on `truncate`.
    /// # C: O(1)
    fn fcntl_seals(&self) -> Option<&core::sync::atomic::AtomicU32> { None }
}

/// `i_state` bits (Linux `include/linux/fs.h`). Stored per-ino in the owning
/// superblock's inode cache (see `SuperBlock::i_state`), NOT on the trait
/// object — the trait-object inodes carry no shared state block, so lifecycle
/// state lives icache-side (one place, zero per-FS-impl churn).
/// `I_NEW` is set by `iget` on a build-miss and cleared once the inode is
/// installed (Linux `unlock_new_inode`); a concurrent `ilookup` upgrades the
/// fully-built `Arc` regardless, so `I_NEW` is the build-race marker only.
pub const I_DIRTY:   u32 = 0x0007; // I_DIRTY_SYNC|DATASYNC|PAGES
pub const I_NEW:     u32 = 0x0008; // 1<<3 — being constructed
pub const I_FREEING: u32 = 0x0020; // 1<<5 — being evicted

/// `poll(2)` event bitmasks. Numeric reps match Linux exactly.
pub const POLL_IN:    u32 = 0x0001;  // POLLIN  — readable
pub const POLL_OUT:   u32 = 0x0004;  // POLLOUT — writable
pub const POLL_HUP:   u32 = 0x0010;  // POLLHUP — peer closed
pub const POLL_ERR:   u32 = 0x0008;  // POLLERR — io error
pub const POLL_PRI:   u32 = 0x0002;  // POLLPRI — urgent (TCP OOB)
pub const POLL_RDHUP: u32 = 0x2000;  // POLLRDHUP — peer-closed-write

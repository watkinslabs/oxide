// namei shared helpers — THE resolver feeding namespace mutations
// (docs/16§3) + path/errno utilities used by ≥2 namei handlers.
// Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// # C: O(1)
pub(crate) fn read_path(ptr: u64) -> Option<String> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 256 B bound.
    let bytes = unsafe { devfs::read_user_cstr(ptr, 256) }?;
    if bytes.is_empty() { return None; }
    core::str::from_utf8(bytes).ok().map(|s| s.into())
}

/// Linux PATH_MAX (includes the terminating NUL); the longest pathname a
/// syscall accepts is `PATH_MAX - 1` bytes.
pub(crate) const PATH_MAX: usize = 4096;

/// Read a user-space pathname with the full Linux errno contract:
///   * NULL / out-of-range ptr  → **EFAULT**
///   * empty string (`""`)      → **ENOENT** (callers without AT_EMPTY_PATH)
///   * pathname ≥ PATH_MAX bytes → **ENAMETOOLONG**
///   * non-UTF-8 bytes          → byte-preserved (Linux paths are opaque
///     byte strings, `path_resolution(7)`); decoded via
///     `vfs::path_from_bytes` so a non-UTF-8 component still resolves.
/// Returns `Ok(empty)` is impossible — empty maps to ENOENT here; callers
/// that allow AT_EMPTY_PATH must probe emptiness before calling.
/// # C: O(strlen)
pub(crate) fn read_user_path(ptr: u64) -> Result<String, i64> {
    if ptr == 0 || ptr >= USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); PATH_MAX bound.
    let bytes = unsafe { devfs::read_user_cstr(ptr, PATH_MAX) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    // No NUL within PATH_MAX bytes → pathname too long (Linux ENAMETOOLONG).
    if bytes.len() >= PATH_MAX {
        return Err(-(Errno::Enametoolong.as_i32() as i64));
    }
    if bytes.is_empty() {
        return Err(-(Errno::Enoent.as_i32() as i64));
    }
    Ok(vfs::path_from_bytes(bytes))
}

/// # C: O(1)
pub(crate) fn resolve(path_raw: &str) -> Option<String> {
    if path_raw.starts_with('/') { return Some(path_raw.into()); }
    let cur = sched::live::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

/// # C: O(1)
/// Distinct `st_dev` per filesystem, derived from the inode-number namespace
/// each FS allocates from: ext4 stamps `EXT4_INO_MARK` (0x6E54..) in the top
/// 32 bits; the synthetic FSes use distinct high nibbles (devfs 0x2xxx_xxxx,
/// procfs 0x3xxx_xxxx, tmpfs 0x4xxx_xxxx+, sysfs/bpf above). systemd's
/// mount-boundary detection compares `st_dev` across a path — with every
/// `st_dev == 0` it cannot tell one filesystem from another, which breaks its
/// cgroup/credentials/os-release boundary walks. Linux gives each mount its
/// own `dev_t` (a block dev_t or an anon-bdev); this is the stable analogue.
/// # C: O(1)
pub(crate) fn encode_dev(major: u32, minor: u32) -> u64 {
    ((minor & 0xff) as u64)
        | (((major & 0xfff) as u64) << 8)
        | (((minor & !0xff) as u64) << 12)
        | (((major & !0xfff) as u64) << 32)
}

pub(crate) fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

pub(crate) fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Encode a filesystem identity into Linux `dev_t`. The source identity is
/// owned by the filesystem (`Inode::fsid()`); this helper only gives it the
/// ABI shape expected by stat/statx.
/// # C: O(1)
pub(crate) fn fsid_to_dev(fsid: u64) -> u64 {
    let mut x = fsid;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    let major = (((x >> 20) & 0x0fff) as u32).max(1);
    let minor = (x & 0x000f_ffff) as u32;
    encode_dev(major, minor)
}

/// Map a `VfsError` to the negative Linux errno the ABI returns. Complete
/// over every `VfsError` discriminant so a path-walk error (ELOOP /
/// ENAMETOOLONG / ENOTDIR / EACCES) propagates with its true errno instead
/// of collapsing to EIO/ENOENT.
/// # C: O(1)
pub(crate) fn errno_from_vfs(e: vfs::VfsError) -> i64 {
    -(match e {
        vfs::VfsError::Eperm   => Errno::Eperm   as i32,
        vfs::VfsError::Enoent  => Errno::Enoent  as i32,
        vfs::VfsError::Eintr   => Errno::Eintr   as i32,
        vfs::VfsError::Eio     => Errno::Eio     as i32,
        vfs::VfsError::Enxio   => Errno::Enxio   as i32,
        vfs::VfsError::Ebadf   => Errno::Ebadf   as i32,
        vfs::VfsError::Enomem  => Errno::Enomem  as i32,
        vfs::VfsError::Eacces  => Errno::Eacces  as i32,
        vfs::VfsError::Efault  => Errno::Efault  as i32,
        vfs::VfsError::Eexist  => Errno::Eexist  as i32,
        vfs::VfsError::Exdev   => Errno::Exdev   as i32,
        vfs::VfsError::Enodev  => Errno::Enodev  as i32,
        vfs::VfsError::Enotdir => Errno::Enotdir as i32,
        vfs::VfsError::Eisdir  => Errno::Eisdir  as i32,
        vfs::VfsError::Einval  => Errno::Einval  as i32,
        vfs::VfsError::Emfile  => Errno::Emfile  as i32,
        vfs::VfsError::Enotty  => Errno::Enotty  as i32,
        vfs::VfsError::Espipe  => Errno::Espipe  as i32,
        vfs::VfsError::Eagain  => Errno::Eagain  as i32,
        vfs::VfsError::Epipe   => Errno::Epipe   as i32,
        vfs::VfsError::Erofs   => Errno::Erofs   as i32,
        vfs::VfsError::Ebusy   => Errno::Ebusy   as i32,
        vfs::VfsError::Enospc  => Errno::Enospc  as i32,
        vfs::VfsError::Enotempty => Errno::Enotempty as i32,
        vfs::VfsError::Enosys  => Errno::Enosys  as i32,
        vfs::VfsError::Eloop   => Errno::Eloop   as i32,
        vfs::VfsError::Eopnotsupp => Errno::Eopnotsupp as i32,
        vfs::VfsError::Enametoolong => Errno::Enametoolong as i32,
        vfs::VfsError::Enotconn => Errno::Enotconn as i32,
    } as i64)
}

/// Boot diagnostic for namespace mutation failures during systemd setup.
pub(crate) fn trace_run_vfs_error(op: &[u8], path: &str, e: vfs::VfsError) {
    klog::write_raw(b"[NAMEI] ");
    klog::write_raw(op);
    klog::write_raw(b" path=\"");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"\" err=");
    klog::write_dec_u64(e as u64);
    klog::write_raw(b"\n");
}

/// Split an absolute path into `(parent, basename)`. `None` for `/`
/// or a trailing-only slash.
/// # C: O(N)
fn split_parent(p: &str) -> Option<(&str, &str)> {
    let p = if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p };
    let idx = p.rfind('/')?;
    let name = &p[idx + 1..];
    if name.is_empty() { return None; }
    let parent = if idx == 0 { "/" } else { &p[..idx] };
    Some((parent, name))
}

/// Resolve the PARENT directory of absolute `p` through the dentry walk
/// (`pathresolve::resolve` = `vfs::path_lookup`; follows intermediate
/// symlinks + crosses mounts) and return `(parent_inode, basename)` —
/// THE resolver feeding every namespace mutation per `docs/16§3`,
/// replacing the old path-prefix / pseudo-fs string gates.
/// The owning mount's inode then services the op (ext4 dir → ext4
/// create/unlink; tmpfs dir → tmpfs; cgroupfs → cgroupfs; read-only
/// pseudo-fs → Erofs), exactly as Linux `inode_operations`.
/// # C: O(N parent components)
pub(crate) fn resolve_parent(p: &str) -> Result<(vfs::InodeRef, String), i64> {
    let p = strip_trailing_slash(p);
    let (parent, name) = split_parent(p).ok_or(-(Errno::Einval.as_i32() as i64))?;
    let pino = crate::pathresolve::resolve(parent, false)
        .ok_or(-(Errno::Enoent.as_i32() as i64))?;
    Ok((pino, String::from(name)))
}

/// True if `p` already resolves to an existing inode (final component
/// not followed if it's a symlink). Linux checks target existence
/// before the fs-specific `mkdir`, returning EEXIST regardless of
/// parent writability. Without this, `mkdir` of an existing dir whose
/// parent is a read-only pseudo-fs leaks the parent's EROFS — e.g.
/// systemd's `cg_create("/")` does `mkdir("/sys/fs/cgroup")` (already
/// present), whose parent `/sys/fs` is sysfs → EROFS instead of the
/// EEXIST systemd treats as success, aborting its cgroup setup.
/// # C: O(N path components)
pub(crate) fn path_exists(p: &str) -> bool {
    crate::pathresolve::resolve(p, true).is_some()
}

/// Linux pathname AF_UNIX sockets are removed from the filesystem namespace by
/// unlink(2). Existing socket objects stay alive, but a later bind to the same
/// pathname must be allowed. Our socket registry is separate from tmpfs, so
/// unlink has to drop the registry key as well as the socket inode.
/// # C: O(log N)
pub(crate) fn unlink_unix_socket_path(p: &str) -> bool {
    if net::unix_path_is_abstract(p) || !net::sock::UNIX_REGISTRY.is_bound(p) {
        return false;
    }
    net::sock::UNIX_REGISTRY.unbind(p);
    net::sock::UNIX_REGISTRY.dgram_unbind(p);
    crate::pathresolve::d_delete_path(p);
    true
}

/// Strip a trailing `/` (POSIX: `mkdir /var/` ≡ `mkdir /var`). Root
/// `/` is preserved. GNU `mkdir -p` walks ancestors with a
/// trailing slash on each prefix; without this the ext4 backend
/// resolves `/var/` to a missing child and returns ENOENT for a dir
/// that exists.
/// # C: O(1)
pub(crate) fn strip_trailing_slash(p: &str) -> &str {
    if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p }
}

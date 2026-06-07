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

/// # C: O(1)
pub(crate) fn resolve(path_raw: &str) -> Option<String> {
    if path_raw.starts_with('/') { return Some(path_raw.into()); }
    let cur = sched::live::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

/// # C: O(1)
pub(crate) fn is_ext4_path(p: &str) -> bool {
    p.starts_with("/bin/")  || p.starts_with("/etc/")  || p.starts_with("/usr/")
 || p.starts_with("/sbin/") || p.starts_with("/lib/")  || p.starts_with("/opt/")
 || p.starts_with("/home/") || p.starts_with("/root/") || p == "/init"
 || p == "/hello.txt"
 // B47: /var and /tmp host writable state for daemons (dhcpcd's
 // lease + control socket dirs, /tmp for temporary files). We
 // pre-create the parent dirs in the ext4 image and mount tmpfs
 // over /var/{run,db} + /tmp; dhcpcd does mkdir('/var/db/dhcpcd')
 // (EEXIST is fine) which our gate was returning EROFS for. Route
 // those to ext4 too — the overlay-mount machinery rides a
 // follow-up; for now the tmpfs mount silently shadows the dir.
 || p.starts_with("/var/") || p.starts_with("/tmp/") || p.starts_with("/run/")
}

/// # C: O(1)
pub(crate) fn errno_from_vfs(e: vfs::VfsError) -> i64 {
    -(match e {
        vfs::VfsError::Enoent  => Errno::Enoent  as i32,
        vfs::VfsError::Eisdir  => Errno::Eisdir  as i32,
        vfs::VfsError::Enotdir => Errno::Enotdir as i32,
        vfs::VfsError::Erofs   => Errno::Erofs   as i32,
        vfs::VfsError::Eio     => Errno::Eio     as i32,
        vfs::VfsError::Eperm   => Errno::Eperm   as i32,
        vfs::VfsError::Eexist  => Errno::Eexist  as i32,
        vfs::VfsError::Einval  => Errno::Einval  as i32,
        vfs::VfsError::Eacces  => Errno::Eacces  as i32,
        vfs::VfsError::Enomem  => Errno::Enomem  as i32,
        vfs::VfsError::Enospc  => Errno::Enospc  as i32,
        vfs::VfsError::Ebusy   => Errno::Ebusy   as i32,
        vfs::VfsError::Enotempty => Errno::Enotempty as i32,
        vfs::VfsError::Enosys  => Errno::Enosys  as i32,
        _                      => Errno::Eio     as i32,
    } as i64)
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
/// replacing the is_ext4_path / mount_for_write / pseudo_* string gates.
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

/// Strip a trailing `/` (POSIX: `mkdir /var/` ≡ `mkdir /var`). Root
/// `/` is preserved. GNU `mkdir -p` walks ancestors with a
/// trailing slash on each prefix; without this the ext4 backend
/// resolves `/var/` to a missing child and returns ENOENT for a dir
/// that exists.
/// # C: O(1)
pub(crate) fn strip_trailing_slash(p: &str) -> &str {
    if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p }
}

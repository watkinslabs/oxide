#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

use super::cred::current_cred;
use super::root::resolution_root_vfs;

pub const AT_FDCWD: i32 = -100;

// Hosted tests cannot install a per-CPU runqueue, so they drive the
// hook-installable `sched::current()` instead of the real per-CPU
// `sched::live::current()`. Kernel builds are unaffected (same call). Matches
// the established `032_dup.rs` split.
#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }
#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// # C: O(components × dir-lookup)
pub fn resolve_confined(dirfd: i32, raw: &str, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let op = b"resolve_confined";
    // `false`: openat2 RESOLVE_BENEATH/RESOLVE_IN_ROOT (the only callers of
    // `resolve_confined`) make dirfd itself the resolution root — Linux
    // `ND_ROOT_PRESET` validates it (ENOTDIR on a non-directory) even for an
    // absolute pathname, unlike the plain `*at` family below.
    let (mid, base) = dirfd_base(dirfd, b"resolve_confined", raw, false)?;
    vfs::path_lookup_at_cred(base.clone(), mid, base, raw, flags, current_cred())
        .map_err(|e| {
            if e == vfs::VfsError::Enotdir {
                trace_enotdir(op, dirfd, raw, b"walk", None, mid, b"");
            }
            crate::namei_common::errno_from_vfs(e)
        })
}

/// Resolve the dirfd/cwd base for a `*at` pathname. `ignore_if_absolute`:
/// Linux `path_init` never looks at `dfd` when `pathname` is absolute — it
/// jumps straight to `nd->root` (`nd_jump_root`) before `dfd` is fetched or
/// validated, so a closed/invalid dirfd (`EBADF`) or a non-directory dirfd
/// (`ENOTDIR`) must NOT surface for an absolute path. `walk_inner`'s leading
/// `/` branch (`crates/kernel/vfs/src/namei/walk.rs`) already resets the walk
/// to the resolution root and discards whatever `start` this function
/// returns, so the value handed back on this path is never consulted —
/// still fetching a real one keeps the return type simple and matches what
/// `walk()` uses anyway. Pass `false` (see `resolve_confined`) when dirfd
/// itself IS the resolution root and must stay validated regardless of the
/// pathname's leading slash.
fn dirfd_base(dirfd: i32, op: &'static [u8], raw: &str, ignore_if_absolute: bool) -> Result<(u64, Arc<vfs::Dentry>), i64> {
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    if ignore_if_absolute && raw.as_bytes().first() == Some(&b'/') {
        let root = resolution_root_vfs().ok_or(ebadf)?.0;
        return Ok((root.mnt_id, root.dentry));
    }
    let cur = current_task().ok_or(ebadf)?;
    if dirfd == AT_FDCWD {
        if let Some(p) = cur.fs_context_snapshot().cwd_vfs() {
            if p.mnt_id != vfs::mount::MNT_ID_NONE { return Ok((p.mnt_id, p.dentry)); }
        }
        let root = resolution_root_vfs().ok_or(ebadf)?.0;
        return Ok((root.mnt_id, root.dentry));
    }
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
    let f = fdt.get(dirfd).map_err(|_| ebadf)?;
    if f.inode().file_type() != vfs::FileType::Directory {
        trace_enotdir(op, dirfd, raw, b"dirfd-base", Some(f.inode().file_type()), f.mnt_id(), f.dentry().absolute_path().as_slice());
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    Ok((f.mnt_id(), f.dentry().clone()))
}

/// # C: O(components × dir-lookup) + O(symlinks)
pub fn resolve_at_path(dirfd: i32, raw: &str, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    resolve_at_path_cred(dirfd, raw, flags, current_cred())
}

/// # C: O(components × dir-lookup) + O(symlinks)
pub fn resolve_at_path_cred(dirfd: i32, raw: &str, mut flags: vfs::LookupFlags, cred: vfs::Cred) -> Result<vfs::VfsPath, i64> {
    // `true`: the plain `*at` family ignores dirfd entirely for an absolute
    // pathname (Linux `path_init`), so an open non-directory or a
    // closed/invalid dirfd must not error here.
    let (mid, base) = dirfd_base(dirfd, b"resolve_at_path", raw, true)?;
    let (root, beneath) = resolution_root_vfs().ok_or(-(Errno::Enoent.as_i32() as i64))?;
    flags.beneath = flags.beneath || beneath;
    vfs::path_lookup_at_root_cred(base, mid, root.dentry, root.mnt_id, raw, flags, cred)
        .map_err(|e| {
            if e == vfs::VfsError::Enotdir {
                trace_enotdir(b"resolve_at_path", dirfd, raw, b"walk", None, mid, b"");
            }
            crate::namei_common::errno_from_vfs(e)
        })
}

/// Resolve the parent directory of a `*at` pathname while preserving the
/// dirfd/cwd mount identity. # C: O(components × dir-lookup) + O(symlinks)
pub fn resolve_parent_at(dirfd: i32, raw: &str) -> Result<vfs::VfsPath, i64> {
    resolve_at_path(dirfd, raw, vfs::LookupFlags { parent: true, ..Default::default() })
}

/// Probe whether a user pathname is the empty string without consuming normal
/// non-empty paths. NULL/unreadable pointers are `EFAULT`. # C: O(1)
pub(crate) fn at_path_empty(ptr: u64) -> Result<bool, i64> {
    if ptr == 0 || ptr >= USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    unsafe { devfs::read_user_cstr(ptr, 1) }
        .map(|b| b.is_empty())
        .ok_or(-(Errno::Efault.as_i32() as i64))
}

/// # C: O(components × dir-lookup)
fn resolve_empty_at(dirfd: i32) -> Result<vfs::VfsPath, i64> {
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    if dirfd == AT_FDCWD {
        let cur = current_task().ok_or(ebadf)?;
        if let Some(p) = cur.fs_context_snapshot().cwd_vfs() {
            if p.mnt_id != vfs::mount::MNT_ID_NONE { return Ok(p); }
        }
        return Ok(resolution_root_vfs().ok_or(ebadf)?.0);
    }
    let cur = current_task().ok_or(ebadf)?;
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
    let f = fdt.get(dirfd).map_err(|_| ebadf)?;
    Ok(vfs::VfsPath { mnt_id: f.mnt_id(), dentry: f.dentry().clone(), inode: f.inode().clone(), last_component: None })
}

/// # C: O(components × dir-lookup)
pub fn resolve_at_lookup(dirfd: i32, path_ptr: u64, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    resolve_at_lookup_cred(dirfd, path_ptr, flags, current_cred())
}

/// # C: O(components × dir-lookup)
pub fn resolve_at_lookup_cred(dirfd: i32, path_ptr: u64, flags: vfs::LookupFlags, cred: vfs::Cred) -> Result<vfs::VfsPath, i64> {
    if at_path_empty(path_ptr)? {
        if !flags.empty { return Err(-(Errno::Enoent.as_i32() as i64)); }
        return resolve_empty_at(dirfd);
    }
    let raw = crate::namei_common::read_user_path(path_ptr)?;
    resolve_at_path_cred(dirfd, &raw, flags, cred)
}

/// Linux stat-family `getname_maybe_null`: NULL is allowed only when
/// AT_EMPTY_PATH is set. Non-stat callers must keep using `resolve_at_lookup`
/// so their NULL path remains EFAULT.
/// # C: O(components × dir-lookup)
pub fn resolve_at_lookup_maybe_null(dirfd: i32, path_ptr: u64, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    if path_ptr == 0 {
        if !flags.empty { return Err(-(Errno::Efault.as_i32() as i64)); }
        return resolve_empty_at(dirfd);
    }
    resolve_at_lookup(dirfd, path_ptr, flags)
}

#[cfg(feature = "debug-boot")]
fn trace_enotdir(op: &'static [u8], dirfd: i32, raw: &str, why: &'static [u8], ft: Option<vfs::FileType>, mnt_id: u64, fd_path: &[u8]) {
    klog::write_raw(b"[ENOTDIR] op=");
    klog::write_raw(op);
    klog::write_raw(b" why=");
    klog::write_raw(why);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" dirfd=");
    if dirfd < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-(dirfd as i64)) as u64); }
    else { klog::write_dec_u64(dirfd as u64); }
    klog::write_raw(b" mnt=");
    klog::write_dec_u64(mnt_id);
    klog::write_raw(b" ft=");
    match ft {
        Some(vfs::FileType::Directory) => klog::write_raw(b"dir"),
        Some(vfs::FileType::Regular)   => klog::write_raw(b"reg"),
        Some(vfs::FileType::Symlink)   => klog::write_raw(b"lnk"),
        Some(vfs::FileType::CharDev)   => klog::write_raw(b"chr"),
        Some(vfs::FileType::BlockDev)  => klog::write_raw(b"blk"),
        Some(vfs::FileType::Fifo)      => klog::write_raw(b"fifo"),
        Some(vfs::FileType::Socket)    => klog::write_raw(b"sock"),
        None                           => klog::write_raw(b"none"),
    }
    klog::write_raw(b" raw=");
    klog::write_raw(raw.as_bytes());
    klog::write_raw(b" fdpath=");
    klog::write_raw(fd_path);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn trace_enotdir(_op: &'static [u8], _dirfd: i32, _raw: &str, _why: &'static [u8], _ft: Option<vfs::FileType>, _mnt_id: u64, _fd_path: &[u8]) {}

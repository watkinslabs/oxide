#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

use super::cred::current_cred;
use super::lookup::{resolve_path_flags, resolve_result};
use super::root::{resolution_root, root_dentry};

pub const AT_FDCWD: i32 = -100;

/// # C: O(components × dir-lookup)
pub fn resolve_confined(dirfd: i32, raw: &str, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let (mid, base) = dirfd_base(dirfd)?;
    vfs::path_lookup_at_cred(base.clone(), mid, base, raw, flags, current_cred())
        .map_err(crate::namei_common::errno_from_vfs)
}

fn dirfd_base(dirfd: i32) -> Result<(u64, Arc<vfs::Dentry>), i64> {
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    let cur = sched::live::current().ok_or(ebadf)?;
    if dirfd == AT_FDCWD {
        // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is sole writer.
        if let Some(p) = unsafe { (*cur.cwd_vfs.get()).clone() } {
            return Ok((p.mnt_id, p.dentry));
        }
        let d = root_dentry().ok_or(ebadf)?;
        return Ok((0, d));
    }
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
    let f = fdt.get(dirfd).map_err(|_| ebadf)?;
    if f.inode().file_type() != vfs::FileType::Directory {
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    Ok((f.mnt_id(), f.dentry().clone()))
}

/// # C: O(components × dir-lookup) + O(symlinks)
pub fn resolve_at_path(dirfd: i32, raw: &str, mut flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let (mid, base) = dirfd_base(dirfd)?;
    let (root, beneath) = resolution_root().ok_or(-(Errno::Enoent.as_i32() as i64))?;
    flags.beneath = flags.beneath || beneath;
    vfs::path_lookup_at_cred(base, mid, root, raw, flags, current_cred())
        .map_err(crate::namei_common::errno_from_vfs)
}

/// # C: O(N_path) + O(1) fd lookup
pub fn resolve_at_result(dirfd: i32, raw: &str) -> Result<String, i64> {
    if raw.starts_with('/') {
        return vfs::path::lexical_normalize(raw).ok_or(-(Errno::Enoent.as_i32() as i64));
    }
    if dirfd == AT_FDCWD { return Ok(resolve_cwd(raw)); }
    let cur = sched::live::current().ok_or(-(Errno::Ebadf.as_i32() as i64))?;
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(-(Errno::Ebadf.as_i32() as i64))?.clone();
    let f = fdt.get(dirfd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))?;
    if f.inode().file_type() != vfs::FileType::Directory {
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    let base_bytes = f.dentry().absolute_path();
    let base = core::str::from_utf8(&base_bytes).map_err(|_| -(Errno::Enotdir.as_i32() as i64))?;
    vfs::path::resolve_against_cwd(base, raw).ok_or(-(Errno::Enoent.as_i32() as i64))
}

pub fn resolve_at(dirfd: i32, raw: &str) -> Option<String> {
    resolve_at_result(dirfd, raw).ok()
}

fn at_path_empty(ptr: u64) -> bool {
    if ptr == 0 { return true; }
    if ptr >= USER_VA_END { return false; }
    unsafe { devfs::read_user_cstr(ptr, 1) }.map_or(true, |b| b.is_empty())
}

/// # C: O(components × dir-lookup)
pub fn resolve_at_lookup(dirfd: i32, path_ptr: u64, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    if at_path_empty(path_ptr) {
        if !flags.empty { return Err(-(Errno::Enoent.as_i32() as i64)); }
        if dirfd == AT_FDCWD {
            let cur = sched::live::current().ok_or(ebadf)?;
            // SAFETY: cwd_vfs slot single-mutator per 13§5; current task sole writer.
            if let Some(p) = unsafe { (*cur.cwd_vfs.get()).clone() } { return Ok(p); }
            let dentry = root_dentry().ok_or(ebadf)?;
            let inode = dentry.inode().ok_or(ebadf)?;
            return Ok(vfs::VfsPath { mnt_id: 0, dentry, inode, last_component: None });
        }
        let cur = sched::live::current().ok_or(ebadf)?;
        // SAFETY: running task on this CPU; sole reader of its fd_table slot.
        let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
        let f = fdt.get(dirfd).map_err(|_| ebadf)?;
        return Ok(vfs::VfsPath { mnt_id: f.mnt_id(), dentry: f.dentry().clone(), inode: f.inode().clone(), last_component: None });
    }
    let raw = crate::namei_common::read_user_path(path_ptr)?;
    match resolve_at_path(dirfd, &raw, flags) {
        Ok(p) => Ok(p),
        Err(rv) if rv == -(Errno::Enoent.as_i32() as i64) => {
            let abs = resolve_at_result(dirfd, &raw)?;
            resolve_path_flags(&abs, flags).map_err(crate::namei_common::errno_from_vfs)
        }
        Err(rv) => Err(rv),
    }
}

/// # C: O(N_path components)
pub fn resolve_cwd(raw: &str) -> String {
    if raw.starts_with('/') {
        return vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into());
    }
    let Some(cur) = sched::live::current() else { return raw.into(); };
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, raw).unwrap_or_else(|| raw.into())
}

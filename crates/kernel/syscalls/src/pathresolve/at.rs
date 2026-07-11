#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

use super::cred::current_cred;
use super::root::{resolution_root_vfs, root_dentry};

pub const AT_FDCWD: i32 = -100;

/// # C: O(components × dir-lookup)
pub fn resolve_confined(dirfd: i32, raw: &str, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let op = b"resolve_confined";
    let (mid, base) = dirfd_base(dirfd, b"resolve_confined", raw)?;
    vfs::path_lookup_at_cred(base.clone(), mid, base, raw, flags, current_cred())
        .map_err(|e| {
            if e == vfs::VfsError::Enotdir {
                trace_enotdir(op, dirfd, raw, b"walk", None, mid, b"");
            }
            crate::namei_common::errno_from_vfs(e)
        })
}

fn dirfd_base(dirfd: i32, op: &'static [u8], raw: &str) -> Result<(u64, Arc<vfs::Dentry>), i64> {
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
        trace_enotdir(op, dirfd, raw, b"dirfd-base", Some(f.inode().file_type()), f.mnt_id(), f.dentry().absolute_path().as_slice());
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    Ok((f.mnt_id(), f.dentry().clone()))
}

/// # C: O(components × dir-lookup) + O(symlinks)
pub fn resolve_at_path(dirfd: i32, raw: &str, mut flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let (mid, base) = dirfd_base(dirfd, b"resolve_at_path", raw)?;
    let (root, beneath) = resolution_root_vfs().ok_or(-(Errno::Enoent.as_i32() as i64))?;
    flags.beneath = flags.beneath || beneath;
    vfs::path_lookup_at_root_cred(base, mid, root.dentry, root.mnt_id, raw, flags, current_cred())
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
    resolve_at_path(dirfd, &raw, flags)
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

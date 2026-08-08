#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::perms_common::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, resolve_fd_file, resolve_xattr_at_mnt, with_mnt_write};

#[cfg(feature = "debug-mount")]
fn log_path_error(op: &str, path_ptr: u64, rv: i64) {
    if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
        if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log(op, &path, rv); }
    }
}

/// Resolve a legacy path xattr target; l-variants pass `follow=false`. # C: O(N_path)
fn resolve_legacy_path(path_ptr: u64, follow: bool) -> Result<(vfs::InodeRef, u64), i64> {
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    resolve_xattr_at_mnt(AT_FDCWD, path_ptr, flags)
}

/// Resolve an fd xattr target. # C: O(1)
fn resolve_fd(fd: i32) -> Result<Arc<vfs::File>, i64> {
    resolve_fd_file(fd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))
}

/// `setxattr/lsetxattr` work shared by slots 188/189. Linux `setxattr_copy`
/// imports name+value+flags BEFORE `filename_lookup`, so a bad name outranks a
/// bad path. # C: O(N_path + N_xattrs)
pub fn sys_setxattr_path(args: &SyscallArgs, follow: bool) -> i64 {
    let ctx = match ::fs::xattr::import_set(args.a1, args.a2, args.a3 as usize, args.a4 as u32) {
        Ok(c) => c, Err(rv) => return rv,
    };
    let (inode, mnt_id) = match resolve_legacy_path(args.a0, follow) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")] log_path_error("setxattr_resolve", args.a0, rv);
        return rv;
    } };
    let rv = with_mnt_write(mnt_id, || ::fs::xattr::set_on(&inode, ctx));
    #[cfg(feature = "debug-mount")] if rv < 0 { log_path_error("setxattr", args.a0, rv); }
    rv
}

/// `fsetxattr` work for slot 190. # C: O(N_xattrs)
pub fn sys_fsetxattr(args: &SyscallArgs) -> i64 {
    let ctx = match ::fs::xattr::import_set(args.a1, args.a2, args.a3 as usize, args.a4 as u32) {
        Ok(c) => c, Err(rv) => return rv,
    };
    let f = match resolve_fd(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    with_mnt_write(f.mnt_id(), || ::fs::xattr::set_on(f.inode(), ctx))
}

/// `getxattr/lgetxattr` work shared by slots 191/192. # C: O(N_path + N_xattrs)
pub fn sys_getxattr_path(args: &SyscallArgs, follow: bool) -> i64 {
    let name = match ::fs::xattr::import_name(args.a1) { Ok(n) => n, Err(rv) => return rv };
    let (inode, _) = match resolve_legacy_path(args.a0, follow) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")] log_path_error("getxattr_resolve", args.a0, rv);
        return rv;
    } };
    let rv = ::fs::xattr::get_on(&inode, &name, args.a2, args.a3 as usize);
    #[cfg(feature = "debug-mount")] if rv < 0 { log_path_error("getxattr", args.a0, rv); }
    rv
}

/// `fgetxattr` work for slot 193. # C: O(N_xattrs)
pub fn sys_fgetxattr(args: &SyscallArgs) -> i64 {
    let name = match ::fs::xattr::import_name(args.a1) { Ok(n) => n, Err(rv) => return rv };
    let f = match resolve_fd(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    ::fs::xattr::get_on(f.inode(), &name, args.a2, args.a3 as usize)
}

/// `listxattr/llistxattr` work shared by slots 194/195. # C: O(N_path + N_xattrs)
pub fn sys_listxattr_path(args: &SyscallArgs, follow: bool) -> i64 {
    let (inode, _) = match resolve_legacy_path(args.a0, follow) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")] log_path_error("listxattr_resolve", args.a0, rv);
        return rv;
    } };
    let rv = ::fs::xattr::list_on(&inode, args.a1, args.a2 as usize);
    #[cfg(feature = "debug-mount")] if rv < 0 { log_path_error("listxattr", args.a0, rv); }
    rv
}

/// `flistxattr` work for slot 196. # C: O(N_xattrs)
pub fn sys_flistxattr(args: &SyscallArgs) -> i64 {
    let f = match resolve_fd(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    ::fs::xattr::list_on(f.inode(), args.a1, args.a2 as usize)
}

/// `removexattr/lremovexattr` work shared by slots 197/198. # C: O(N_path + N_xattrs)
pub fn sys_removexattr_path(args: &SyscallArgs, follow: bool) -> i64 {
    let name = match ::fs::xattr::import_name(args.a1) { Ok(n) => n, Err(rv) => return rv };
    let (inode, mnt_id) = match resolve_legacy_path(args.a0, follow) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")] log_path_error("removexattr_resolve", args.a0, rv);
        return rv;
    } };
    let rv = with_mnt_write(mnt_id, || ::fs::xattr::remove_on(&inode, &name));
    #[cfg(feature = "debug-mount")] if rv < 0 { log_path_error("removexattr", args.a0, rv); }
    rv
}

/// `fremovexattr` work for slot 199. # C: O(N_xattrs)
pub fn sys_fremovexattr(args: &SyscallArgs) -> i64 {
    let name = match ::fs::xattr::import_name(args.a1) { Ok(n) => n, Err(rv) => return rv };
    let f = match resolve_fd(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    with_mnt_write(f.mnt_id(), || ::fs::xattr::remove_on(f.inode(), &name))
}

/// `setxattrat(dfd, path, at_flags, name, xattr_args*, usize)` — slot 463.
/// Admission order and target selection are Linux's;
/// see `fs::xattr::admit_setxattrat` and `pathresolve::resolve_at_or_dirfd`.
/// # C: O(N_path + N_xattrs)
pub fn sys_setxattrat(args: &SyscallArgs) -> i64 {
    let ctx = match ::fs::xattr::admit_setxattrat(args.a2 as u32, args.a3, args.a4, args.a5 as usize) {
        Ok(c) => c, Err(rv) => return rv,
    };
    let p = match crate::pathresolve::resolve_at_or_dirfd(args.a0 as i32, args.a1, args.a2 as u32) {
        Ok(p) => p, Err(rv) => return rv,
    };
    with_mnt_write(p.mnt_id, || ::fs::xattr::set_on(&p.inode, ctx))
}

/// `getxattrat(dfd, path, at_flags, name, xattr_args*, usize)` — slot 464.
/// `xattr_args.flags` must be zero here. # C: O(N_path + N_xattrs)
pub fn sys_getxattrat(args: &SyscallArgs) -> i64 {
    let (name, value_ptr, size) =
        match ::fs::xattr::admit_getxattrat(args.a2 as u32, args.a3, args.a4, args.a5 as usize) {
            Ok(t) => t, Err(rv) => return rv,
        };
    let p = match crate::pathresolve::resolve_at_or_dirfd(args.a0 as i32, args.a1, args.a2 as u32) {
        Ok(p) => p, Err(rv) => return rv,
    };
    ::fs::xattr::get_on(&p.inode, &name, value_ptr, size)
}

/// `listxattrat(dfd, path, at_flags, list, size)` — slot 465. Takes the buffer
/// DIRECTLY, not a `struct xattr_args`, and carries no name. A NULL/empty
/// pathname resolves through the fd table, not the cwd.
/// # C: O(N_path + N_xattrs)
pub fn sys_listxattrat(args: &SyscallArgs) -> i64 {
    if let Err(rv) = ::fs::xattr::admit_listxattrat(args.a2 as u32) { return rv; }
    let p = match crate::pathresolve::resolve_at_or_fd(args.a0 as i32, args.a1, args.a2 as u32) {
        Ok(p) => p, Err(rv) => return rv,
    };
    ::fs::xattr::list_on(&p.inode, args.a3, args.a4 as usize)
}

/// `removexattrat(dfd, path, at_flags, name)` — slot 466. # C: O(N_path + N_xattrs)
pub fn sys_removexattrat(args: &SyscallArgs) -> i64 {
    let name = match ::fs::xattr::admit_removexattrat(args.a2 as u32, args.a3) {
        Ok(n) => n, Err(rv) => return rv,
    };
    let p = match crate::pathresolve::resolve_at_or_fd(args.a0 as i32, args.a1, args.a2 as u32) {
        Ok(p) => p, Err(rv) => return rv,
    };
    with_mnt_write(p.mnt_id, || ::fs::xattr::remove_on(&p.inode, &name))
}

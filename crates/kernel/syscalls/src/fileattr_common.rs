// Shared shim glue for `file_getattr(2)` / `file_setattr(2)` (slots 468/469,
// Linux `fs/file_attr.c`). The `struct file_attr` ABI lives in
// `fs::fileattr`; the inode work is `vfs::fileattr_{get,set}`. Everything here
// is resolve + credential/mount plumbing.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::at::AT_NOFOLLOW_EMPTY;

/// Both syscalls reject unknown `at_flags` before they look at `usize`
/// (`fs/file_attr.c:387,440`). # C: O(1)
fn check_at_flags(at_flags: u32) -> Result<(), i64> {
    if at_flags & !AT_NOFOLLOW_EMPTY != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    Ok(())
}

/// `file_getattr(dfd, filename, ufattr, usize, at_flags)`: at_flags, then the
/// struct-size handshake, then resolve, then `vfs_fileattr_get` (whose
/// `ENOTTY`/`ENOIOCTLCMD` becomes `EOPNOTSUPP`), then `copy_struct_to_user`.
/// # C: O(N_path)
pub fn sys_file_getattr(dfd: i32, path_ptr: u64, ubuf: u64, usize_bytes: usize, at_flags: u32) -> i64 {
    if let Err(rv) = check_at_flags(at_flags) { return rv; }
    if let Err(rv) = ::fs::fileattr::check_struct_size(usize_bytes) { return rv; }
    let p = match crate::pathresolve::resolve_at_or_dirfd(dfd, path_ptr, at_flags) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let fa = match vfs::fileattr_get(&p.inode) {
        Ok(fa) => fa, Err(e) => return ::fs::fileattr::map_backend_err(e),
    };
    ::fs::fileattr::write_user(ubuf, usize_bytes, &fa)
}

/// `file_setattr(dfd, filename, ufattr, usize, at_flags)`: at_flags, size
/// handshake, `copy_struct_from_user` + `file_attr_to_fileattr` (both BEFORE
/// the path walk, `fs/file_attr.c:452`), resolve, `mnt_want_write`, then
/// `vfs_fileattr_set`. # C: O(N_path)
pub fn sys_file_setattr(dfd: i32, path_ptr: u64, ubuf: u64, usize_bytes: usize, at_flags: u32) -> i64 {
    if let Err(rv) = check_at_flags(at_flags) { return rv; }
    let want = match ::fs::fileattr::read_user(ubuf, usize_bytes) { Ok(w) => w, Err(rv) => return rv };
    let p = match crate::pathresolve::resolve_at_or_dirfd(dfd, path_ptr, at_flags) {
        Ok(p) => p, Err(rv) => return rv,
    };
    crate::perms_common::with_mnt_write(p.mnt_id, || apply(&p, want))
}

/// `vfs_fileattr_set` with the caller's idmap/creds. The request always
/// arrives through the `fsxattr` door (`file_attr_to_fileattr` sets
/// `fsx_valid`), so `FileAttrSource::Fsxattr` is the only source here.
/// # C: FS-dependent
fn apply(p: &vfs::VfsPath, want: vfs::FileAttr) -> i64 {
    let Some(cur) = sched::live::current() else { return -(Errno::Eperm.as_i32() as i64) };
    let idmap = vfs::mount::idmap_for(p.mnt_id);
    let init_ns = cur.namespace_id(namespace_identity::NamespaceKind::User) == Some(0);
    match vfs::fileattr_set(&idmap, &p.inode, want, vfs::FileAttrSource::Fsxattr,
                            &crate::pathresolve::current_cred(),
                            init_ns && cur.has_cap(sched::cap::LINUX_IMMUTABLE), init_ns)
    {
        Ok(()) => 0,
        Err(e) => ::fs::fileattr::map_backend_err(e),
    }
}

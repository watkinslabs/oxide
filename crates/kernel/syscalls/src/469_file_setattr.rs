// 469 file_setattr — one syscall, one file (docs/53 §0).
// file_setattr(dfd, filename, struct file_attr*, usize, at_flags): the
// path-based `FS_IOC_FSSETXATTR` (Linux `fs/file_attr.c:427`). Admission,
// resolution, `mnt_want_write` and `vfs_fileattr_set` live in `fileattr_common`.
use syscall::SyscallArgs;
/// `sys_file_setattr(dfd, filename, ufattr, usize, at_flags)` — slot 469.
/// # C: O(N_path)
pub fn sys_file_setattr(args: &SyscallArgs) -> i64 {
    crate::fileattr_common::sys_file_setattr(args.a0 as i32, args.a1, args.a2,
                                             args.a3 as usize, args.a4 as u32)
}

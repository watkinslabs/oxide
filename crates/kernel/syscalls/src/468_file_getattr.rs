// 468 file_getattr — one syscall, one file (docs/53 §0).
// file_getattr(dfd, filename, struct file_attr*, usize, at_flags): the
// path-based `FS_IOC_FSGETXATTR`. Admission,
// resolution and the extensible-struct copy-out live in `fileattr_common`.
use syscall::SyscallArgs;
/// `sys_file_getattr(dfd, filename, ufattr, usize, at_flags)` — slot 468.
/// # C: O(N_path)
pub fn sys_file_getattr(args: &SyscallArgs) -> i64 {
    crate::fileattr_common::sys_file_getattr(args.a0 as i32, args.a1, args.a2,
                                             args.a3 as usize, args.a4 as u32)
}

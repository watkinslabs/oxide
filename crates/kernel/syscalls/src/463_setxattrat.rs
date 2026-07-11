// 463 setxattrat — one syscall, one file (docs/53 §0).
// setxattrat(dfd, path, at_flags, name, xattr_args*, size): dirfd-relative
// setxattr (Linux 6.13). Resolution here; the xattr work in fs::xattr.
use syscall::SyscallArgs;
/// `sys_setxattrat(dfd, path, at_flags, name, args, size)` — slot 463.
/// # C: O(N_path + N_xattrs)
pub fn sys_setxattrat(args: &SyscallArgs) -> i64 {
    crate::xattr_common::sys_setxattrat(args)
}

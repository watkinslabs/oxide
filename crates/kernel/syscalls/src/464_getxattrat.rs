// 464 getxattrat — one syscall, one file (docs/53 §0).
use syscall::SyscallArgs;
/// `sys_getxattrat(dfd, path, at_flags, name, args, size)` — slot 464.
/// # C: O(N_path + N_xattrs)
pub fn sys_getxattrat(args: &SyscallArgs) -> i64 {
    crate::xattr_common::sys_getxattrat(args)
}

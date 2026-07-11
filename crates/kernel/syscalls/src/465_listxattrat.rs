// 465 listxattrat — one syscall, one file (docs/53 §0). No name arg.
use syscall::SyscallArgs;
/// `sys_listxattrat(dfd, path, at_flags, args, size)` — slot 465.
/// # C: O(N_path + N_xattrs)
pub fn sys_listxattrat(args: &SyscallArgs) -> i64 {
    crate::xattr_common::sys_listxattrat(args)
}

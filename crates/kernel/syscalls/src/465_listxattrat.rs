// 465 listxattrat — one syscall, one file (docs/53 §0). No name, no xattr_args:
// the list buffer + size are passed directly (Linux `SYSCALL_DEFINE5`).
use syscall::SyscallArgs;
/// `sys_listxattrat(dfd, path, at_flags, list, size)` — slot 465.
/// # C: O(N_path + N_xattrs)
pub fn sys_listxattrat(args: &SyscallArgs) -> i64 {
    crate::xattr_common::sys_listxattrat(args)
}

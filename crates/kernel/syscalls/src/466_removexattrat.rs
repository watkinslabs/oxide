// 466 removexattrat — one syscall, one file (docs/53 §0). No xattr_args.
use syscall::SyscallArgs;
/// `sys_removexattrat(dfd, path, at_flags, name)` — slot 466.
/// # C: O(N_path + N_xattrs)
pub fn sys_removexattrat(args: &SyscallArgs) -> i64 {
    crate::xattr_common::sys_removexattrat(args)
}

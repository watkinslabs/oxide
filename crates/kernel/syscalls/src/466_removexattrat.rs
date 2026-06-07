// 466 removexattrat — one syscall, one file (docs/53 §0). No xattr_args.
use syscall::SyscallArgs;
/// `sys_removexattrat(dfd, path, at_flags, name)` — slot 466.
/// # C: O(N_path + N_xattrs)
pub fn sys_removexattrat(args: &SyscallArgs) -> i64 {
    let follow = (args.a2 as u32 & 0x100) == 0;
    let inode = match crate::perms::resolve_path_inode(args.a0 as i32, args.a1, follow) {
        Ok(i) => i, Err(e) => return e,
    };
    ::fs::xattr::removexattrat_on(&inode, args.a3)
}

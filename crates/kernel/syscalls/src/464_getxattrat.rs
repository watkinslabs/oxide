// 464 getxattrat — one syscall, one file (docs/53 §0).
use syscall::SyscallArgs;
/// `sys_getxattrat(dfd, path, at_flags, name, args, size)` — slot 464.
/// # C: O(N_path + N_xattrs)
pub fn sys_getxattrat(args: &SyscallArgs) -> i64 {
    let follow = (args.a2 as u32 & crate::perms::AT_SYMLINK_NOFOLLOW) == 0;
    let inode = match crate::perms::resolve_path_inode(args.a0 as i32, args.a1, follow) {
        Ok(i) => i, Err(e) => return e,
    };
    ::fs::xattr::getxattrat_on(&inode, args.a3, args.a4, args.a5 as usize)
}

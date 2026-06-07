// 463 setxattrat — one syscall, one file (docs/53 §0).
// setxattrat(dfd, path, at_flags, name, xattr_args*, size): dirfd-relative
// setxattr (Linux 6.13). Resolution here; the xattr work in fs::xattr.
use syscall::SyscallArgs;
/// `sys_setxattrat(dfd, path, at_flags, name, args, size)` — slot 463.
/// # C: O(N_path + N_xattrs)
pub fn sys_setxattrat(args: &SyscallArgs) -> i64 {
    let follow = (args.a2 as u32 & 0x100) == 0; // !AT_SYMLINK_NOFOLLOW
    let inode = match crate::perms::resolve_path_inode(args.a0 as i32, args.a1, follow) {
        Ok(i) => i, Err(e) => return e,
    };
    ::fs::xattr::setxattrat_on(&inode, args.a3, args.a4, args.a5 as usize)
}

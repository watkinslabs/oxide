// 465 listxattrat — one syscall, one file (docs/53 §0). No name arg.
use syscall::SyscallArgs;
/// `sys_listxattrat(dfd, path, at_flags, args, size)` — slot 465.
/// # C: O(N_path + N_xattrs)
pub fn sys_listxattrat(args: &SyscallArgs) -> i64 {
    let follow = (args.a2 as u32 & 0x100) == 0;
    let inode = match crate::perms::resolve_path_inode(args.a0 as i32, args.a1, follow) {
        Ok(i) => i, Err(e) => return e,
    };
    ::fs::xattr::listxattrat_on(&inode, args.a3, args.a4 as usize)
}

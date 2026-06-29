// 464 getxattrat — one syscall, one file (docs/53 §0).
use syscall::SyscallArgs;
/// `sys_getxattrat(dfd, path, at_flags, name, args, size)` — slot 464.
/// # C: O(N_path + N_xattrs)
pub fn sys_getxattrat(args: &SyscallArgs) -> i64 {
    let inode = match crate::perms_common::resolve_xattr_at(args.a0 as i32, args.a1, args.a2 as u32) {
        Ok(i) => i, Err(e) => return e,
    };
    ::fs::xattr::getxattrat_on(&inode, args.a3, args.a4, args.a5 as usize)
}

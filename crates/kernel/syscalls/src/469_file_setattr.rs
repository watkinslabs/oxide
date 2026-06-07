// 469 file_setattr — one syscall, one file (docs/53 §0).
// file_setattr(dfd, path, struct file_attr*, size, at_flags): set fsxattr /
// inode flags. This kernel tracks no FS_XFLAG_* flags / project ids / extent
// sizes, so an all-clear request is a no-op (0) and any attempt to SET an
// unsupported attribute is rejected EOPNOTSUPP — the honest answer, never a
// silent success that drops the request.
use syscall::{errno::Errno, SyscallArgs};
const FILE_ATTR_SIZE: usize = 24;
/// `sys_file_setattr(dfd, path, ufattr, size, at_flags)` — slot 469.
/// # C: O(N_path)
pub fn sys_file_setattr(args: &SyscallArgs) -> i64 {
    let follow = (args.a4 as u32 & crate::perms::AT_SYMLINK_NOFOLLOW) == 0;
    if let Err(e) = crate::perms::resolve_path_inode(args.a0 as i32, args.a1, follow) { return e; }
    let ubuf = args.a2;
    let usz  = args.a3 as usize;
    if usz < FILE_ATTR_SIZE { return -(Errno::Einval.as_i32() as i64); }
    if ubuf == 0 || ubuf.saturating_add(FILE_ATTR_SIZE as u64) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ubuf range-checked < USER_VA_END; read the 24-byte struct from user AS.
    let (xflags, extsize, projid, cowextsize) = unsafe {
        (core::ptr::read_unaligned(ubuf as *const u64),
         core::ptr::read_unaligned((ubuf + 8)  as *const u32),
         core::ptr::read_unaligned((ubuf + 16) as *const u32),
         core::ptr::read_unaligned((ubuf + 20) as *const u32))
    };
    if xflags != 0 || extsize != 0 || projid != 0 || cowextsize != 0 {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    0
}

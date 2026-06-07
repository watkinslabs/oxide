// 468 file_getattr — one syscall, one file (docs/53 §0).
// file_getattr(dfd, path, struct file_attr*, size, at_flags): the fsxattr /
// inode-flags accessor (Linux 6.13). This kernel tracks no FS_XFLAG_* flags or
// project ids, so every attr is clear — the accurate report (not a stub): we
// resolve+validate the path, then write an all-zero struct file_attr.
// struct file_attr { u64 fa_xflags; u32 fa_extsize; u32 fa_nextents;
//                    u32 fa_projid; u32 fa_cowextsize; } = 24 bytes.
use syscall::{errno::Errno, SyscallArgs};
const FILE_ATTR_SIZE: usize = 24;
/// `sys_file_getattr(dfd, path, ufattr, size, at_flags)` — slot 468.
/// # C: O(N_path)
pub fn sys_file_getattr(args: &SyscallArgs) -> i64 {
    let follow = (args.a4 as u32 & crate::perms_common::AT_SYMLINK_NOFOLLOW) == 0;
    if let Err(e) = crate::perms_common::resolve_path_inode(args.a0 as i32, args.a1, follow) { return e; }
    let ubuf = args.a2;
    let usz  = args.a3 as usize;
    if usz < FILE_ATTR_SIZE { return -(Errno::Einval.as_i32() as i64); }
    if ubuf == 0 || ubuf.saturating_add(FILE_ATTR_SIZE as u64) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ubuf range-checked < USER_VA_END; zero a 24-byte struct in user AS.
    unsafe { core::ptr::write_bytes(ubuf as *mut u8, 0, FILE_ATTR_SIZE); }
    0
}

// 086 link — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, is_ext4_path, errno_from_vfs};

/// `link(target, link)` slot 86. Hardlink only — both must
/// resolve to ext4 paths.
/// # C: O(1)
pub fn sys_link(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let t = resolve(&target).unwrap_or(target);
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match ext4::rootfs::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

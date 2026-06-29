// 086 link — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, errno_from_vfs};

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
    let t = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &target) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let l = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &link) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    let (tm, _) = match vfs::mount::resolve_mount(&t) {
        Some(v) => v, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let (lm, _) = match vfs::mount::resolve_mount(&l) {
        Some(v) => v, None => return -(Errno::Enoent.as_i32() as i64),
    };
    if (lm.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if tm.mnt_id != lm.mnt_id {
        return -(Errno::Exdev.as_i32() as i64);
    }
    match tm.fs().link(&t, &l) {
        Ok(())  => { crate::pathresolve::d_drop_path(&l); 0 }
        Err(e)  => errno_from_vfs(e),
    }
}

// 082 rename — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared rename_impl + mount_for_write cores (also used by
// 264_renameat + 316_renameat2).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs};

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)`
/// slot 264 / `renameat2` slot 316. We collapse all three into
/// link-then-unlink against the ext4 mount.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(-100, args.a0, -100, args.a1)
}

/// Route a path-write operation through the mount table per
/// `docs/16`. Replaces the `is_ext4_path` gate + `ext4::rootfs::*`
/// hardcoded chain. Returns the resolved (mount, relative_path) or
/// EROFS-like errno if no mount matches.
/// # C: O(N path components)
fn mount_for_write(path: &str) -> Result<(alloc::sync::Arc<vfs::mount::Mount>, alloc::string::String), i64> {
    vfs::mount::resolve_mount(path).ok_or(-(Errno::Enoent.as_i32() as i64))
}

/// # C: O(1)
pub(crate) fn rename_impl(from_dirfd: i32, from_ptr: u64, to_dirfd: i32, to_ptr: u64) -> i64 {
    let from_raw = match read_path(from_ptr) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let to_raw = match read_path(to_ptr) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve each side against its dirfd (renameat).
    let f = match crate::pathresolve::resolve_at(from_dirfd, &from_raw) {
        Some(rp) => rp, None => resolve(&from_raw).unwrap_or(from_raw),
    };
    let t = match crate::pathresolve::resolve_at(to_dirfd, &to_raw) {
        Some(rp) => rp, None => resolve(&to_raw).unwrap_or(to_raw),
    };
    // Landlock: from-side needs REMOVE_FILE | REMOVE_DIR | REFER;
    // to-side needs MAKE_REG. Approximate as REMOVE_FILE+MAKE_REG.
    let la = ::security::landlock::access::REMOVE_FILE
           | ::security::landlock::access::MAKE_REG
           | ::security::landlock::access::REFER;
    if let Err(rv) = crate::landlock::check(&f, la) { return rv; }
    if let Err(rv) = crate::landlock::check(&t, la) { return rv; }
    // rename must be within a single mount (Linux EXDEV otherwise).
    let (mnt_f, rel_f) = match mount_for_write(&f) { Ok(x) => x, Err(rv) => return rv };
    let (mnt_t, rel_t) = match mount_for_write(&t) { Ok(x) => x, Err(rv) => return rv };
    if !alloc::sync::Arc::ptr_eq(&mnt_f, &mnt_t) {
        return -(Errno::Exdev.as_i32() as i64);
    }
    match mnt_f.fs.rename(&rel_f, &rel_t) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

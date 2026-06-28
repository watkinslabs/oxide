// 082 rename — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared rename_impl + mount_for_write cores (also used by
// 264_renameat + 316_renameat2).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_user_path, errno_from_vfs, path_exists};

/// renameat2 flags (uapi/linux/fs.h).
pub(crate) const RENAME_NOREPLACE: u32 = 1 << 0;
pub(crate) const RENAME_EXCHANGE:  u32 = 1 << 1;
pub(crate) const RENAME_WHITEOUT:  u32 = 1 << 2;

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)`
/// slot 264 / `renameat2` slot 316. We collapse all three into
/// link-then-unlink against the ext4 mount.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(-100, args.a0, -100, args.a1, 0)
}

/// Route a path-write operation through the mount table per `docs/16`.
/// Returns the resolved (mount, relative_path), or the Linux errno for a
/// missing/read-only mount.
/// # C: O(N path components)
fn mount_for_write(path: &str) -> Result<(alloc::sync::Arc<vfs::mount::Mount>, alloc::string::String), i64> {
    let (mnt, rel) = vfs::mount::resolve_mount(path).ok_or(-(Errno::Enoent.as_i32() as i64))?;
    if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
        return Err(-(Errno::Erofs.as_i32() as i64));
    }
    Ok((mnt, rel))
}

/// # C: O(1)
pub(crate) fn rename_impl(from_dirfd: i32, from_ptr: u64, to_dirfd: i32, to_ptr: u64, flags: u32) -> i64 {
    // renameat2 flag validation (Linux do_renameat2):
    //   * unknown bits → EINVAL
    //   * NOREPLACE | EXCHANGE together → EINVAL
    //   * WHITEOUT requires not-EXCHANGE
    const VALID: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
    if flags & !VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    if (flags & RENAME_NOREPLACE != 0) && (flags & RENAME_EXCHANGE != 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if (flags & RENAME_WHITEOUT != 0) && (flags & RENAME_EXCHANGE != 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let from_raw = match read_user_path(from_ptr) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let to_raw = match read_user_path(to_ptr) {
        Ok(s) => s, Err(rv) => return rv,
    };
    // BUG D follow-up: resolve each side against its dirfd (renameat).
    let f = match crate::pathresolve::resolve_at_result(from_dirfd, &from_raw) {
        Ok(rp) => rp, Err(rv) => return rv,
    };
    let t = match crate::pathresolve::resolve_at_result(to_dirfd, &to_raw) {
        Ok(rp) => rp, Err(rv) => return rv,
    };
    // RENAME_NOREPLACE: fail with EEXIST if the target already exists
    // (mv -n, dpkg atomic installs). Pre-check before the backend rename,
    // which would otherwise silently overwrite → data loss.
    if (flags & RENAME_NOREPLACE != 0) && path_exists(&t) {
        return -(Errno::Eexist.as_i32() as i64);
    }
    // RENAME_EXCHANGE: both names must already exist (Linux ENOENT else).
    // Pre-check here so the missing-side errno is reported against the
    // dirfd-resolved path, not the backend's relative one.
    if (flags & RENAME_EXCHANGE != 0) && (!path_exists(&f) || !path_exists(&t)) {
        return -(Errno::Enoent.as_i32() as i64);
    }
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
    // EXCHANGE atomically swaps; WHITEOUT renames then leaves a whiteout
    // char-dev (0,0) at the source; plain rename is link-then-replace.
    let r = if flags & RENAME_EXCHANGE != 0 {
        mnt_f.fs().exchange(&rel_f, &rel_t)
    } else if flags & RENAME_WHITEOUT != 0 {
        mnt_f.fs().whiteout(&rel_f, &rel_t)
    } else {
        mnt_f.fs().rename(&rel_f, &rel_t)
    };
    match r {
        Ok(())  => {
            if flags & RENAME_EXCHANGE != 0 {
                // EXCHANGE swaps two inodes under two surviving names — neither
                // d_moves; both cached dentries now point at the wrong inode, so
                // drop both and let the next walk re-resolve.
                crate::pathresolve::d_delete_path(&f);
                crate::pathresolve::d_delete_path(&t);
            } else {
                // D9: plain/whiteout rename → `d_move` the source dentry onto the
                // destination (parent,name) (Linux `d_move`), instead of
                // discarding it via two `d_delete`s. d_move_path also drops any
                // stale dentry already at the dest. WHITEOUT's leftover source
                // node re-resolves on the next walk (d_move d_drops the source).
                crate::pathresolve::d_move_path(&f, &t);
            }
            0
        }
        Err(e)  => errno_from_vfs(e),
    }
}

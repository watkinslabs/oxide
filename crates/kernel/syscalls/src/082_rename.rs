// 082 rename — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared rename_impl + mount_for_write cores (also used by
// 264_renameat + 316_renameat2).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    child_dentry, child_inode, drop_child_cache, errno_from_vfs, parent_mount_readonly,
    read_user_path, render_child_path, resolve_rename_parent_at,
};

/// renameat2 flags (uapi/linux/fs.h).
pub(crate) const RENAME_NOREPLACE: u32 = 1 << 0;
pub(crate) const RENAME_EXCHANGE:  u32 = 1 << 1;
pub(crate) const RENAME_WHITEOUT:  u32 = 1 << 2;

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)` slot 264 /
/// `renameat2` slot 316. Rename variants route through resolved parent inodes;
/// strings are display/LSM inputs only, never object identity.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(-100, args.a0, -100, args.a1, 0)
}

fn same_mount(a: &vfs::VfsPath, b: &vfs::VfsPath) -> bool { a.mnt_id == b.mnt_id }

fn same_parent(a: &vfs::VfsPath, b: &vfs::VfsPath) -> bool {
    alloc::sync::Arc::ptr_eq(&a.dentry, &b.dentry)
}

#[cfg(feature = "debug-udevdb")]
fn trace_rename_udevdb(from: &str, to: &str, rv: i64) {
    crate::namei_common::trace_udevdb_path(b"rename-from", from, rv);
    crate::namei_common::trace_udevdb_path(b"rename-to", to, rv);
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
    // D26: Linux do_renameat2 rejects a `.`/`..`/root final component on either
    // side with EBUSY (only LAST_NORM is renameable) — checked on the raw path
    // before resolution normalises the dots away.
    if crate::namei_common::rename_component_busy(&from_raw)
        || crate::namei_common::rename_component_busy(&to_raw) {
        let rv = -(Errno::Ebusy.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&from_raw, &to_raw, rv);
        return rv;
    }
    let (old_parent, old_name) = match resolve_rename_parent_at(from_dirfd, &from_raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    };
    let (new_parent, new_name) = match resolve_rename_parent_at(to_dirfd, &to_raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    };
    if !same_mount(&old_parent, &new_parent) {
        let rv = -(Errno::Exdev.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&from_raw, &to_raw, rv);
        return rv;
    }
    if parent_mount_readonly(&old_parent) || parent_mount_readonly(&new_parent) {
        let rv = -(Errno::Erofs.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&from_raw, &to_raw, rv);
        return rv;
    }
    let old_victim = match child_inode(&old_parent, &old_name) {
        Ok(Some(i)) => i,
        Ok(None) => {
            let rv = -(Errno::Enoent.as_i32() as i64);
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
        Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    };
    let new_target = match child_inode(&new_parent, &new_name) {
        Ok(i) => i,
        Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    };
    if flags == 0 && same_parent(&old_parent, &new_parent) && old_name == new_name {
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&from_raw, &to_raw, 0);
        return 0;
    }
    if let Some(src_d) = child_dentry(&old_parent, &old_name) {
        if matches!(old_victim.file_type(), vfs::FileType::Directory)
            && new_parent.dentry.is_subdir_of(&src_d) {
            let rv = -(Errno::Einval.as_i32() as i64);
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    }
    // Landlock: from-side needs REMOVE_FILE | REMOVE_DIR | REFER;
    // to-side needs MAKE_REG. Approximate as REMOVE_FILE+MAKE_REG.
    let la = ::security::landlock::access::REMOVE_FILE
           | ::security::landlock::access::MAKE_REG
           | ::security::landlock::access::REFER;
    let _f_disp = render_child_path(&old_parent, &old_name);
    let _t_disp = render_child_path(&new_parent, &new_name);
    let old_check = vfs::VfsPath {
        mnt_id: old_parent.mnt_id,
        dentry: vfs::file::open_dentry_at(&old_parent.dentry, &old_name, &old_victim),
        inode: old_victim.clone(),
        last_component: None,
    };
    if let Err(rv) = crate::landlock::check(&old_check, la) {
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&_f_disp, &_t_disp, rv);
        return rv;
    }
    let new_check = match new_target.as_ref() {
        Some(i) => vfs::VfsPath {
            mnt_id: new_parent.mnt_id,
            dentry: vfs::file::open_dentry_at(&new_parent.dentry, &new_name, i),
            inode: i.clone(),
            last_component: None,
        },
        None => new_parent.clone(),
    };
    if let Err(rv) = crate::landlock::check(&new_check, la) {
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&_f_disp, &_t_disp, rv);
        return rv;
    }
    if let Err(e) = vfs::namei::may_rename(&old_parent.inode, &old_victim, &new_parent.inode,
        new_target.as_ref(), flags, same_parent(&old_parent, &new_parent),
        &crate::pathresolve::current_cred()) {
        let rv = errno_from_vfs(e);
        #[cfg(feature = "debug-udevdb")]
        trace_rename_udevdb(&_f_disp, &_t_disp, rv);
        return rv;
    }
    // D29: hold BOTH parent dirs' `i_rwsem` via `lock_rename` (Linux
    // `vfs_rename` → `lock_rename`) across the backend rename. `lock_rename`
    // orders the two rank-40 `i_rwsem`s by address (deadlock-safe vs. a reverse
    // concurrent rename) and locks a same-dir rename's single inode ONCE. The
    // backend resolves names via `i_op.lookup` (no nested `i_rwsem`), so holding
    // the exclusive side here is deadlock-free. The guard drops at the end of
    // this block — before the rank-50/60 dcache update below.
    let source_dentry = child_dentry(&old_parent, &old_name);
    let dest_victim = if new_target.is_some() { child_dentry(&new_parent, &new_name) } else { None };
    let r = {
        let _rg = vfs::lock_rename(&old_parent.inode, &new_parent.inode);
        old_parent.inode.rename_child(&old_name, &new_parent.inode, &new_name, flags, &vfs::CreateCtx::root())
    };
    let rv = match r {
        Ok(())  => {
            if flags & RENAME_EXCHANGE != 0 {
                drop_child_cache(&old_parent, &old_name);
                drop_child_cache(&new_parent, &new_name);
            } else if let Some(d) = source_dentry {
                if let Some(v) = dest_victim { vfs::dcache::d_unlink(&v); }
                vfs::dcache::d_move(&d, &new_parent.dentry, &new_name);
            } else {
                drop_child_cache(&old_parent, &old_name);
                drop_child_cache(&new_parent, &new_name);
            }
            ::fs::inotify::fire_move(&old_parent.inode, &new_parent.inode, Some(&old_victim));
            0
        }
        Err(e)  => errno_from_vfs(e),
    };
    #[cfg(feature = "debug-udevdb")]
    trace_rename_udevdb(&_f_disp, &_t_disp, rv);
    rv
}

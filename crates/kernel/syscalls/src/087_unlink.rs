// 087 unlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    child_dentry, drop_child_cache, errno_from_vfs, parent_mount_readonly, read_user_path,
    render_child_path, resolve_unlink_parent_at, unlink_unix_socket_addr,
};

/// `unlink(path)` slot 87.
/// # C: O(N parent entries)
pub fn sys_unlink(args: &SyscallArgs) -> i64 {
    // X4: EFAULT(bad ptr) / ENOENT(empty) / ENAMETOOLONG, not EINVAL.
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    unlink_at(crate::pathresolve::AT_FDCWD, &raw)
}

pub(crate) fn unlink_at(dirfd: i32, raw: &str) -> i64 {
    let (parent, name) = match resolve_unlink_parent_at(dirfd, raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"unlink", raw, rv);
            return rv;
        }
    };
    let p = render_child_path(&parent, &name);
    // D30: grab the victim dentry before the backend drops the name (it would no
    // longer resolve afterwards) so Landlock and `d_unlink` both use the exact
    // object under the already-resolved parent.
    let victim = child_dentry(&parent, &name);
    // The removal right is a property of the containing directory: a rule
    // granting it on the victim itself must not authorise unlinking the victim.
    if let Err(rv) = crate::landlock::check_parent(&parent,
        ::landlock::uapi::ACCESS_FS_REMOVE_FILE) {
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
        return rv;
    }
    if parent_mount_readonly(&parent) {
        let rv = -(Errno::Erofs.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
        return rv;
    }
    if let Some(d) = victim.as_ref() {
        if let Some(inode) = d.inode() {
            if let Err(e) = crate::path_ops_policy::check_unlink_trailing_slash(
                vfs::path::requires_dir(raw),
                matches!(inode.file_type(), vfs::FileType::Directory)) {
                let rv = -(e.as_i32() as i64);
                #[cfg(feature = "debug-udevdb")]
                crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
                return rv;
            }
            let cred = crate::pathresolve::current_cred();
            if let Err(e) = vfs::namei::may_delete_dentry(&parent.inode, d, false, &cred) {
                let rv = errno_from_vfs(e);
                #[cfg(feature = "debug-udevdb")]
                crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
                return rv;
            }
            // `vfs_unlink`'s `is_local_mountpoint` gate: a file that something
            // is mounted over (a bind-mounted file) keeps its name.
            if d.is_mounted() {
                let rv = -(Errno::Ebusy.as_i32() as i64);
                #[cfg(feature = "debug-udevdb")]
                crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
                return rv;
            }
        }
    }
    // Recall the delegations this removal invalidates, in the order the objects
    // are affected: the parent directory loses a name, then the victim itself
    // loses a link. After every permission gate above, before the backend drops
    // the name.
    if let Some(rv) = crate::deleg_break::break_deleg_for_mutation(&parent.inode) { return rv; }
    if let Some(i) = victim.as_ref().and_then(|d| d.inode()) {
        if let Some(rv) = crate::deleg_break::break_deleg_for_mutation(&i) { return rv; }
    }
    let unix_addr = victim.as_ref()
        .and_then(|d| d.inode())
        .and_then(|i| if i.file_type() == vfs::FileType::Socket {
            Some(net::UnixAddr::from_inode(p.clone(), &i))
        } else {
            None
        });
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend unlink (Linux
    // `do_unlinkat` locks the parent); dropped before the dcache delete below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.unlink_child(&name) };
    let rv = match r {
        // D30: backend `i_op->unlink` ran first; now `d_unlink` reflects it —
        // `drop_link`s the inode (mirrors the backend's link drop in the in-memory
        // inode), tears this name's dentry down, and on the LAST name prunes the
        // sibling aliases so the inode retires via the normal iput/evict window
        // (Linux `vfs_unlink` tail). No cached victim → path-based d_delete clears
        // any stale positive so stat/open after unlink still misses.
        Ok(())  => {
            if let Some(a) = unix_addr.as_ref() { unlink_unix_socket_addr(a); }
            match victim {
                Some(d) => {
                    // IN_DELETE_SELF is fired by `d_unlink` itself, gated on the
                    // link count reaching 0 — Linux `dentry_unlink_inode`. Doing
                    // it here reported a still-hardlinked file as deleted.
                    vfs::dcache::d_unlink(&d);
                }
                None    => drop_child_cache(&parent, &name),
            }
            vfs::fire_dirent_delete(&parent.inode, &name, false);
            0
        }
        Err(e)  => errno_from_vfs(e),
    };
    #[cfg(feature = "debug-udevdb")]
    crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
    rv
}

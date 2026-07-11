// 087 unlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
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
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_FILE) {
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
        return rv;
    }
    if parent_mount_readonly(&parent) {
        let rv = -(syscall::errno::Errno::Erofs.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
        return rv;
    }
    // D30: grab the victim dentry before the backend drops the name (it would no
    // longer resolve afterwards) so `d_unlink` can drive the nlink↔alias coupling.
    let victim = child_dentry(&parent, &name);
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
                    // FAN_DELETE_SELF / IN_DELETE_SELF on the victim before its
                    // alias is torn down (Linux fsnotify_unlink → fsnotify_inoderemove).
                    if let Some(ino) = d.inode() { ::fs::inotify::fire_delete_self(&ino); }
                    vfs::dcache::d_unlink(&d);
                }
                None    => drop_child_cache(&parent, &name),
            }
            vfs::fire_dirent_delete(&parent.inode, &name);
            0
        }
        Err(e)  => errno_from_vfs(e),
    };
    #[cfg(feature = "debug-udevdb")]
    crate::namei_common::trace_udevdb_path(b"unlink", &p, rv);
    rv
}

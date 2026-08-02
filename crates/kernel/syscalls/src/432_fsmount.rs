// 432 fsmount — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_fsmount(fs_fd, flags, attr_flags)` — slot 432. Materialises a
/// detached mount object from the `fs_context`; returns a new fd for it.
/// `FSMOUNT_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsmount(args: &SyscallArgs) -> i64 {
    const FSMOUNT_CLOEXEC: u64 = 1;
    // MOUNT_ATTR_* (uapi `linux/mount.h`) settable via fsmount. IDMAP is NOT
    // accepted here (Linux do_fsmount rejects it — only mount_setattr sets idmap).
    const MOUNT_ATTR_RDONLY:     u64 = 0x00_0001;
    const MOUNT_ATTR_NOSUID:     u64 = 0x00_0002;
    const MOUNT_ATTR_NODEV:      u64 = 0x00_0004;
    const MOUNT_ATTR_NOEXEC:     u64 = 0x00_0008;
    const MOUNT_ATTR__ATIME:     u64 = 0x00_0070; // mask: RELATIME(0)/NOATIME(0x10)/STRICTATIME(0x20)
    const MOUNT_ATTR_NOATIME:    u64 = 0x00_0010;
    const MOUNT_ATTR_STRICTATIME:u64 = 0x00_0020;
    const MOUNT_ATTR_NODIRATIME: u64 = 0x00_0080;
    const MOUNT_ATTR_NOSYMFOLLOW:u64 = 0x20_0000;
    const ATTR_VALID: u64 = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
        | MOUNT_ATTR_NOEXEC | MOUNT_ATTR__ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW;
    // Linux order: the FLAG WORDS are validated before any privilege test, so a
    // malformed call reports EINVAL regardless of who made it and an
    // unprivileged caller cannot use the errno to probe its own privilege.
    // `flags` outside FSMOUNT_CLOEXEC → EINVAL; `attr_flags` outside the settable
    // MOUNT_ATTR_* set → EINVAL; the atime sub-field must name exactly one mode.
    if args.a1 & !FSMOUNT_CLOEXEC != 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Some(rv) = may_mount_or_eperm() { return rv; }  // Linux may_mount (D49)
    if args.a2 & !ATTR_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    match args.a2 & MOUNT_ATTR__ATIME {
        0 | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME => {}
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    let fd = args.a0 as i32;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let attrs = args.a2;
    // CONVERTED pseudo fstype: the SB was realized at fsconfig(CMD_CREATE). The
    // context MUST be AwaitingMount with a pinned root (Linux do_fsmount rejects
    // a fsmount before get_tree); carry the realized (sb, root) for
    // move_mount → attach_sb.
    {
        let mut g = ctx.fc.lock();
        if let Some(fc) = g.as_mut() {
            // Linux `do_fsmount` ladder, in order: no realized root → EINVAL;
            // too-revealing → EPERM; wrong phase → EBUSY. The phase rung is LAST
            // and it is EBUSY, not EINVAL — "the context exists but is not
            // holding a mountable tree right now" is a retry condition, and it
            // is what a SECOND fsmount on one context fd reports once the first
            // has cleaned it back to the fspick state.
            let (sb, root) = match (fc.sb(), fc.root()) {
                (Some(sb), Some(root)) => (sb.clone(), root.clone()),
                _ => return -(Errno::Einval.as_i32() as i64),
            };
            // Linux `do_fsmount`: `if (mount_too_revealing(fc->root->d_sb,
            // &mnt_flags)) return -EPERM;` — the same userns visibility gate
            // `mount(2)` gets, at the same syscall. `mnt_flags` is the MOUNT_ATTR_*
            // request mapped into the MNT_* option space, exactly what the graft
            // will install. The locked attributes it feeds back, plus the
            // `create_new_namespace` `lock_mnt_tree` stamp, travel on the mount
            // object because this tree materialises the mount at `move_mount(2)`.
            let mnt_flags = vfs::mount::mount_attr_to_mnt(attrs);
            let mut lock_flags = match vfs::mount::mount_too_revealing(&sb, mnt_flags) {
                Ok(l) => l,
                Err(_) => return -(Errno::Eperm.as_i32() as i64),
            };
            if fc.phase() != vfs::fs::FsContextPhase::AwaitingMount {
                return -(Errno::Ebusy.as_i32() as i64);
            }
            if crate::mount_perm::current_user_ns_differs_from_mount_ns_owner() {
                lock_flags |= vfs::mount::lock_new_mount_bits(mnt_flags);
            }
            // Linux `do_fsmount`: `vfs_create_mount(fc)` then `alloc_mnt_ns(..,
            // anon=true)` + `mnt_add_to_ns` — the mount is REAL from here, with
            // its own id and its own root, and simply belongs to no task's
            // namespace until `move_mount(2)`. What this replaces carried
            // `(sb, root)` on the fd and minted a mount only at move time, so
            // between the two calls there was no mount to have an id, to report
            // through `statmount`, or to dissolve if the fd was just closed.
            let anon = match vfs::mount::create_anon_mount(sb, mnt_flags, lock_flags, None) {
                Ok(m) => m,
                Err(e) => return crate::namei_common::errno_from_vfs(e),
            };
            let Some(mnt_root) = anon.mnt_root() else {
                vfs::mount::dissolve_anon(&anon);
                return -(Errno::Einval.as_i32() as i64);
            };
            let Some(root_inode) = mnt_root.inode() else {
                vfs::mount::dissolve_anon(&anon);
                return -(Errno::Einval.as_i32() as i64);
            };
            // `vfs_clean_context(fc)`: the mount is made, so the context returns
            // to the state an `fspick(2)` leaves behind. Without this a caller
            // could fsmount(2) one context fd repeatedly and mint N mount
            // objects from a single superblock.
            vfs::fs::vfs_clean_context(fc);
            // `dentry_open(&new_path, O_PATH, fc->cred)` + `FMODE_NEED_UNMOUNT`:
            // a real path fd over (mount, root dentry), so it carries the mount
            // id, resolves as a dirfd, and dissolves its mount if closed
            // unmoved.
            let path = vfs::VfsPath {
                mnt_id: anon.mnt_id, dentry: mnt_root, inode: root_inode, last_component: None,
            };
            return install_mount_path_fd(path, anon.mnt_id,
                (args.a1 & FSMOUNT_CLOEXEC) != 0);
        }
    }
    -(Errno::Einval.as_i32() as i64)
}

// 133 mknod — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared mknod_impl core (also used by 259_mknodat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_user_path, errno_from_vfs, resolve_create_parent_at, render_child_path,
    child_exists, parent_mount_readonly, drop_child_cache,
};

/// `mknod(path, mode, dev)` slot 133.
/// # C: O(N parent entries)
pub fn sys_mknod(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    mknod_impl(crate::pathresolve::AT_FDCWD, raw, args.a1 as u16, args.a2 as u32)
}

/// # C: O(N parent entries)
pub(crate) fn mknod_impl(dirfd: i32, raw: String, mode: u16, dev: u32) -> i64 {
    const S_IFMT:  u16 = 0xF000;
    const S_IFREG: u16 = 0x8000;
    const S_IFCHR: u16 = 0x2000;
    const S_IFDIR: u16 = 0x4000;
    const S_IFBLK: u16 = 0x6000;
    const S_IFIFO: u16 = 0x1000;
    const S_IFSOCK: u16 = 0xC000;
    let ftype = mode & S_IFMT;
    // POSIX: mknod with no type bits ⇒ regular file (≡ create).
    let real_ftype = if ftype == 0 { S_IFREG } else { ftype };
    let la = match real_ftype {
        S_IFREG  => ::security::landlock::access::MAKE_REG,
        S_IFCHR  => ::security::landlock::access::MAKE_CHAR,
        S_IFBLK  => ::security::landlock::access::MAKE_BLOCK,
        S_IFIFO  => ::security::landlock::access::MAKE_FIFO,
        S_IFSOCK => ::security::landlock::access::MAKE_SOCK,
        S_IFDIR  => return -(Errno::Eperm.as_i32() as i64),
        _        => return -(Errno::Einval.as_i32() as i64),
    };
    let (parent, name) = match resolve_create_parent_at(dirfd, &raw) {
        Ok(x) => x, Err(rv) => return rv,
    };
    let p = render_child_path(&parent, &name);
    match child_exists(&parent, &name) {
        Ok(true) => return -(Errno::Eexist.as_i32() as i64),
        Ok(false) => {}
        Err(rv) => return rv,
    }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if let Err(rv) = crate::landlock::check_parent(&parent, la) { return rv; }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        return errno_from_vfs(e);
    }
    // Linux may_mknod / vfs_mknod: device nodes require CAP_MKNOD; FIFO,
    // socket and regular files do not (D24).
    if matches!(real_ftype, S_IFCHR | S_IFBLK) {
        let has = sched::live::current()
            .map(|c| c.has_cap(sched::cap::MKNOD)).unwrap_or(false);
        if !has { return -(Errno::Eperm.as_i32() as i64); }
    }
    let umask = sched::live::current()
        .map(|c| c.umask()).unwrap_or(0) as u16;
    // Thread the mount idmap + caller cred + umask so the new node gets the
    // right owner (Linux `->mknod`/`->create(struct mnt_idmap *, ...)`).
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create/mknod (Linux
    // `filename_create` → `->create`/`->mknod`); dropped before the dcache update.
    let node_dev = if matches!(real_ftype, S_IFIFO | S_IFSOCK) { 0 } else { dev };
    let r = {
        let _g = parent.inode.inode_lock();
        if real_ftype == S_IFREG {
            // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
            parent.inode.create_child(&name, (mode & 0x0FFF) as u32, &ctx).map(|_| ())
        } else {
            parent.inode.mknod_child(&name, (real_ftype | (mode & 0x0FFF)) as u16, node_dev, &ctx)
        }
    };
    match r {
        Ok(())  => {
            drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name);
            0
        }
        Err(e)  => {
            crate::namei_common::trace_run_vfs_error(b"mknod", &p, e);
            errno_from_vfs(e)
        }
    }
}

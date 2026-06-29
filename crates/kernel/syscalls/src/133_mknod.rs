// 133 mknod — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared mknod_impl core (also used by 259_mknodat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_user_path, errno_from_vfs, resolve_parent};

/// `mknod(path, mode, dev)` slot 133.
/// # C: O(N parent entries)
pub fn sys_mknod(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    mknod_impl(raw, args.a1 as u16, args.a2 as u32)
}

/// # C: O(N parent entries)
pub(crate) fn mknod_impl(raw: String, mode: u16, dev: u32) -> i64 {
    let p = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &raw) {
        Ok(p) => p, Err(rv) => return rv,
    };
    // Map mode's type bits to the Landlock access needed.
    const S_IFMT:  u16 = 0xF000;
    const S_IFREG: u16 = 0x8000;
    const S_IFCHR: u16 = 0x2000;
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
        _        => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = crate::landlock::check(&p, la) { return rv; }
    // Linux may_mknod / vfs_mknod: device nodes require CAP_MKNOD; FIFO,
    // socket and regular files do not (D24).
    if matches!(real_ftype, S_IFCHR | S_IFBLK) {
        let has = sched::live::current()
            .map(|c| c.has_cap(sched::cap::MKNOD)).unwrap_or(false);
        if !has { return -(Errno::Eperm.as_i32() as i64); }
    }
    if vfs::mount::is_readonly_path(&p) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    // Linux do_mknodat: `mode &= ~current_umask()` on the permission bits (D23).
    let umask = sched::live::current()
        .map(|c| c.umask.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0) as u16;
    let perm = (mode & 0x0FFF) & !umask;
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    // Thread the mount idmap + caller cred + umask so the new node gets the
    // right owner (Linux `->mknod`/`->create(struct mnt_idmap *, ...)`).
    let cred = crate::pathresolve::current_cred();
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create/mknod (Linux
    // `filename_create` → `->create`/`->mknod`); dropped before the dcache update.
    let r = {
        let _g = pino.inode_lock();
        if real_ftype == S_IFREG {
            // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
            pino.create_child(&name, perm as u32, &ctx).map(|_| ())
        } else {
            pino.mknod_child(&name, (real_ftype | perm) as u16, dev, &ctx)
        }
    };
    match r {
        Ok(())  => { crate::pathresolve::d_drop_path(&p); 0 }
        Err(e)  => {
            crate::namei_common::trace_run_vfs_error(b"mknod", &p, e);
            errno_from_vfs(e)
        }
    }
}

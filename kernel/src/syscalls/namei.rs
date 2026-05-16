// Namespace-mutating syscalls — unlink / mkdir / rmdir / rename —
// per `15§5` / `16§3`. Routed to the ext4 mount via dev_ext4 for
// real-fs paths; tmpfs/devfs/procfs paths return Erofs (those
// pseudo filesystems don't accept create/remove from userspace).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

const AT_REMOVEDIR: u32 = 0x200;

fn read_path(ptr: u64) -> Option<String> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 256 B bound.
    let bytes = unsafe { crate::devfs::read_user_cstr(ptr, 256) }?;
    if bytes.is_empty() { return None; }
    core::str::from_utf8(bytes).ok().map(|s| s.into())
}

fn resolve(path_raw: &str) -> Option<String> {
    if path_raw.starts_with('/') { return Some(path_raw.into()); }
    let cur = sched::live::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

fn is_ext4_path(p: &str) -> bool {
    p.starts_with("/bin/")  || p.starts_with("/etc/")  || p.starts_with("/usr/")
 || p.starts_with("/sbin/") || p.starts_with("/lib/")  || p.starts_with("/opt/")
 || p.starts_with("/home/") || p.starts_with("/root/") || p == "/init"
 || p == "/hello.txt"
}

fn errno_from_vfs(e: vfs::VfsError) -> i64 {
    -(match e {
        vfs::VfsError::Enoent  => Errno::Enoent  as i32,
        vfs::VfsError::Eisdir  => Errno::Eisdir  as i32,
        vfs::VfsError::Enotdir => Errno::Enotdir as i32,
        vfs::VfsError::Erofs   => Errno::Erofs   as i32,
        vfs::VfsError::Eio     => Errno::Eio     as i32,
        _                      => Errno::Eio     as i32,
    } as i64)
}

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
    if let Err(rv) = crate::syscalls::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match ext4::rootfs::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `linkat(odir, target, ndir, link, flags)` slot 265.
/// # C: O(1)
pub fn sys_linkat(args: &SyscallArgs) -> i64 {
    let target_p = args.a1;
    let link_p   = args.a3;
    let target = match read_path(target_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(link_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let t = resolve(&target).unwrap_or(target);
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::syscalls::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match ext4::rootfs::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `unlink(path)` slot 87.
/// # C: O(N parent entries)
pub fn sys_unlink(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::syscalls::landlock::check(&p,
        ::security::landlock::access::REMOVE_FILE) { return rv; }
    let (mnt, rel) = match mount_for_write(&p) { Ok(x) => x, Err(rv) => return rv };
    match mnt.fs.unlink(&rel) { Ok(()) => 0, Err(e) => errno_from_vfs(e) }
}

/// `unlinkat(dirfd, path, flags)` slot 263. We currently honour
/// the `AT_REMOVEDIR` flag → rmdir; ignore dirfd (no per-fd
/// directory state yet — paths are absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn sys_unlinkat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    let flags = args.a2 as u32;
    let op = if (flags & AT_REMOVEDIR) != 0 {
        ::security::landlock::access::REMOVE_DIR
    } else {
        ::security::landlock::access::REMOVE_FILE
    };
    if let Err(rv) = crate::syscalls::landlock::check(&p, op) { return rv; }
    let (mnt, rel) = match mount_for_write(&p) { Ok(x) => x, Err(rv) => return rv };
    // AT_REMOVEDIR currently only supported on ext4 path. Other FSes
    // get the unified unlink which they may reject as Erofs/Eisdir.
    let r = if (flags & AT_REMOVEDIR) != 0 && is_ext4_path(&p) {
        ext4::rootfs::rmdir_at(p.as_bytes())
    } else {
        mnt.fs.unlink(&rel)
    };
    match r { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn sys_mkdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::syscalls::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let mode = args.a1 as u16;
    match ext4::rootfs::mkdir_at(p.as_bytes(), mode) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn sys_mkdirat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::syscalls::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let mode = args.a2 as u16;
    match ext4::rootfs::mkdir_at(p.as_bytes(), mode) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `symlink(target, linkpath)` slot 88.
/// # C: O(N parent entries)
pub fn sys_symlink(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    symlink_impl(target, link)
}

/// `symlinkat(target, newdirfd, linkpath)` slot 266. Ignores newdirfd
/// (paths resolved absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn sys_symlinkat(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a2) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    symlink_impl(target, link)
}

fn symlink_impl(target: String, link: String) -> i64 {
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::syscalls::landlock::check(&l,
        ::security::landlock::access::MAKE_SYM) { return rv; }
    if !is_ext4_path(&l) { return -(Errno::Erofs.as_i32() as i64); }
    match ext4::rootfs::symlink_at(target.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `mknod(path, mode, dev)` slot 133.
/// # C: O(N parent entries)
pub fn sys_mknod(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    mknod_impl(raw, args.a1 as u16, args.a2 as u32)
}

/// `mknodat(dirfd, path, mode, dev)` slot 259. Ignores dirfd.
/// # C: O(N parent entries)
pub fn sys_mknodat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    mknod_impl(raw, args.a2 as u16, args.a3 as u32)
}

fn mknod_impl(raw: String, mode: u16, dev: u32) -> i64 {
    let p = resolve(&raw).unwrap_or(raw);
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
    if let Err(rv) = crate::syscalls::landlock::check(&p, la) { return rv; }
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let r = if real_ftype == S_IFREG {
        // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
        ext4::rootfs::create_at(p.as_bytes(), mode & 0x0FFF)
            .map(|_| ()).ok_or(vfs::VfsError::Eio)
    } else {
        ext4::rootfs::mknod_at(p.as_bytes(), (real_ftype | (mode & 0x0FFF)) as u16, dev)
    };
    match r { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}

/// `rmdir(path)` slot 84.
/// # C: O(1)
pub fn sys_rmdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::syscalls::landlock::check(&p,
        ::security::landlock::access::REMOVE_DIR) { return rv; }
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    match ext4::rootfs::rmdir_at(p.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)`
/// slot 264 / `renameat2` slot 316. We collapse all three into
/// link-then-unlink against the ext4 mount.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(args.a0, args.a1)
}

/// # C: O(1)
pub fn sys_renameat(args: &SyscallArgs) -> i64 {
    rename_impl(args.a1, args.a3)
}

/// # C: O(1)
pub fn sys_renameat2(args: &SyscallArgs) -> i64 {
    rename_impl(args.a1, args.a3)
}


/// Route a path-write operation through the mount table per
/// `docs/16`. Replaces the `is_ext4_path` gate + `ext4::rootfs::*`
/// hardcoded chain. Returns the resolved (mount, relative_path) or
/// EROFS-like errno if no mount matches.
fn mount_for_write(path: &str) -> Result<(alloc::sync::Arc<vfs::mount::Mount>, alloc::string::String), i64> {
    vfs::mount::resolve_mount(path).ok_or(-(Errno::Enoent.as_i32() as i64))
}

fn rename_impl(from_ptr: u64, to_ptr: u64) -> i64 {
    let from_raw = match read_path(from_ptr) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let to_raw = match read_path(to_ptr) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let f = resolve(&from_raw).unwrap_or(from_raw);
    let t = resolve(&to_raw).unwrap_or(to_raw);
    // Landlock: from-side needs REMOVE_FILE | REMOVE_DIR | REFER;
    // to-side needs MAKE_REG. Approximate as REMOVE_FILE+MAKE_REG.
    let la = ::security::landlock::access::REMOVE_FILE
           | ::security::landlock::access::MAKE_REG
           | ::security::landlock::access::REFER;
    if let Err(rv) = crate::syscalls::landlock::check(&f, la) { return rv; }
    if let Err(rv) = crate::syscalls::landlock::check(&t, la) { return rv; }
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

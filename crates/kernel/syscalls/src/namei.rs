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
    let bytes = unsafe { devfs::read_user_cstr(ptr, 256) }?;
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
 // B47: /var and /tmp host writable state for daemons (dhcpcd's
 // lease + control socket dirs, /tmp for temporary files). We
 // pre-create the parent dirs in the ext4 image and mount tmpfs
 // over /var/{run,db} + /tmp; dhcpcd does mkdir('/var/db/dhcpcd')
 // (EEXIST is fine) which our gate was returning EROFS for. Route
 // those to ext4 too — the overlay-mount machinery rides a
 // follow-up; for now the tmpfs mount silently shadows the dir.
 || p.starts_with("/var/") || p.starts_with("/tmp/") || p.starts_with("/run/")
}

fn errno_from_vfs(e: vfs::VfsError) -> i64 {
    -(match e {
        vfs::VfsError::Enoent  => Errno::Enoent  as i32,
        vfs::VfsError::Eisdir  => Errno::Eisdir  as i32,
        vfs::VfsError::Enotdir => Errno::Enotdir as i32,
        vfs::VfsError::Erofs   => Errno::Erofs   as i32,
        vfs::VfsError::Eio     => Errno::Eio     as i32,
        vfs::VfsError::Eperm   => Errno::Eperm   as i32,
        vfs::VfsError::Eexist  => Errno::Eexist  as i32,
        vfs::VfsError::Einval  => Errno::Einval  as i32,
        vfs::VfsError::Eacces  => Errno::Eacces  as i32,
        vfs::VfsError::Enomem  => Errno::Enomem  as i32,
        vfs::VfsError::Enospc  => Errno::Enospc  as i32,
        vfs::VfsError::Ebusy   => Errno::Ebusy   as i32,
        vfs::VfsError::Enotempty => Errno::Enotempty as i32,
        vfs::VfsError::Enosys  => Errno::Enosys  as i32,
        _                      => Errno::Eio     as i32,
    } as i64)
}

/// Split an absolute path into `(parent, basename)`. `None` for `/`
/// or a trailing-only slash.
fn split_parent(p: &str) -> Option<(&str, &str)> {
    let p = if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p };
    let idx = p.rfind('/')?;
    let name = &p[idx + 1..];
    if name.is_empty() { return None; }
    let parent = if idx == 0 { "/" } else { &p[..idx] };
    Some((parent, name))
}

/// Resolve the PARENT directory of absolute `p` through the dentry walk
/// (`pathresolve::resolve` = `vfs::path_lookup`; follows intermediate
/// symlinks + crosses mounts) and return `(parent_inode, basename)` —
/// THE resolver feeding every namespace mutation per `docs/16§3`,
/// replacing the is_ext4_path / mount_for_write / pseudo_* string gates.
/// The owning mount's inode then services the op (ext4 dir → ext4
/// create/unlink; tmpfs dir → tmpfs; cgroupfs → cgroupfs; read-only
/// pseudo-fs → Erofs), exactly as Linux `inode_operations`.
/// # C: O(N parent components)
fn resolve_parent(p: &str) -> Result<(vfs::InodeRef, String), i64> {
    let p = strip_trailing_slash(p);
    let (parent, name) = split_parent(p).ok_or(-(Errno::Einval.as_i32() as i64))?;
    let pino = crate::pathresolve::resolve(parent, false)
        .ok_or(-(Errno::Enoent.as_i32() as i64))?;
    Ok((pino, String::from(name)))
}

/// True if `p` already resolves to an existing inode (final component
/// not followed if it's a symlink). Linux checks target existence
/// before the fs-specific `mkdir`, returning EEXIST regardless of
/// parent writability. Without this, `mkdir` of an existing dir whose
/// parent is a read-only pseudo-fs leaks the parent's EROFS — e.g.
/// systemd's `cg_create("/")` does `mkdir("/sys/fs/cgroup")` (already
/// present), whose parent `/sys/fs` is sysfs → EROFS instead of the
/// EEXIST systemd treats as success, aborting its cgroup setup.
/// # C: O(N path components)
fn path_exists(p: &str) -> bool {
    crate::pathresolve::resolve(p, true).is_some()
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
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match ext4::rootfs::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `linkat(odir, target, ndir, link, flags)` slot 265. Supports
/// `AT_EMPTY_PATH` (flag bit 0x1000): when set and `target` is the
/// empty string, the source is the fd in `odir`, not a path. This
/// is how O_TMPFILE inodes get a name after creation.
/// # C: O(1)
pub fn sys_linkat(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let odir_fd  = args.a0 as i32;
    let target_p = args.a1;
    let link_p   = args.a3;
    let flags    = args.a4;

    let link = match read_path(link_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&l) { return -(Errno::Erofs.as_i32() as i64); }

    if (flags & AT_EMPTY_PATH) != 0 {
        // target must be empty (NULL ptr or "").
        let target_empty = if target_p == 0 {
            true
        } else {
            // SAFETY: target_p in user range (we don't deref past 256B); user page mapped under caller's AS on the syscall path; bounded read.
            let bytes = unsafe { devfs::read_user_cstr(target_p, 256) };
            matches!(bytes, Some(b) if b.is_empty())
        };
        if !target_empty { return -(Errno::Einval.as_i32() as i64); }
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let file = match fdt.get(odir_fd) {
            Ok(f)  => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let vfs_ino = file.inode().ino();
        // Only ext4-resident inodes (high-half marker = 0x6E54) can
        // be linked into the ext4 dir tree.
        if (vfs_ino >> 32) != 0x6E54 {
            return -(Errno::Exdev.as_i32() as i64);
        }
        let ino = (vfs_ino & 0xFFFF_FFFF) as u32;
        return match ext4::rootfs::link_inode_at(ino, l.as_bytes()) {
            Ok(())  => 0,
            Err(e)  => errno_from_vfs(e),
        };
    }

    // Classic path→path linkat.
    let target = match read_path(target_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let t = resolve(&target).unwrap_or(target);
    if !is_ext4_path(&t) { return -(Errno::Erofs.as_i32() as i64); }
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
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_FILE) { return rv; }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.unlink_child(&name) { Ok(()) => 0, Err(e) => errno_from_vfs(e) }
}

/// `unlinkat(dirfd, path, flags)` slot 263. We currently honour
/// the `AT_REMOVEDIR` flag → rmdir; ignore dirfd (no per-fd
/// directory state yet — paths are absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn sys_unlinkat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let p = match crate::pathresolve::resolve_at(args.a0 as i32, &raw) {
        Some(rp) => rp, None => resolve(&raw).unwrap_or(raw),
    };
    let flags = args.a2 as u32;
    let op = if (flags & AT_REMOVEDIR) != 0 {
        ::security::landlock::access::REMOVE_DIR
    } else {
        ::security::landlock::access::REMOVE_FILE
    };
    if let Err(rv) = crate::landlock::check(&p, op) { return rv; }
    // AT_REMOVEDIR is rmdir — delegate to the shared core so the
    // legacy rmdir(2) and the *at form (the only one aarch64 has)
    // stay identical. Without this, cgroup/pseudo-fs rmdir worked on
    // x86 (via sys_rmdir) but returned EROFS on arm.
    if (flags & AT_REMOVEDIR) != 0 {
        return do_rmdir(&p);
    }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.unlink_child(&name) { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}

/// Strip a trailing `/` (POSIX: `mkdir /var/` ≡ `mkdir /var`). Root
/// `/` is preserved. busybox/GNU `mkdir -p` walk ancestors with a
/// trailing slash on each prefix; without this the ext4 backend
/// resolves `/var/` to a missing child and returns ENOENT for a dir
/// that exists.
/// # C: O(1)
fn strip_trailing_slash(p: &str) -> &str {
    if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p }
}

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn sys_mkdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let mode = args.a1 as u16;
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.mkdir(&name, mode as u32) { Ok(_) => 0, Err(e) => errno_from_vfs(e) }
}

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn sys_mkdirat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let p = match crate::pathresolve::resolve_at(args.a0 as i32, &raw) {
        Some(rp) => rp, None => resolve(&raw).unwrap_or(raw),
    };
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let mode = args.a2 as u16;
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.mkdir(&name, mode as u32) { Ok(_) => 0, Err(e) => errno_from_vfs(e) }
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
    // BUG D follow-up: resolve linkpath against newdirfd (a1). The symlink
    // target is stored verbatim (never resolved at creation).
    let link = crate::pathresolve::resolve_at(args.a1 as i32, &link).unwrap_or(link);
    symlink_impl(target, link)
}

fn symlink_impl(target: String, link: String) -> i64 {
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_SYM) { return rv; }
    let (pino, name) = match resolve_parent(&l) { Ok(x) => x, Err(rv) => return rv };
    match pino.symlink_child(&name, target.as_bytes()) {
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
    // BUG D follow-up: resolve against the real dirfd (a0).
    let raw = crate::pathresolve::resolve_at(args.a0 as i32, &raw).unwrap_or(raw);
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
    if let Err(rv) = crate::landlock::check(&p, la) { return rv; }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    let r = if real_ftype == S_IFREG {
        // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
        pino.create_child(&name, (mode & 0x0FFF) as u32).map(|_| ())
    } else {
        pino.mknod_child(&name, (real_ftype | (mode & 0x0FFF)) as u16, dev)
    };
    match r { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}

/// Single rmdir core — both `rmdir(2)` (slot 84, x86 legacy) and
/// `unlinkat(…, AT_REMOVEDIR)` (the only form aarch64 has) delegate
/// here so the two ABI entry points can never diverge (Linux routes
/// both through `do_rmdirat`). `p` is the resolved absolute path;
/// the caller has already run the landlock REMOVE_DIR check.
/// Pseudo-fs dirs (cgroupfs, …) own their rmdir; ext4 dirs go to the
/// ext4 backend; everything else is read-only.
/// # C: O(1)
fn do_rmdir(p: &str) -> i64 {
    let (pino, name) = match resolve_parent(p) { Ok(x) => x, Err(rv) => return rv };
    match pino.rmdir(&name) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rmdir(path)` slot 84 (x86 legacy; absent on aarch64).
/// # C: O(1)
pub fn sys_rmdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_DIR) { return rv; }
    do_rmdir(&p)
}

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)`
/// slot 264 / `renameat2` slot 316. We collapse all three into
/// link-then-unlink against the ext4 mount.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(-100, args.a0, -100, args.a1)
}

/// # C: O(1)
pub fn sys_renameat(args: &SyscallArgs) -> i64 {
    // renameat(olddirfd, from, newdirfd, to): resolve each against its dirfd.
    rename_impl(args.a0 as i32, args.a1, args.a2 as i32, args.a3)
}

/// # C: O(1)
pub fn sys_renameat2(args: &SyscallArgs) -> i64 {
    rename_impl(args.a0 as i32, args.a1, args.a2 as i32, args.a3)
}


/// Route a path-write operation through the mount table per
/// `docs/16`. Replaces the `is_ext4_path` gate + `ext4::rootfs::*`
/// hardcoded chain. Returns the resolved (mount, relative_path) or
/// EROFS-like errno if no mount matches.
fn mount_for_write(path: &str) -> Result<(alloc::sync::Arc<vfs::mount::Mount>, alloc::string::String), i64> {
    vfs::mount::resolve_mount(path).ok_or(-(Errno::Enoent.as_i32() as i64))
}

fn rename_impl(from_dirfd: i32, from_ptr: u64, to_dirfd: i32, to_ptr: u64) -> i64 {
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

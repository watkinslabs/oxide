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
    let cur = crate::sched::current()?;
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
pub fn kernel_sys_link(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let t = resolve(&target).unwrap_or(target);
    let l = resolve(&link).unwrap_or(link);
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match dev_ext4::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `linkat(odir, target, ndir, link, flags)` slot 265.
/// # C: O(1)
pub fn kernel_sys_linkat(args: &SyscallArgs) -> i64 {
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
    if !is_ext4_path(&t) || !is_ext4_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match dev_ext4::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `unlink(path)` slot 87.
/// # C: O(N parent entries)
pub fn kernel_sys_unlink(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    match dev_ext4::unlink_at(p.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `unlinkat(dirfd, path, flags)` slot 263. We currently honour
/// the `AT_REMOVEDIR` flag → rmdir; ignore dirfd (no per-fd
/// directory state yet — paths are absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn kernel_sys_unlinkat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let flags = args.a2 as u32;
    let r = if (flags & AT_REMOVEDIR) != 0 {
        dev_ext4::rmdir_at(p.as_bytes())
    } else {
        dev_ext4::unlink_at(p.as_bytes())
    };
    match r { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn kernel_sys_mkdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let mode = args.a1 as u16;
    match dev_ext4::mkdir_at(p.as_bytes(), mode) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn kernel_sys_mkdirat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    let mode = args.a2 as u16;
    match dev_ext4::mkdir_at(p.as_bytes(), mode) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rmdir(path)` slot 84.
/// # C: O(1)
pub fn kernel_sys_rmdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if !is_ext4_path(&p) { return -(Errno::Erofs.as_i32() as i64); }
    match dev_ext4::rmdir_at(p.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)`
/// slot 264 / `renameat2` slot 316. We collapse all three into
/// link-then-unlink against the ext4 mount.
/// # C: O(1)
pub fn kernel_sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(args.a0, args.a1)
}

/// # C: O(1)
pub fn kernel_sys_renameat(args: &SyscallArgs) -> i64 {
    rename_impl(args.a1, args.a3)
}

/// # C: O(1)
pub fn kernel_sys_renameat2(args: &SyscallArgs) -> i64 {
    rename_impl(args.a1, args.a3)
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
    if !is_ext4_path(&f) || !is_ext4_path(&t) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    match dev_ext4::rename_at(f.as_bytes(), t.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

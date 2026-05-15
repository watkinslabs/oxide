// `sys_open` / `sys_openat` per `15§5` / `16§3`. Split from
// syscall_glue.rs / syscall_glue_fs.rs to keep both under cap.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use vfs::{Dentry, File, OpenFlags};


const O_CREAT:     u32 = 0o100;
const O_TRUNC:     u32 = 0o1000;
const O_DIRECTORY: u32 = 0o200000;

/// Resolve a relative path against the calling task's cwd. Returns
/// `None` for absolute paths (caller uses path_raw verbatim).
/// Critically, the bare `.` and `..` cases must NOT be short-
/// circuited — `ls` (no arg) sends `.` and the openat lookup
/// otherwise tries to find a literal `.` entry in the registry,
/// which doesn't exist.
/// # C: O(N)
fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    if path_raw.starts_with('/') { return None; }
    Some(crate::syscalls::pathresolve::resolve_cwd(path_raw))
}

/// `sys_open(path, flags, mode)` — slot 2.
/// # C: O(N_path)
pub fn sys_open(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let flags    = args.a1 as u32;
    let mode     = args.a2 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller already ran code from this AS); 256 B bound.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let path_raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(path_raw);
    let path_str: &str = resolved.as_deref().unwrap_or(path_raw);
    {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        if let Err(rv) = crate::syscalls::landlock::check(path_str, op) { return rv; }
    }
    // Unified mount-table lookup (R67). Special-case /dev/ptmx since
    // it allocates a new pair per open rather than resolving to a
    // pre-registered inode.
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if let Ok(i) = vfs::mount::lookup(path_str) {
        i
    } else if let Some(i) = ext4::rootfs::lookup_inode_any(path_str.as_bytes()) {
        // Fallback for ext4 dirs/non-regular inodes the unified mount-
        // table doesn't expose (e.g. /root, /etc as Directory inodes
        // for getdents64 on open(O_DIRECTORY)).
        i
    } else if (flags & O_CREAT) != 0 {
        // O_CREAT: ask the owning mount's FS to create with
        // user-supplied mode masked by the current task's umask.
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = mode & 0o777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => match mnt.fs.create(&rel, final_mode) {
                Ok(i) => i,
                Err(_) => return -(Errno::Enoent.as_i32() as i64),
            },
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match vfs::file::install_open(&fdt, inode, path_str, OpenFlags::from_bits_truncate(flags)) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_openat(dirfd, path, flags, mode)` — slot 257.
/// # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a1;
    let flags    = args.a2 as u32;
    let mode     = args.a3 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(s);
    let path_str: &str = resolved.as_deref().unwrap_or(s);
    // Landlock check: derive requested access from open flags.
    {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        if let Err(rv) = crate::syscalls::landlock::check(path_str, op) { return rv; }
    }
    // Unified mount-table lookup (R67). Special-case /dev/ptmx since
    // it allocates a new pair per open rather than resolving to a
    // pre-registered inode.
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if let Ok(i) = vfs::mount::lookup(path_str) {
        i
    } else if let Some(i) = ext4::rootfs::lookup_inode_any(path_str.as_bytes()) {
        // Fallback for ext4 dirs/non-regular inodes the unified mount-
        // table doesn't expose (e.g. /root, /etc as Directory inodes
        // for getdents64 on open(O_DIRECTORY)).
        i
    } else if (flags & O_CREAT) != 0 {
        // O_CREAT: ask owning mount's FS to create with the
        // user-supplied mode masked by the task umask.
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = mode & 0o777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => match mnt.fs.create(&rel, final_mode) {
                Ok(i) => i,
                Err(_) => return -(Errno::Enoent.as_i32() as i64),
            },
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    if (flags & O_DIRECTORY) != 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, path_str.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}

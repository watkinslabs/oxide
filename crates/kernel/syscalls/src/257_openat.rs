// 257 openat — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use vfs::{Dentry, File, OpenFlags};

use crate::open_common::{dup_fd_target, open_proc_fd, O_CREAT, O_TRUNC, O_DIRECTORY,
    O_NOFOLLOW, O_TMPFILE};

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
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // openat(2): resolve relative `s` against the dirfd's directory (a0).
    let resolved = crate::pathresolve::resolve_at(args.a0 as i32, s);
    let path_str: &str = resolved.as_deref().unwrap_or(s);
    {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        if let Err(rv) = crate::landlock::check(path_str, op) { return rv; }
    }
    if let Some((tid_opt, n)) = dup_fd_target(path_str) {
        return open_proc_fd(tid_opt, n);
    }
    // O_TMPFILE short-circuits to anonymous inode creation.
    let inode = if (flags & O_TMPFILE) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = (mode & 0o777 & !umask) as u16;
        match ext4::rootfs::create_anonymous_at(path_str.as_bytes(), final_mode) {
            Some(i) => i,
            None    => return -(Errno::Enospc.as_i32() as i64),
        }
    } else if path_str == "/dev/ptmx" {
        let (master, _n) = devpts::allocate_pair();
        master
    } else if path_str == "/dev/tty" {
        // F200: caller's controlling terminal; ENXIO when none.
        match sched::live::current() {
            // SAFETY: single-mutator per `13§5` — current task on this CPU.
            Some(t) => match unsafe { (*t.ctty.get()).clone() } {
                Some(i) => i,
                None    => return -(Errno::Enxio.as_i32() as i64),
            },
            None => return -(Errno::Enxio.as_i32() as i64),
        }
    } else if let Some(i) = crate::pathresolve::resolve(path_str, (flags & O_NOFOLLOW) != 0) {
        i
    } else if (flags & O_CREAT) != 0 {
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
    // O_TMPFILE = __O_TMPFILE | O_DIRECTORY, so skip the dir check for it.
    if (flags & O_DIRECTORY) != 0 && (flags & O_TMPFILE) == 0
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

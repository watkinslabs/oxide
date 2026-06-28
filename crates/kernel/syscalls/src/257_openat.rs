// 257 openat — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use vfs::{File, OpenFlags};

use crate::open_common::{dup_fd_target, open_proc_fd, enforce_open_perm, O_CREAT, O_TRUNC,
    O_DIRECTORY, O_NOFOLLOW, O_TMPFILE};

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
    #[cfg(feature = "debug-syscall")]
    {
        klog::write_raw(b"[OPENAT] dirfd=");
        let dirfd = args.a0 as i64;
        if dirfd < 0 {
            klog::write_raw(b"-");
            klog::write_dec_u64(dirfd.wrapping_neg() as u64);
        } else {
            klog::write_dec_u64(dirfd as u64);
        }
        klog::write_raw(b" flags=");
        klog::write_hex_u64(flags as u64);
        klog::write_raw(b" path=\"");
        klog::write_raw(s.as_bytes());
        klog::write_raw(b"\"\n");
    }
    // openat(2): resolve relative `s` against the dirfd's directory (a0).
    let resolved = match crate::pathresolve::resolve_at_result(args.a0 as i32, s) {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    let path_str: &str = resolved.as_str();
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
    // O_TMPFILE short-circuits to anonymous inode creation. Each branch
    // also yields the `mnt_id` the file is opened through (Linux
    // `f_path.mnt`): the resolved mount for FS paths, 0 for anon devices.
    let (inode, mnt_id, created) = if (flags & O_TMPFILE) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = (mode & 0o777 & !umask) as u16;
        // O_TMPFILE creates the anonymous inode on the filesystem that
        // actually backs the target directory — tmpfs for /run|/tmp|/dev/shm,
        // ext4 for the rootfs. Routing every O_TMPFILE to ext4 returned ENOSPC
        // for tmpfs paths, which made journald (O_TMPFILE on /run/log/journal)
        // abort and cascaded to udevd/device units.
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => {
                if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                    return -(Errno::Erofs.as_i32() as i64);
                }
                match mnt.fs().create_anonymous(&rel, final_mode as u32) {
                    Ok(i)  => (i, mnt.mnt_id, true),
                    Err(_) => return -(Errno::Enospc.as_i32() as i64),
                }
            }
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else if path_str == "/dev/ptmx" {
        let (master, _n) = devpts::allocate_pair();
        (master, 0, false)
    } else if path_str == "/dev/tty" {
        // F200: caller's controlling terminal; ENXIO when none.
        match sched::live::current() {
            // SAFETY: single-mutator per `13§5` — current task on this CPU.
            Some(t) => match unsafe { (*t.ctty.get()).clone() } {
                Some(i) => (i, 0, false),
                None    => return -(Errno::Enxio.as_i32() as i64),
            },
            None => return -(Errno::Enxio.as_i32() as i64),
        }
    } else if let Some(vp) = crate::pathresolve::resolve_path(path_str, (flags & O_NOFOLLOW) != 0) {
        (vp.inode, vp.mnt_id, false)
    } else if (flags & O_CREAT) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = mode & 0o777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => {
                if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                    return -(Errno::Erofs.as_i32() as i64);
                }
                match mnt.fs().create(&rel, final_mode) {
                    Ok(i) => (i, mnt.mnt_id, true),
                    Err(e) => {
                        crate::namei_common::trace_run_vfs_error(b"openat-create", path_str, e);
                        return -(Errno::Enoent.as_i32() as i64);
                    }
                }
            }
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        // DIAG (debug-mount): surface ENOENT opens of the paths whose chase
        // fails the service sandbox (domainname / credentials / RuntimeDir /
        // StateDir), so the exact missing path is visible without flooding.
        #[cfg(feature = "debug-mount")]
        if path_str.contains("domainname") || path_str.contains("osrelease")
            || path_str.contains("cap_last_cap")
        {
            // Isolate the failure layer: ns of the caller + whether the namei
            // walk finds it (resolve() bug if dl=1; ns/chroot bug if dl=0).
            let ns = sched::live::current().map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
            let dl = if crate::pathresolve::resolve(path_str, false).is_some() { 1u64 } else { 0 };
            let mut tag = alloc::string::String::from(path_str);
            tag.push_str(" ns=");
            tag.push_str(&alloc::format!("{}", ns));
            tag.push_str(" dl=");
            tag.push_str(&alloc::format!("{}", dl));
            crate::mount_common::mnt_log("openat_ENOENT", &tag, -(Errno::Enoent.as_i32() as i64));
        }
        return -(Errno::Enoent.as_i32() as i64);
    };
    // O_TMPFILE = __O_TMPFILE | O_DIRECTORY, so skip the dir check for it.
    if (flags & O_DIRECTORY) != 0 && (flags & O_TMPFILE) == 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if let Err(e) = inode.on_open() { return -(e as i64); }
    // DAC + EROFS enforcement (Linux `may_open`), before the O_TRUNC truncate.
    if let Some(rv) = enforce_open_perm(&inode, mnt_id, flags, created) { return rv; }
    // fanotify FAN_OPEN_PERM (fast no-op without perm marks; deny → EACCES).
    if !::fs::inotify::check_open_perm(&inode) { return -(Errno::Eacces.as_i32() as i64); }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Parented dentry (Linux `f_path.dentry`): the fd's path reconstructs by
    // parent-walk (`Dentry::absolute_path`), not a stored whole string.
    // O_TMPFILE inodes have no directory entry — their path is the *directory*.
    let dentry_path = if (flags & O_TMPFILE) != 0 { "/" } else { path_str };
    let dentry = vfs::file::open_dentry(dentry_path, &inode);
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new_at(inode, dentry, oflags, mnt_id, crate::pathresolve::current_cred());
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}

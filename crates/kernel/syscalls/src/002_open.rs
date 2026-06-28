// 002 open — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use vfs::OpenFlags;

use crate::open_common::{dup_fd_target, open_proc_fd, resolve_path_for_open,
    enforce_open_perm, O_CREAT, O_TRUNC, O_NOFOLLOW};

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
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
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
        if let Err(rv) = crate::landlock::check(path_str, op) { return rv; }
    }
    // /dev/{stdin,stdout,stderr}, /dev/fd/<n>, /proc/<pid>/fd/<n>: dup the
    // existing open file description (Linux fd-link semantics).
    if let Some((tid_opt, n)) = dup_fd_target(path_str) {
        return open_proc_fd(tid_opt, n, flags);
    }
    // Unified mount-table lookup (R67). /dev/ptmx allocates a new pair per open.
    // Each branch also yields the `mnt_id` the file is opened through (Linux
    // `f_path.mnt`): the resolved mount for FS paths, 0 for anon devices.
    let (inode, mnt_id, created) = if path_str == "/dev/ptmx" {
        let (master, _n) = devpts::allocate_pair();
        (master, 0, false)
    } else if path_str == "/dev/tty" {
        // F200: /dev/tty resolves to caller's ctty (POSIX §11.1.3); ENXIO when none.
        match sched::live::current() {
            // SAFETY: single-mutator per `13§5`; current task on this CPU.
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
                // EROFS before create on a read-only mount (Linux `mnt_want_write`).
                if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                    return -(Errno::Erofs.as_i32() as i64);
                }
                match mnt.fs().create(&rel, final_mode) {
                    Ok(i) => (i, mnt.mnt_id, true),
                    Err(e) => {
                        crate::namei_common::trace_run_vfs_error(b"open-create", path_str, e);
                        return -(Errno::Enoent.as_i32() as i64);
                    }
                }
            }
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    // DAC + EROFS enforcement (Linux `may_open`), before the O_TRUNC truncate.
    if let Some(rv) = enforce_open_perm(&inode, mnt_id, flags, created) { return rv; }
    // fanotify FAN_OPEN_PERM: blocks here until a daemon allows/denies (fast
    // no-op when no perm marks exist). Deny → EACCES, no fd created.
    if !::fs::inotify::check_open_perm(&inode) { return -(Errno::Eacces.as_i32() as i64); }
    if let Err(rv) = ::security::bpf_lsm::file_open(&inode) { return rv; }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match vfs::file::install_open(&fdt, inode, path_str, OpenFlags::from_bits_truncate(flags),
        mnt_id, crate::pathresolve::current_cred()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

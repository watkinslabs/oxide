// 002 open — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::open_common::{dup_fd_target, open_proc_fd, resolve_path_for_open,
    enforce_open_perm, break_lease_for_open, O_CREAT, O_EXCL, O_TRUNC, O_DIRECTORY, O_NOFOLLOW};

/// `sys_open(path, flags, mode)` — slot 2.
/// # C: O(N_path)
pub fn sys_open(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let flags    = args.a1 as u32;
    let mode     = args.a2 as u32;
    // D1/D2: full PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG)
    // via read_user_path, replacing the 256-byte cap + EINVAL-on-empty.
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let path_raw: &str = path.as_str();
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
        // O_CREAT|O_EXCL: an existing final component is a hard error (Linux
        // `do_last`/`lookup_open`: `if (open_flag & O_EXCL) → -EEXIST`).
        if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
            return -(Errno::Eexist.as_i32() as i64);
        }
        (vp.inode, vp.mnt_id, false)
    } else if (flags & O_CREAT) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        // Linux build_open_flags: mode masked with S_IALLUGO (0o7777) so the
        // S_ISUID/S_ISGID/S_ISVTX bits survive the create; umask clears only the
        // rwx bits it carries (D8).
        let final_mode = mode & 0o7777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, _rel)) => {
                // EROFS before create on a read-only mount (Linux `mnt_want_write`).
                if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                    return -(Errno::Erofs.as_i32() as i64);
                }
                // ext4 D9: create on the RESOLVED PARENT dir inode + leaf name
                // (Linux `filename_create` → `i_op->create`), instead of the
                // whole-path `FileSystem::create` re-splitting the path string.
                // Same op `mknod(S_IFREG)` drives; `final_mode` is already
                // umasked and `apply_umask` is idempotent. Owner is the caller's
                // fsuid/fsgid (Linux `inode_init_owner`), not a hardcoded 0,0.
                let (pino, name) = match crate::namei_common::resolve_parent(path_str) {
                    Ok(x) => x, Err(rv) => return rv,
                };
                let cred = crate::pathresolve::current_cred();
                let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
                // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create
                // (Linux `filename_create`); dropped before the dcache update.
                let r = { let _g = pino.inode_lock(); pino.create_child(&name, final_mode, &ctx) };
                match r {
                    Ok(i) => (i, mnt.mnt_id, true),
                    Err(e) => {
                        crate::namei_common::trace_run_vfs_error(b"open-create", path_str, e);
                        // D7: surface the real VfsError→errno (EACCES/EROFS/
                        // ENOSPC/ENOTDIR/…) instead of collapsing to ENOENT.
                        return crate::namei_common::errno_from_vfs(e);
                    }
                }
            }
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    // O_CREAT flush: drop the leaf negative planted by the failed existence
    // resolve above so `install_open`'s path-walk re-resolves to the NEW inode
    // rather than the stale negative (Linux instantiates the create's own leaf).
    if created { crate::pathresolve::d_drop_path(path_str); }
    // D6: O_DIRECTORY on a non-directory final → ENOTDIR (Linux `do_open`
    // `if ((open_flag & O_DIRECTORY) && !S_ISDIR) → -ENOTDIR`).
    if (flags & O_DIRECTORY) != 0 && !matches!(inode.file_type(), vfs::FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    // FileOps on_open() hook (Linux `file_operations::open`), at open(2).
    if let Err(e) = inode.on_open() { return -(e as i64); }
    // DAC + EROFS enforcement (Linux `may_open`), before the O_TRUNC truncate.
    if let Some(rv) = enforce_open_perm(&inode, mnt_id, flags, created) { return rv; }
    // Lease-break (Linux `break_lease` in `do_open`): a conflicting open signals
    // the lease holder + waits for the downgrade/release (or break timeout)
    // before proceeding. Zero-cost when no lease exists. A just-created file
    // cannot have a pre-existing lease, so skip it there.
    if !created { if let Some(rv) = break_lease_for_open(&inode, flags) { return rv; } }
    // fanotify FAN_OPEN_PERM: blocks here until a daemon allows/denies (fast
    // no-op when no perm marks exist). Deny → EACCES, no fd created.
    if !::fs::inotify::check_open_perm(&inode) { return -(Errno::Eacces.as_i32() as i64); }
    if let Err(rv) = ::security::bpf_lsm::file_open(&inode) { return rv; }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    // D3/D37: a freshly CREATED inode (`fs().create`) carries the build/born
    // `i_count` reference. `install_open` binds it to a dentry (`d_add` grab) and
    // an open `File` (`igrab`); on success those are durable counted holders, so
    // release the born ref here (Linux `do_last`/`d_instantiate` consumes the
    // iget ref). `inode.clone()` is a pointer clone (no `i_count` change) taken
    // BEFORE the move so we can iput AFTER `install_open` reports a holder exists
    // → `i_count` never reaches 0 on the live inode. (The Err path leaves the
    // born ref held — conservative: no eviction there, but never a UAF.)
    let created_ref = if created { Some(inode.clone()) } else { None };
    match vfs::file::install_open(&fdt, inode, path_str, OpenFlags::from_bits_truncate(flags),
        mnt_id, crate::pathresolve::current_cred(), cur.nofile_soft()) {
        Ok(fd) => { if let Some(i) = created_ref { vfs::file::iput(i); } fd as i64 }
        Err(e) => -(e as i64),
    }
}

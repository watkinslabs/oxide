// 257 openat — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::open_common::{dup_fd_target, open_proc_fd, enforce_open_perm, break_lease_for_open,
    O_CREAT, O_EXCL, O_TRUNC, O_DIRECTORY, O_NOFOLLOW, O_TMPFILE};

/// `sys_openat(dirfd, path, flags, mode)` — slot 257. No openat2 RESOLVE_*
/// modifiers (default `LookupFlags`). # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    open_core(args, vfs::LookupFlags::default())
}

// openat2 RESOLVE_* (uapi/linux/openat2.h). VALID = OR of all six.
const RESOLVE_NO_XDEV:       u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS:   u64 = 0x04;
const RESOLVE_BENEATH:       u64 = 0x08;
const RESOLVE_IN_ROOT:       u64 = 0x10;
const RESOLVE_CACHED:        u64 = 0x20;
const RESOLVE_VALID: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED;

/// `sys_openat2(dirfd, path, flags, mode)` with the `open_how.resolve` field
/// already extracted by the dispatcher. Validates `resolve` (unknown bits →
/// EINVAL, BENEATH+IN_ROOT mutually exclusive — Linux `build_open_flags`) and
/// maps it onto `LookupFlags` consumed by the resolver. # C: O(N_path)
pub fn sys_openat2(args: &SyscallArgs, resolve: u64) -> i64 {
    if resolve & !RESOLVE_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    // Linux rejects RESOLVE_BENEATH together with RESOLVE_IN_ROOT.
    if (resolve & RESOLVE_BENEATH != 0) && (resolve & RESOLVE_IN_ROOT != 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let extra = vfs::LookupFlags {
        no_xdev:       resolve & RESOLVE_NO_XDEV != 0,
        no_magiclinks: resolve & RESOLVE_NO_MAGICLINKS != 0,
        no_symlinks:   resolve & RESOLVE_NO_SYMLINKS != 0,
        beneath_exdev: resolve & RESOLVE_BENEATH != 0,
        in_root:       resolve & RESOLVE_IN_ROOT != 0,
        cached:        resolve & RESOLVE_CACHED != 0,
        ..Default::default()
    };
    open_core(args, extra)
}

/// True when any openat2 RESOLVE_* modifier is set (so the resolve path takes
/// the flag-aware route that surfaces EXDEV/ELOOP instead of the legacy
/// collapse-to-ENOENT). # C: O(1)
fn extra_active(x: &vfs::LookupFlags) -> bool {
    x.no_xdev || x.no_magiclinks || x.no_symlinks || x.beneath_exdev || x.in_root || x.cached
}

/// openat / openat2 shared core. `extra` carries the openat2 RESOLVE_* bits
/// (empty for plain openat). # C: O(N_path)
fn open_core(args: &SyscallArgs, extra: vfs::LookupFlags) -> i64 {
    let path_ptr = args.a1;
    let flags    = args.a2 as u32;
    let mode     = args.a3 as u32;
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(p)   => p,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    #[cfg(feature = "debug-atexit")]
    if dyn_trace_path(s) {
        klog::write_raw(b"[DYNOPEN] raw dirfd=");
        let dirfd = args.a0 as i64;
        if dirfd < 0 {
            klog::write_raw(b"-");
            klog::write_dec_u64(dirfd.wrapping_neg() as u64);
        } else {
            klog::write_dec_u64(dirfd as u64);
        }
        klog::write_raw(b" flags=");
        klog::write_hex_u64(flags as u64);
        klog::write_raw(b" path=");
        klog::write_raw(s.as_bytes());
        klog::write_raw(b"\n");
    }
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
    #[cfg(feature = "debug-atexit")]
    if dyn_trace_path(path_str) {
        klog::write_raw(b"[DYNOPEN] resolved=");
        klog::write_raw(path_str.as_bytes());
        klog::write_raw(b"\n");
    }
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
        // RESOLVE_NO_MAGICLINKS: a magic link (/proc/self/fd/N, …) → ELOOP
        // (Linux nd_jump_link under LOOKUP_NO_MAGICLINKS).
        if extra.no_magiclinks { return -(Errno::Eloop.as_i32() as i64); }
        return open_proc_fd(tid_opt, n, flags);
    }
    // openat2 RESOLVE_*: resolve the existing-file path up-front through the
    // flag-aware resolver so EXDEV (BENEATH/NO_XDEV) / ELOOP (NO_SYMLINKS) /
    // EAGAIN (CACHED) surface to userspace instead of collapsing to ENOENT.
    // BENEATH/IN_ROOT re-base the walk START on the dirfd (resolve_confined).
    let nofollow = (flags & O_NOFOLLOW) != 0;
    let extra_resolved: Option<Option<vfs::VfsPath>> = if extra_active(&extra) {
        let mut lookup = extra;
        lookup.no_follow_final = nofollow;
        let r: Result<vfs::VfsPath, i64> = if extra.beneath_exdev || extra.in_root {
            crate::pathresolve::resolve_confined(args.a0 as i32, s, lookup)
        } else {
            // D17: seed from the dirfd's real (mnt_id, dentry) so EXDEV (NO_XDEV)
            // / ELOOP (NO_SYMLINKS) decisions key on the bind-correct mount.
            crate::pathresolve::resolve_at_path(args.a0 as i32, s, lookup)
        };
        match r {
            Ok(p) => Some(Some(p)),
            Err(rv) if rv == -(Errno::Enoent.as_i32() as i64) => Some(None),
            Err(rv) => return rv,
        }
    } else { None };
    // O_TMPFILE short-circuits to anonymous inode creation. Each branch
    // also yields the `mnt_id` the file is opened through (Linux
    // `f_path.mnt`): the resolved mount for FS paths, 0 for anon devices.
    let (inode, mnt_id, created) = if (flags & O_TMPFILE) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        // S_IALLUGO (0o7777): preserve suid/sgid/sticky on O_TMPFILE create (D8).
        let final_mode = (mode & 0o7777 & !umask) as u16;
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
    } else if let Some(vp) = extra_resolved
        .unwrap_or_else(|| crate::pathresolve::resolve_path(path_str, nofollow)) {
        // O_CREAT|O_EXCL: an existing final component is a hard error (Linux
        // `do_last`/`lookup_open`: `if (open_flag & O_EXCL) → -EEXIST`).
        // O_TMPFILE short-circuited above, so this is the ordinary-open path.
        if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
            return -(Errno::Eexist.as_i32() as i64);
        }
        (vp.inode, vp.mnt_id, false)
    } else if (flags & O_CREAT) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        // S_IALLUGO (0o7777): preserve suid/sgid/sticky on O_CREAT (D8).
        let final_mode = mode & 0o7777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, _rel)) => {
                if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                    return -(Errno::Erofs.as_i32() as i64);
                }
                // ext4 D9: create on the RESOLVED PARENT dir inode + leaf name
                // (Linux `filename_create` → `i_op->create`), instead of the
                // whole-path `FileSystem::create` re-splitting the path string.
                // Mirrors `mknod(S_IFREG)`; `final_mode` is already umasked and
                // `apply_umask` is idempotent; owner = caller fsuid/fsgid.
                let (pino, name) = match crate::namei_common::resolve_parent(path_str) {
                    Ok(x) => x, Err(rv) => return rv,
                };
                let cred = crate::pathresolve::current_cred();
                let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
                // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create.
                let r = { let _g = pino.inode_lock(); pino.create_child(&name, final_mode, &ctx) };
                match r {
                    Ok(i) => (i, mnt.mnt_id, true),
                    Err(e) => {
                        crate::namei_common::trace_run_vfs_error(b"openat-create", path_str, e);
                        // D7: surface the real VfsError→errno (EACCES/EROFS/
                        // ENOSPC/ENOTDIR/…) instead of collapsing to ENOENT.
                        return crate::namei_common::errno_from_vfs(e);
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
    // O_CREAT flush: drop the leaf negative planted by the failed existence
    // resolve above so `open_dentry`'s path-walk re-resolves to the NEW inode
    // rather than the stale negative (Linux instantiates the create's own leaf).
    // O_TMPFILE has no directory entry (path is the directory), so it is exempt.
    if created && (flags & O_TMPFILE) == 0 { crate::pathresolve::d_drop_path(path_str); }
    // O_TMPFILE = __O_TMPFILE | O_DIRECTORY, so skip the dir check for it.
    if (flags & O_DIRECTORY) != 0 && (flags & O_TMPFILE) == 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if let Err(e) = inode.on_open() { return -(e as i64); }
    // DAC + EROFS enforcement (Linux `may_open`), before the O_TRUNC truncate.
    if let Some(rv) = enforce_open_perm(&inode, mnt_id, flags, created) { return rv; }
    // Lease-break (Linux `break_lease` in `do_open`): conflicting open signals
    // the lease holder + waits before proceeding. Zero-cost without a lease;
    // skip for a just-created file (cannot hold a pre-existing lease).
    if !created { if let Some(rv) = break_lease_for_open(&inode, flags) { return rv; } }
    // fanotify FAN_OPEN_PERM (fast no-op without perm marks; deny → EACCES).
    if !::fs::inotify::check_open_perm(&inode) { return -(Errno::Eacces.as_i32() as i64); }
    if let Err(rv) = ::security::bpf_lsm::file_open(&inode) { return rv; }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    // D23: controlling-terminal acquisition on open (Linux `tty_open`). A
    // session leader opening a console/serial/VT tty WITHOUT O_NOCTTY, when
    // the tty is unclaimed, makes it the session's controlling terminal.
    console::acquire_ctty_on_open(&inode, flags);
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
    let oflags = OpenFlags::from_bits_truncate(flags) - OpenFlags::O_CLOEXEC;
    // D3/D37: a freshly CREATED inode (incl. O_TMPFILE) carries the build/born
    // `i_count` reference. `open_dentry` bound it to a dentry (`d_add` grab) and
    // `File::new_at` takes the open file's `igrab`; release the born ref once the
    // File's hold is in place (Linux `do_last`/`d_instantiate` consumes the iget
    // ref). Cloned (pointer-only) BEFORE the move into `File::new_at`; iput AFTER
    // → `i_count` never reaches 0 on the live inode. For an O_TMPFILE (nlink==0)
    // the File's hold is then the SOLE holder, so close → 1→0 → evict.
    let created_ref = if created { Some(inode.clone()) } else { None };
    let file = File::new_at(inode, dentry, oflags, mnt_id, crate::pathresolve::current_cred());
    if let Some(i) = created_ref { vfs::file::iput(i); }
    // RLIMIT_NOFILE soft limit caps fd allocation (Linux `__alloc_fd`
    // against `rlimit(RLIMIT_NOFILE)`); exceeding it → EMFILE.
    // SAFETY: rlimits slot single-mutator per `13§5`; cur is the running task on this CPU.
    let nofile = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::NOFILE].0 } as usize;
    match fdt.alloc_limit(file, nofile) {
        Ok(fd)  => {
            if (flags & OpenFlags::O_CLOEXEC.bits()) != 0 {
                if let Err(e) = fdt.set_cloexec(fd, true) { return -(e as i64); }
            }
            fd as i64
        }
        Err(e)  => -(e as i64),
    }
}

#[cfg(feature = "debug-atexit")]
fn dyn_trace_path(s: &str) -> bool {
    s.contains("libselinux")
        || s.contains("libpcre2")
        || s.contains("libaudit")
        || s.contains("libseccomp")
        || s.contains("libpam")
        || s.contains("libsystemd-shared")
}

// 257 openat — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::open_common::{enforce_open_perm, break_lease_for_open, O_CREAT, O_EXCL, O_TRUNC,
    O_DIRECTORY, O_NOFOLLOW, O_TMPFILE, O_PATH};

const DEV_TTY_MAJOR: u32 = 5;
const DEV_TTY_ALIAS_MINOR: u32 = 0;
const DEV_PTMX_MINOR: u32 = 2;
const DEV_TTY_RDEV: u32 = vfs::new_encode_dev(vfs::mkdev(DEV_TTY_MAJOR, DEV_TTY_ALIAS_MINOR));
const DEV_PTMX_RDEV: u32 = vfs::new_encode_dev(vfs::mkdev(DEV_TTY_MAJOR, DEV_PTMX_MINOR));

/// `sys_openat(dirfd, path, flags, mode)` — slot 257. No openat2 RESOLVE_*
/// modifiers (default `LookupFlags`). # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    let rv = open_core(args, vfs::LookupFlags::default());
    #[cfg(feature = "debug-udevdb")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_udevdb_path(b"openat", p.as_str(), rv);
    }
    #[cfg(feature = "debug-boot")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_logind_dev(b"open", p.as_str(), rv);
    }
    rv
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
    let rv = open_core(args, extra);
    #[cfg(feature = "debug-udevdb")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_udevdb_path(b"openat2", p.as_str(), rv);
    }
    rv
}

/// True when any openat2 RESOLVE_* modifier is set (so the resolve path takes
/// the flag-aware route that surfaces EXDEV/ELOOP instead of the legacy
/// collapse-to-ENOENT). # C: O(1)
fn extra_active(x: &vfs::LookupFlags) -> bool {
    x.no_xdev || x.no_magiclinks || x.no_symlinks || x.beneath_exdev || x.in_root || x.cached
}

fn is_chr_rdev(inode: &vfs::InodeRef, rdev: u32) -> bool {
    inode.file_type() == vfs::FileType::CharDev && inode.rdev() == rdev
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
    #[cfg(feature = "debug-openat")]
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
    let landlock_op = {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        op
    };
    // openat2 RESOLVE_*: resolve the existing-file path up-front through the
    // flag-aware resolver so EXDEV (BENEATH/NO_XDEV) / ELOOP (NO_SYMLINKS) /
    // EAGAIN (CACHED) surface to userspace instead of collapsing to ENOENT.
    // BENEATH/IN_ROOT re-base the walk START on the dirfd (resolve_confined).
    let nofollow = (flags & O_NOFOLLOW) != 0;
    let lookup_resolved: Option<vfs::VfsPath> = if extra_active(&extra) {
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
            Ok(p) => Some(p),
            Err(rv) if rv == -(Errno::Enoent.as_i32() as i64) => None,
            Err(rv) => return rv,
        }
    } else {
        let mut lookup = vfs::LookupFlags::default();
        lookup.no_follow_final = nofollow;
        match crate::pathresolve::resolve_at_path(args.a0 as i32, s, lookup) {
            Ok(p) => Some(p),
            Err(rv) if rv == -(Errno::Enoent.as_i32() as i64) => None,
            Err(rv) => return rv,
        }
    };
    // O_TMPFILE short-circuits to anonymous inode creation. Each branch
    // also yields the `mnt_id` the file is opened through (Linux
    // `f_path.mnt`): the resolved mount for FS paths, 0 only for anon fds.
    let (inode, mnt_id, dentry, created, _path_display) = if (flags & O_TMPFILE) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        // S_IALLUGO (0o7777): preserve suid/sgid/sticky on O_TMPFILE create (D8).
        let req_mode = mode & 0o7777;
        // O_TMPFILE creates the anonymous inode on the filesystem that
        // actually backs the target directory — tmpfs for /run|/tmp|/dev/shm,
        // ext4 for the rootfs. Routing every O_TMPFILE to ext4 returned ENOSPC
        // for tmpfs paths, which made journald (O_TMPFILE on /run/log/journal)
        // abort and cascaded to udevd/device units.
        let Some(dir) = lookup_resolved.clone() else { return -(Errno::Enoent.as_i32() as i64); };
        let Some(mnt) = vfs::mount::mount_by_id(dir.mnt_id) else { return -(Errno::Enoent.as_i32() as i64); };
        if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            return -(Errno::Erofs.as_i32() as i64);
        }
        let display = vfs::mount::render_path_for_mount(dir.mnt_id, &dir.dentry);
        if let Err(rv) = crate::landlock::check(&display, landlock_op) { return rv; }
        let cred = crate::pathresolve::current_cred();
        let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
        match dir.inode.tmpfile(req_mode, &ctx) {
            Ok(i)  => {
                let d = dir.dentry;
                (i, mnt.mnt_id, d, true, display)
            }
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        }
    } else if let Some(vp) = lookup_resolved {
        // O_CREAT|O_EXCL: an existing final component is a hard error (Linux
        // `do_last`/`lookup_open`: `if (open_flag & O_EXCL) → -EEXIST`).
        // O_TMPFILE short-circuited above, so this is the ordinary-open path.
        if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
            return -(Errno::Eexist.as_i32() as i64);
        }
        let display = vfs::mount::render_path_for_mount(vp.mnt_id, &vp.dentry);
        if let Err(rv) = crate::landlock::check(&display, landlock_op) { return rv; }
        // `/dev/ptmx` and `/dev/tty` are device identities, not string paths:
        // bind mounts, chroot, and `openat(devfd,"ptmx")` must route the same
        // as `/dev/ptmx`. O_PATH remains a pure path fd and never runs the
        // device-open side effect (PTY allocation / controlling-tty lookup).
        if (flags & O_PATH) == 0 && is_chr_rdev(&vp.inode, DEV_PTMX_RDEV) {
            let (master, _n) = devpts::allocate_pair();
            (master, vp.mnt_id, vp.dentry, false, display)
        } else if (flags & O_PATH) == 0 && is_chr_rdev(&vp.inode, DEV_TTY_RDEV) {
            // F200: caller's controlling terminal; ENXIO when none.
            match sched::live::current() {
                // SAFETY: single-mutator per `13§5` — current task on this CPU.
                Some(t) => match unsafe { (*t.ctty.get()).clone() } {
                    Some(i) => (i, vp.mnt_id, vp.dentry, false, display),
                    None    => return -(Errno::Enxio.as_i32() as i64),
                },
                None => return -(Errno::Enxio.as_i32() as i64),
            }
        } else {
            #[cfg(feature = "debug-cgroup")]
            if display.starts_with("/proc/") && display.ends_with("/cgroup") {
                klog::write_raw(b"[OPENCG ");
                klog::write_raw(display.as_bytes());
                klog::write_raw(b" EXISTS by=");
                if let Some(c) = sched::live::current() {
                    klog::write_dec_u64(c.tid as u64);
                    klog::write_raw(b"/");
                    klog::write_raw(c.name.as_bytes());
                }
                klog::write_raw(b"]\n");
            }
            (vp.inode, vp.mnt_id, vp.dentry, false, display)
        }
    } else if (flags & O_CREAT) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        // S_IALLUGO (0o7777): preserve suid/sgid/sticky on O_CREAT (D8).
        let final_mode = mode & 0o7777 & !umask;
        let parent = match crate::pathresolve::resolve_parent_at(args.a0 as i32, s) {
            Ok(x) => x, Err(rv) => return rv,
        };
        let name = match parent.last_component.clone() {
            Some(n) => n,
            None    => return -(Errno::Einval.as_i32() as i64),
        };
        let Some(mnt) = vfs::mount::mount_by_id(parent.mnt_id) else { return -(Errno::Enoent.as_i32() as i64); };
        if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            return -(Errno::Erofs.as_i32() as i64);
        }
        let create_path = crate::namei_common::render_child_path(&parent, &name);
        if let Err(rv) = crate::landlock::check(&create_path, landlock_op) { return rv; }
        // ext4 D9: create on the RESOLVED PARENT dir inode + leaf name
        // (Linux `filename_create` → `i_op->create`), instead of the
        // old whole-path backend create re-splitting the path string.
        let cred = crate::pathresolve::current_cred();
        let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
        // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create.
        let r = { let _g = parent.inode.inode_lock(); parent.inode.create_child(&name, final_mode, &ctx) };
        match r {
            Ok(i) => {
                let d = vfs::file::open_dentry_at(&parent.dentry, &name, &i);
                crate::namei_common::drop_child_cache(&parent, &name);
                vfs::fire_dirent_create(&parent.inode, &name);
                (i, mnt.mnt_id, d, true, create_path)
            }
            Err(e) => {
                crate::namei_common::trace_run_vfs_error(b"openat-create", &create_path, e);
                // D7: surface the real VfsError→errno (EACCES/EROFS/
                // ENOSPC/ENOTDIR/…) instead of collapsing to ENOENT.
                return crate::namei_common::errno_from_vfs(e);
            }
        }
    } else {
        // DIAG (debug-mount): surface ENOENT opens of the paths whose chase
        // fails the service sandbox (domainname / credentials / RuntimeDir /
        // StateDir), so the exact missing path is visible without flooding.
        #[cfg(feature = "debug-boot")]
        if s.contains("domainname") || s.contains("osrelease")
            || s.contains("cap_last_cap")
        {
            let ns = sched::live::current().map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
            let mut tag = alloc::string::String::from(s);
            tag.push_str(" ns=");
            tag.push_str(&alloc::format!("{}", ns));
            crate::mount_common::mnt_log("openat_ENOENT", &tag, -(Errno::Enoent.as_i32() as i64));
        }
        #[cfg(feature = "debug-mount")]
        if s.starts_with("/run") {
            crate::mount_common::mnt_log("openat_ENOENT", s, -(Errno::Enoent.as_i32() as i64));
        }
        return -(Errno::Enoent.as_i32() as i64);
    };
    #[cfg(any(feature = "debug-atexit", feature = "debug-boot", feature = "debug-eacces"))]
    let path_str = _path_display.as_str();
    #[cfg(feature = "debug-atexit")]
    if dyn_trace_path(path_str) {
        klog::write_raw(b"[DYNOPEN] resolved=");
        klog::write_raw(path_str.as_bytes());
        klog::write_raw(b"\n");
    }
    // O_CREAT cache flush/fsnotify is done in the create branch from the exact
    // resolved parent VfsPath. Re-walking display text here would collapse bind or
    // chroot identity back into display text.
    // O_TMPFILE = __O_TMPFILE | O_DIRECTORY, so skip the dir check for it.
    if (flags & O_DIRECTORY) != 0 && (flags & O_TMPFILE) == 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[ENOTDIR] op=openat why=o_directory-target tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b" flags=");
            klog::write_hex_u64(flags as u64);
            klog::write_raw(b" path=");
            klog::write_raw(path_str.as_bytes());
            klog::write_raw(b"\n");
        }
        return -(Errno::Enotdir.as_i32() as i64);
    }
    // Linux `do_dentry_open`: an O_PATH (FMODE_PATH) descriptor is a pure
    // fd-reference — it NEVER calls `f_op->open`, so the device driver's open is
    // skipped. Our `on_open` IS that driver hook (char/block `->open`), so gating
    // it on !O_PATH matches Linux. Without this, an O_PATH open of a char node
    // whose (major,minor) has no registered driver — e.g. systemd's ProtectKernelLogs
    // inaccessible node `/run/systemd/inaccessible/chr` (devt 0:0) bound over
    // /dev/kmsg — hit `lookup_chrdev` → ENXIO. systemd `mount_entry_chase`
    // O_PATH-opens each mount target during namespace setup, so that ENXIO aborted
    // the whole sandbox (EXIT_NAMESPACE 226 for logind/udevd/… → no graphical target).
    if (flags & O_PATH) == 0 {
        if let Err(e) = inode.on_open() { return -(e as i64); }
    }
    // DAC + EROFS enforcement (Linux `may_open`), before the O_TRUNC truncate.
    if let Some(rv) = enforce_open_perm(&inode, mnt_id, flags, created) {
        #[cfg(feature = "debug-eacces")]
        if rv == -(Errno::Eacces.as_i32() as i64) {
            klog::write_raw(b"[EACCES] openat(may_open) path=\"");
            klog::write_raw(path_str.as_bytes());
            klog::write_raw(b"\" flags=");
            klog::write_hex_u64(flags as u64);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b"\n");
        }
        return rv;
    }
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
    let oflags = OpenFlags::from_bits_truncate(flags) - OpenFlags::O_CLOEXEC;
    // fifo(7): opening a named-pipe (S_IFIFO) inode binds the shared pipe ring
    // to the inode and runs the reader/writer rendezvous (Linux
    // `def_fifo_fops.open = fifo_open`), then this open's data path dispatches
    // through `pipefifo_fops`. Without it a FIFO read hits the backend's stub
    // (tmpfs `TmpfsErrFileOps` → EIO), which is the systemd-initctl failure.
    // O_PATH is a pure fd-reference and never runs the open hook.
    let fifo_fop: Option<alloc::sync::Arc<dyn vfs::FileOps>> =
        if (flags & O_PATH) == 0 && ::fs::pipe::is_named_fifo(&inode) {
            match ::fs::pipe::fifo_open(&inode, flags) {
                Ok(fop) => Some(fop),
                Err(e)  => return -(e as i64),
            }
        } else { None };
    // D3/D37: a freshly CREATED inode (incl. O_TMPFILE) carries the build/born
    // `i_count` reference. The resolved dentry binding holds the dcache ref and
    // `File::new_at` takes the open file's `igrab`; release the born ref once the
    // File's hold is in place (Linux `do_last`/`d_instantiate` consumes the iget
    // ref). Cloned (pointer-only) BEFORE the move into `File::new_at`; iput AFTER
    // → `i_count` never reaches 0 on the live inode. For an O_TMPFILE (nlink==0)
    // the File's hold is then the SOLE holder, so close → 1→0 → evict.
    let created_ref = if created { Some(inode.clone()) } else { None };
    // DIAG (debug-atexit): capture ino before the move so a .so open can be
    // logged — the same path resolving to different inos across calls = lookup race.
    #[cfg(feature = "debug-atexit")]
    let probe_ino = if path_str.contains(".so") { Some(inode.ino()) } else { None };
    let file = match fifo_fop {
        Some(fop) => File::new_at_fop(inode, dentry, oflags, mnt_id, crate::pathresolve::current_cred(), fop),
        None      => File::new_at(inode, dentry, oflags, mnt_id, crate::pathresolve::current_cred()),
    };
    if (flags & O_PATH) == 0 {
        if let Err(e) = file.open_hook() { return -(e as i64); }
    }
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
            #[cfg(feature = "debug-atexit")]
            if let Some(pino) = probe_ino {
                let tail = if path_str.len() > 28 { &path_str[path_str.len() - 28..] } else { path_str };
                klog::write_raw(b"[SOOPEN] tid=");
                klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                klog::write_raw(b" fd=");
                klog::write_dec_u64(fd as u64);
                klog::write_raw(b" ino=");
                klog::write_hex_u64(pino);
                klog::write_raw(b" p=");
                klog::write_raw(tail.as_bytes());
                klog::write_raw(b"\n");
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

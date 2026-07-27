// 257 openat — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::open_common::{enforce_open_perm, break_lease_for_open, normalize_open_flags, O_CREAT, O_EXCL, O_TRUNC,
    O_DIRECTORY, O_EMPTYPATH, O_NOFOLLOW, OPENAT2_REGULAR, O_TMPFILE, O_PATH};

const OPEN_HOW_SIZE_VER0: u64 = 24;
const PAGE_SIZE: u64 = 4096;
const DEV_TTY_MAJOR: u32 = 5;
const DEV_TTY_ALIAS_MINOR: u32 = 0;
const DEV_PTMX_MINOR: u32 = 2;
const DEV_TTY_RDEV: u32 = vfs::new_encode_dev(vfs::mkdev(DEV_TTY_MAJOR, DEV_TTY_ALIAS_MINOR));
const DEV_PTMX_RDEV: u32 = vfs::new_encode_dev(vfs::mkdev(DEV_TTY_MAJOR, DEV_PTMX_MINOR));

/// `sys_openat(dirfd, path, flags, mode)` — slot 257. No openat2 RESOLVE_*
/// modifiers (default `LookupFlags`). # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    let rv = open_core(args, vfs::LookupFlags::default(), false);
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

/// `sys_openat2(dirfd, path, how, size)`. Copies `struct open_how` with Linux
/// size/tail rules, validates `resolve`, and maps it onto `LookupFlags`
/// consumed by the resolver. # C: O(N_path + how_size)
pub fn sys_openat2(args: &SyscallArgs) -> i64 {
    let how = match copy_open_how(args.a2, args.a3) {
        Ok(h) => h, Err(rv) => return rv,
    };
    if how.resolve & !RESOLVE_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    // Linux rejects RESOLVE_BENEATH together with RESOLVE_IN_ROOT.
    if (how.resolve & RESOLVE_BENEATH != 0) && (how.resolve & RESOLVE_IN_ROOT != 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut sa = *args;
    sa.a2 = how.flags;
    sa.a3 = how.mode;
    let extra = vfs::LookupFlags {
        no_xdev:       how.resolve & RESOLVE_NO_XDEV != 0,
        no_magiclinks: how.resolve & RESOLVE_NO_MAGICLINKS != 0,
        no_symlinks:   how.resolve & RESOLVE_NO_SYMLINKS != 0,
        beneath_exdev: how.resolve & RESOLVE_BENEATH != 0,
        in_root:       how.resolve & RESOLVE_IN_ROOT != 0,
        cached:        how.resolve & RESOLVE_CACHED != 0,
        ..Default::default()
    };
    let rv = open_core(&sa, extra, true);
    #[cfg(feature = "debug-udevdb")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_udevdb_path(b"openat2", p.as_str(), rv);
    }
    rv
}

struct OpenHow {
    flags:   u64,
    mode:    u64,
    resolve: u64,
}

fn copy_open_how(ptr: u64, size: u64) -> Result<OpenHow, i64> {
    if size < OPEN_HOW_SIZE_VER0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if size > PAGE_SIZE { return Err(-(Errno::E2big.as_i32() as i64)); }
    validate_user_readable(ptr, size)?;
    // SAFETY: openat2 how span was validated readable for at least 24 bytes; unaligned loads match copy_from_user.
    let flags = unsafe { core::ptr::read_unaligned(ptr as *const u64) };
    // SAFETY: openat2 how span was validated readable for at least 24 bytes; unaligned loads match copy_from_user.
    let mode = unsafe { core::ptr::read_unaligned((ptr + 8) as *const u64) };
    // SAFETY: openat2 how span was validated readable for at least 24 bytes; unaligned loads match copy_from_user.
    let resolve = unsafe { core::ptr::read_unaligned((ptr + 16) as *const u64) };
    if size > OPEN_HOW_SIZE_VER0 {
        let mut p = ptr + OPEN_HOW_SIZE_VER0;
        while p < ptr + size {
            // SAFETY: extension tail byte lies inside the validated readable open_how span.
            if unsafe { core::ptr::read_volatile(p as *const u8) } != 0 {
                return Err(-(Errno::E2big.as_i32() as i64));
            }
            p += 1;
        }
    }
    Ok(OpenHow { flags, mode, resolve })
}

fn validate_user_readable(ptr: u64, len: u64) -> Result<(), i64> {
    use hal::{UserVirtAddr, PAGE_SIZE_BYTES, USER_VA_END};
    use vmm::VmaProt;
    if ptr == 0 { return Err(-(Errno::Efault.as_i32() as i64)); }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    if len == 0 { return Ok(()); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    // SAFETY: current task owns its mm slot during syscall argument copying.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    let mut va = ptr & !(PAGE_SIZE_BYTES - 1);
    let last = (end - 1) & !(PAGE_SIZE_BYTES - 1);
    loop {
        let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
        match mm.find_vma(uva) {
            Some(v) if v.prot.contains(VmaProt::READ) => {}
            _ => return Err(-(Errno::Efault.as_i32() as i64)),
        }
        if va == last { return Ok(()); }
        va = va.checked_add(PAGE_SIZE_BYTES).ok_or(-(Errno::Efault.as_i32() as i64))?;
    }
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
fn open_core(args: &SyscallArgs, extra: vfs::LookupFlags, openat2: bool) -> i64 {
    let rv = open_core_impl(args, extra, openat2);
    // Y3 cgroup-EACCES capture (gated): systemd --user (uid 979) EXIT_CGROUP
    // (code=219). Log the EXACT cgroup path + euid + inode owner that a denied
    // openat hit, to confirm/refute the delegation-chown hypothesis.
    #[cfg(feature = "debug-syscall")]
    if rv == -(Errno::Eacces.as_i32() as i64) {
        if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
            let s: &str = p.as_str();
            if s.contains("cgroup") {
                use core::sync::atomic::Ordering;
                let cur = sched::live::current();
                let (vpid, euid) = match &cur {
                    Some(c) => {
                        let v = c.vtgid.load(Ordering::Acquire);
                        let vpid = if v != 0 { v } else { c.tgid.load(Ordering::Acquire) };
                        (vpid as u64, c.creds.euid.load(Ordering::Acquire) as u64)
                    }
                    None => (0, 0),
                };
                klog::write_raw(b"[CGACC] vpid=");
                klog::write_dec_u64(vpid);
                klog::write_raw(b" euid=");
                klog::write_dec_u64(euid);
                klog::write_raw(b" path=");
                klog::write_raw(s.as_bytes());
                // Inode ownership (delegation-chown probe): resolve the target
                // (it exists, this is a perm denial not ENOENT) and dump its
                // uid/gid/mode. root:root => chown not applied; 979 => applied.
                if let Ok(vp) = crate::pathresolve::resolve_path_raw(s, false) {
                    klog::write_raw(b" ino.uid=");
                    klog::write_dec_u64(vp.inode.uid().unwrap_or(0xFFFF_FFFF) as u64);
                    klog::write_raw(b" ino.gid=");
                    klog::write_dec_u64(vp.inode.gid().unwrap_or(0xFFFF_FFFF) as u64);
                    klog::write_raw(b" ino.mode=");
                    klog::write_hex_u64(vp.inode.i_mode() as u64);
                }
                klog::write_raw(b" rv=-13\n");
            }
        }
    }
    rv
}

fn open_core_impl(args: &SyscallArgs, extra: vfs::LookupFlags, openat2: bool) -> i64 {
    let path_ptr = args.a1;
    let (flags, mode) = match normalize_open_flags(args.a2, args.a3, openat2) {
        Ok(x) => x, Err(rv) => return rv,
    };
    let empty_path = (flags as u64 & O_EMPTYPATH) != 0;
    let regular_only = openat2 && (args.a2 & OPENAT2_REGULAR) != 0;
    if extra.cached && (flags & (O_TRUNC | O_CREAT | O_TMPFILE)) != 0 {
        return -(Errno::Eagain.as_i32() as i64);
    }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match if empty_path {
        crate::mount_common::read_user_path_allow_empty(path_ptr)
    } else {
        crate::namei_common::read_user_path(path_ptr)
    } {
        Ok(p)   => p,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    #[cfg(feature = "debug-zram-lifecycle")]
    crate::signal_trace::zram_lifecycle_openat(s, flags);
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
        lookup.directory = (flags & O_DIRECTORY) != 0;
        lookup.empty = empty_path;
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
        lookup.directory = (flags & O_DIRECTORY) != 0;
        lookup.empty = empty_path;
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
        let umask = cur.umask();
        // S_IALLUGO (0o7777): pass requested suid/sgid/sticky to VFS prepare.
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
        if let Err(rv) = crate::landlock::check(&dir, landlock_op) { return rv; }
        let display = vfs::mount::render_path_for_mount(dir.mnt_id, &dir.dentry);
        let cred = crate::pathresolve::current_cred();
        let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
        match dir.inode.tmpfile(req_mode, &ctx) {
            Ok(i)  => {
                i.set_state(vfs::I_LINKABLE, 0);
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
        if (flags & O_CREAT) != 0 {
            if vp.inode.file_type() == vfs::FileType::Directory {
                return -(Errno::Eisdir.as_i32() as i64);
            }
            if let Some(parent) = vp.dentry.parent().and_then(|d| d.inode()) {
                let cred = crate::pathresolve::current_cred();
                if let Err(e) = vfs::may_create_in_sticky(&parent, &vp.inode, &cred) {
                    return crate::namei_common::errno_from_vfs(e);
                }
            }
        }
        if regular_only && vp.inode.file_type() != vfs::FileType::Regular {
            return -(Errno::Eftype.as_i32() as i64);
        }
        if let Err(rv) = crate::landlock::check(&vp, landlock_op) { return rv; }
        let display = vfs::mount::render_path_for_mount(vp.mnt_id, &vp.dentry);
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
        let umask = cur.umask();
        // S_IALLUGO (0o7777): pass requested suid/sgid/sticky to VFS prepare.
        let final_mode = mode & 0o7777;
        let parent = match crate::pathresolve::resolve_parent_at(args.a0 as i32, s) {
            Ok(x) => x,
            Err(rv) => {
                #[cfg(feature = "debug-eacces")]
                if rv == -(Errno::Eacces.as_i32() as i64) {
                    crate::namei_common::trace_create_resolve_eacces(b"openat-create", s);
                }
                return rv;
            }
        };
        let name = match parent.last_component.clone() {
            Some(n) => n,
            None    => return -(Errno::Einval.as_i32() as i64),
        };
        let Some(mnt) = vfs::mount::mount_by_id(parent.mnt_id) else { return -(Errno::Enoent.as_i32() as i64); };
        if (mnt.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            return -(Errno::Erofs.as_i32() as i64);
        }
        if let Err(rv) = crate::landlock::check_parent(&parent, landlock_op) { return rv; }
        let create_path = crate::namei_common::render_child_path(&parent, &name);
        // ext4 D9: create on the RESOLVED PARENT dir inode + leaf name
        // (Linux `filename_create` → `i_op->create`), instead of the
        // old whole-path backend create re-splitting the path string.
        let cred = crate::pathresolve::current_cred();
        if let Err(e) = vfs::may_create(&parent.inode, &cred) {
            #[cfg(feature = "debug-eacces")]
            if e == vfs::VfsError::Eacces {
                crate::namei_common::trace_create_eacces(b"openat-create", &create_path, &parent.inode, &cred);
            }
            return crate::namei_common::errno_from_vfs(e);
        }
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
            let ns = sched::live::current().and_then(sched::Task::mount_namespace_id).unwrap_or(0);
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
    // Linux `do_dentry_open` runs `f_op->open` once. `install_open_at` owns it so O_PATH can
    // skip it and backends that need `file->private_data` see the final `File`.
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
    let oflags = OpenFlags::from_bits_truncate(flags);
    // RLIMIT_NOFILE soft limit caps fd allocation (Linux `__alloc_fd`
    // against `rlimit(RLIMIT_NOFILE)`); exceeding it → EMFILE.
    let nofile = cur.rlimit(sched::rlimit::rlim::NOFILE).0 as usize;
    let file_cred = match crate::pathresolve::file_cred_for(&cur) {
        Some(cred) => cred, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match vfs::file::install_open_at(&fdt, inode, dentry, oflags, mnt_id,
        file_cred, nofile, fifo_fop)
    {
        Ok(fd)  => {
            if let Some(i) = created_ref { vfs::file::iput(i); }
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
        Err(e)  => {
            if let Some(i) = created_ref { vfs::file::iput(i); }
            -(e as i64)
        }
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

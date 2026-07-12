use alloc::sync::Arc;
use alloc::string::String;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::{FileType, InodeRef};

use crate::inotify::group::make_inotify_inode;
use crate::inotify::types::{
    inode_key, perm_delta, InotifyData, MarkScope, Watch, FAN_ACCESS, FAN_ALL_EVENT_BITS,
    FAN_CLOSE, FAN_FS_ERROR, FAN_MNT_EVENTS, FAN_MODIFY, FAN_ONDIR, FAN_OPEN,
    FAN_OPEN_EXEC, FAN_PRE_ACCESS, FAN_Q_OVERFLOW, FAN_RENAME, IN_ALL_EVENTS,
    IN_EXCL_UNLINK, IN_IGNORED, IN_ONESHOT, IN_Q_OVERFLOW, INOTIFY_MARK_FLAGS,
    MARK_COUNT, PERM_BITS, PERM_MARK_COUNT,
};

const IN_NONBLOCK: u32 = 0o0_004_000;
const IN_CLOEXEC:  u32 = 0o2_000_000;
const IN_INIT_KNOWN: u32 = IN_NONBLOCK | IN_CLOEXEC;
const IN_UNMOUNT:     u32 = 0x0000_2000;
const IN_ONLYDIR:     u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD:    u32 = 0x2000_0000;
const IN_ISDIR:       u32 = 0x4000_0000;
const ALL_INOTIFY_BITS: u32 = IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED
    | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD
    | IN_ISDIR | IN_ONESHOT;

pub(crate) const FAN_CLOEXEC:           u32 = 0x0000_0001;
pub(crate) const FAN_NONBLOCK:          u32 = 0x0000_0002;
pub(crate) const FAN_CLASS_CONTENT:     u32 = 0x0000_0004;
pub(crate) const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
const FAN_ALL_CLASS_BITS:    u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;
const FAN_UNLIMITED_QUEUE:   u32 = 0x0000_0010;
const FAN_UNLIMITED_MARKS:   u32 = 0x0000_0020;
pub(crate) const FAN_ENABLE_AUDIT:      u32 = 0x0000_0040;
const FAN_REPORT_PIDFD:      u32 = 0x0000_0080;
const FAN_REPORT_TID:        u32 = 0x0000_0100;
pub(crate) const FAN_REPORT_FID:        u32 = 0x0000_0200;
pub(crate) const FAN_REPORT_DIR_FID:    u32 = 0x0000_0400;
pub(crate) const FAN_REPORT_NAME:       u32 = 0x0000_0800;
pub(crate) const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
pub(crate) const FAN_REPORT_FD_ERROR:   u32 = 0x0000_2000;
pub(crate) const FAN_REPORT_MNT:        u32 = 0x0000_4000;
const FANOTIFY_FID_BITS: u32 = FAN_REPORT_FID | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID;
const FANOTIFY_ADMIN_INIT_FLAGS: u32 = FAN_ALL_CLASS_BITS | FAN_REPORT_TID
    | FAN_REPORT_PIDFD | FAN_REPORT_FD_ERROR | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;
const FAN_INIT_KNOWN: u32 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS
    | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_PIDFD
    | FAN_REPORT_TID | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME
    | FAN_REPORT_TARGET_FID | FAN_REPORT_FD_ERROR | FAN_REPORT_MNT;
const FANOTIFY_INIT_ALL_EVENT_F_BITS: u32 = 0o3 | 0o2000 | 0o4000 | 0o10000
    | 0o4010000 | 0o2000000 | 0o100000 | 0o1000000;

pub(crate) const FAN_MARK_ADD:                 u32 = 0x0000_0001;
pub(crate) const FAN_MARK_REMOVE:              u32 = 0x0000_0002;
pub(crate) const FAN_MARK_DONT_FOLLOW:         u32 = 0x0000_0004;
pub(crate) const FAN_MARK_ONLYDIR:             u32 = 0x0000_0008;
pub(crate) const FAN_MARK_MOUNT:               u32 = 0x0000_0010;
pub(crate) const FAN_MARK_IGNORED_MASK:        u32 = 0x0000_0020;
pub(crate) const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
pub(crate) const FAN_MARK_FLUSH:               u32 = 0x0000_0080;
pub(crate) const FAN_MARK_FILESYSTEM:          u32 = 0x0000_0100;
pub(crate) const FAN_MARK_EVICTABLE:           u32 = 0x0000_0200;
pub(crate) const FAN_MARK_IGNORE:              u32 = 0x0000_0400;
pub(crate) const FAN_MARK_MNTNS:               u32 = 0x0000_0110;
pub(crate) const FAN_MARK_KNOWN: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM
    | FAN_MARK_EVICTABLE | FAN_MARK_IGNORE;
const FANOTIFY_MARK_TYPE_BITS: u32 = FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM;
const FANOTIFY_MARK_CMD_BITS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;
const FANOTIFY_MARK_IGNORE_BITS: u32 = FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE;
const FANOTIFY_EVENT_FLAGS: u32 = FAN_EVENT_ON_CHILD | FAN_ONDIR;
const FAN_EVENT_ON_CHILD: u32 = 0x0800_0000;
const FANOTIFY_EVENTS: u32 = FAN_ALL_EVENT_BITS & !(PERM_BITS | FANOTIFY_EVENT_FLAGS | FAN_Q_OVERFLOW);
const FANOTIFY_FD_EVENTS: u32 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN
    | FAN_OPEN_EXEC | PERM_BITS;

fn current_cred() -> vfs::Cred {
    let Some(c) = sched::current() else { return vfs::Cred::root(); };
    let eff = c.creds.cap_effective.load(Ordering::Acquire);
    let uid = c.creds.fsuid.load(Ordering::Acquire);
    let gid = c.creds.fsgid.load(Ordering::Acquire);
    let ng = (c.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: groups slot follows the task single-mutator credential rule.
    unsafe {
        let g = &*c.creds.groups.get();
        groups[..ng].copy_from_slice(&g[..ng]);
    }
    let has = |cap: u32| eff & (1u64 << cap) != 0;
    vfs::Cred {
        uid,
        gid,
        cap_dac_override: has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner: has(sched::cap::FOWNER),
        cap_chown: has(sched::cap::CHOWN),
        cap_fsetid: has(sched::cap::FSETID),
        ngroups: ng as u32,
        groups,
    }
}

fn current_start_root() -> Result<(vfs::VfsPath, vfs::VfsPath), i64> {
    let Some(cur) = sched::current() else {
        return Err(-(Errno::Ebadf.as_i32() as i64));
    };
    // SAFETY: current task path slots follow the single-mutator task rule.
    let root = unsafe { (*cur.root_vfs.get()).clone() }
        .ok_or(-(Errno::Eio.as_i32() as i64))?;
    // SAFETY: current task path slots follow the single-mutator task rule.
    let start = unsafe { (*cur.cwd_vfs.get()).clone() }
        .ok_or(-(Errno::Eio.as_i32() as i64))?;
    Ok((start, root))
}

fn decode_watch_path_bytes(bytes: &[u8]) -> Result<String, i64> {
    if bytes.is_empty() {
        return Err(-(Errno::Enoent.as_i32() as i64));
    }
    let path = vfs::path_from_bytes(bytes);
    vfs::path::check_path_len(&path)
        .map_err(|e| -(e as i64))?;
    Ok(path)
}

fn read_watch_path(path_p: u64) -> Result<String, i64> {
    if path_p == 0 || path_p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_p in user range; bounded read through the current address space.
    let bytes = unsafe { devfs::read_user_cstr(path_p, vfs::path::PATH_MAX) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    decode_watch_path_bytes(bytes)
}

fn resolve_watch_path(raw: &str, no_follow_final: bool, only_dir: bool) -> Result<InodeRef, i64> {
    let (start, root) = current_start_root()?;
    resolve_watch_path_at(
        start.dentry,
        start.mnt_id,
        root.dentry,
        root.mnt_id,
        raw,
        no_follow_final,
        only_dir,
        current_cred(),
    )
}

pub(crate) fn resolve_watch_path_at(
    start: Arc<vfs::Dentry>,
    start_mnt_id: u64,
    root: Arc<vfs::Dentry>,
    root_mnt_id: u64,
    raw: &str,
    no_follow_final: bool,
    only_dir: bool,
    cred: vfs::Cred,
) -> Result<InodeRef, i64> {
    let flags = vfs::LookupFlags {
        no_follow_final,
        follow: !no_follow_final,
        directory: only_dir,
        ..Default::default()
    };
    vfs::path_lookup_at_root_cred(
        start,
        start_mnt_id,
        root,
        root_mnt_id,
        raw,
        flags,
        cred,
    ).and_then(|p| {
        vfs::inode_permission(&p.inode, vfs::MAY_READ, &cred)?;
        Ok(p.inode)
    }).map_err(|e| -(e as i64))
}

fn fd_to_inotify(fd: i32) -> Result<Arc<InotifyData>, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let f = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    f.inode().i_private().clone().downcast::<InotifyData>().map_err(|_| Errno::Einval)
}

/// `sys_inotify_init(flags=0)` / `sys_inotify_init1(flags)`.
/// Allocates a fresh InotifyData at the lowest free fd.
/// # C: O(N_fds)
pub fn sys_inotify_init(_args: &syscall::SyscallArgs) -> i64 {
    sys_inotify_init_flags(0)
}

/// Validate `inotify_init1` flags per Linux `do_inotify_init`: only
/// IN_CLOEXEC/O_CLOEXEC and IN_NONBLOCK/O_NONBLOCK are accepted.
/// # C: O(1)
pub(crate) fn validate_inotify_init_flags(flags: u32) -> Result<(), Errno> {
    if flags & !IN_INIT_KNOWN != 0 { return Err(Errno::Einval); }
    Ok(())
}

fn sys_inotify_init_flags(flags: u32) -> i64 {
    use vfs::{File, OpenFlags};
    if let Err(e) = validate_inotify_init_flags(flags) {
        return -(e.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_inotify_inode(InotifyData::new(flags));
    let dentry = vfs::dcache::d_alloc_pseudo("inotify", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDONLY;
    if (flags & IN_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & IN_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_inotify_init1(flags)`.
/// # C: O(N_fds)
pub fn sys_inotify_init1(args: &syscall::SyscallArgs) -> i64 {
    sys_inotify_init_flags(args.a0 as u32)
}

fn current_has_cap(cap: u32) -> bool {
    sched::current().map(|c| c.has_cap(cap)).unwrap_or(false)
}

/// Validate `fanotify_init` inputs per Linux `fanotify_init`: userspace init
/// flags, event-fd flags, class/FID/report-mode dependencies, and capability
/// gates. Returns the errno (>0) or 0 if valid.
/// # C: O(1)
pub(crate) fn validate_fanotify_init_args(
    flags: u32,
    event_f_flags: u32,
    has_sys_admin: bool,
    has_audit_write: bool,
) -> i32 {
    let fid_mode = flags & FANOTIFY_FID_BITS;
    let class = flags & FAN_ALL_CLASS_BITS;
    if ((flags & FANOTIFY_ADMIN_INIT_FLAGS) != 0
        || (flags & (FANOTIFY_FID_BITS | FAN_REPORT_MNT)) == 0)
        && !has_sys_admin {
        return Errno::Eperm.as_i32();
    }
    if flags & !FAN_INIT_KNOWN != 0 { return Errno::Einval.as_i32(); }
    if class == FAN_ALL_CLASS_BITS { return Errno::Einval.as_i32(); }
    if (flags & FAN_REPORT_MNT) != 0 {
        if class != 0 { return Errno::Einval.as_i32(); }
        if flags & (FANOTIFY_FID_BITS | FAN_REPORT_FD_ERROR) != 0 {
            return Errno::Einval.as_i32();
        }
    }
    if event_f_flags & !FANOTIFY_INIT_ALL_EVENT_F_BITS != 0 { return Errno::Einval.as_i32(); }
    if event_f_flags & 0o3 == 0o3 { return Errno::Einval.as_i32(); }
    if fid_mode != 0 && class != 0 { return Errno::Einval.as_i32(); }
    if (fid_mode & FAN_REPORT_NAME) != 0 && (fid_mode & FAN_REPORT_DIR_FID) == 0 {
        return Errno::Einval.as_i32();
    }
    if (fid_mode & FAN_REPORT_TARGET_FID) != 0
        && ((fid_mode & FAN_REPORT_NAME) == 0 || (fid_mode & FAN_REPORT_FID) == 0) {
        return Errno::Einval.as_i32();
    }
    if (flags & FAN_ENABLE_AUDIT) != 0 && !has_audit_write { return Errno::Eperm.as_i32(); }
    0
}

/// Legacy helper retained for hosted tests that only exercise the flag word.
/// # C: O(1)
#[cfg(test)]
pub(crate) fn validate_fanotify_init(flags: u32) -> i32 {
    validate_fanotify_init_args(flags, 0, true, true)
}

/// `sys_fanotify_init(flags, event_f_flags)`. Allocates a fanotify GROUP fd
/// whose read() yields `fanotify_event_metadata`. `flags` carries the class
/// (NOTIF/CONTENT/PRE_CONTENT), FAN_CLOEXEC/FAN_NONBLOCK and the report-fid
/// modifiers; `event_f_flags` is the open mode for minted object fds.
/// # C: O(N_fds)
pub fn sys_fanotify_init(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    let flags = args.a0 as u32;
    let event_f_flags = args.a1 as u32;
    let e = validate_fanotify_init_args(
        flags,
        event_f_flags,
        current_has_cap(sched::cap::SYS_ADMIN),
        current_has_cap(sched::cap::AUDIT_WRITE),
    );
    if e != 0 { return -(e as i64); }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_inotify_inode(InotifyData::new_fanotify(flags));
    let dentry = vfs::dcache::d_alloc_pseudo("[fanotify]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if (flags & FAN_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & FAN_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_inotify_add_watch(fd, pathname, mask)`. Resolves `pathname` through
/// the task VFS root/cwd, records a Watch on the fd's InotifyData, returns wd.
/// # C: O(N_path)
pub fn sys_inotify_add_watch(args: &syscall::SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let path_p = args.a1;
    let mask = args.a2 as u32;
    if let Err(e) = validate_inotify_watch_mask_bits(mask) {
        return -(e.as_i32() as i64);
    }
    let inotify = match fd_to_inotify(fd) {
        Ok(a) => a, Err(e) => return -(e.as_i32() as i64),
    };
    if let Err(e) = validate_inotify_watch_mask_after_fd(mask) {
        return -(e.as_i32() as i64);
    }
    let s = match read_watch_path(path_p) { Ok(s) => s, Err(rv) => return rv };
    let no_follow = (mask & IN_DONT_FOLLOW) != 0;
    let only_dir = (mask & IN_ONLYDIR) != 0;
    let inode = match resolve_watch_path(&s, no_follow, only_dir) {
        Ok(i) => i,
        Err(rv) => {
            #[cfg(feature = "debug-boot")]
            { klog::write_raw(b"[INOTIFY-ENOENT path="); klog::write_raw(s.as_bytes()); klog::write_raw(b"]\n"); }
            return rv;
        }
    };
    let key = inode_key(&inode);
    match add_or_update_watch(&inotify, key, inode.fsid(), mask) {
        Ok(wd) => wd as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// Linux `inotify_add_watch` rejects unknown masks and a zero valid mask before
/// fd lookup.
/// # C: O(1)
pub(crate) fn validate_inotify_watch_mask_bits(mask: u32) -> Result<(), Errno> {
    if mask & !ALL_INOTIFY_BITS != 0 { return Err(Errno::Einval); }
    if mask & ALL_INOTIFY_BITS == 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux checks this combination after the fd exists.
/// # C: O(1)
pub(crate) fn validate_inotify_watch_mask_after_fd(mask: u32) -> Result<(), Errno> {
    if (mask & IN_MASK_ADD) != 0 && (mask & IN_MASK_CREATE) != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Create or update an inode watch with Linux `IN_MASK_ADD`/`IN_MASK_CREATE`
/// semantics. Stores user event bits in the dispatch mask and Linux mark flags
/// (`IN_ONESHOT`, `IN_EXCL_UNLINK`) alongside it.
/// # C: O(N_watches)
pub(crate) fn add_or_update_watch(
    inotify: &Arc<InotifyData>,
    key: usize,
    fsid: u64,
    mask: u32,
) -> Result<i32, Errno> {
    let event_mask = mask & IN_ALL_EVENTS;
    let mark_flags = mask & INOTIFY_MARK_FLAGS;
    let mut g = inotify.watches.lock();
    for w in g.iter_mut() {
        if w.scope == MarkScope::Inode && w.inode_key == key {
            if (mask & IN_MASK_CREATE) != 0 { return Err(Errno::Eexist); }
            if (mask & IN_MASK_ADD) != 0 {
                w.mask |= event_mask;
                w.flags |= mark_flags;
            } else {
                w.mask = event_mask;
                w.flags = mark_flags;
            }
            return Ok(w.wd);
        }
    }
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    g.push(Watch { wd, inode_key: key, fsid, scope: MarkScope::Inode, mask: event_mask, flags: mark_flags, ignored: 0 });
    MARK_COUNT.fetch_add(1, Ordering::AcqRel);
    Ok(wd)
}

/// Remove one watch and queue Linux `IN_IGNORED` for its wd.
/// # C: O(N_watches)
pub(crate) fn remove_watch(inotify: &Arc<InotifyData>, wd: i32) -> Result<(), Errno> {
    let mut g = inotify.watches.lock();
    let Some(pos) = g.iter().position(|w| w.wd == wd) else {
        return Err(Errno::Einval);
    };
    g.remove(pos);
    MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
    inotify.enqueue_event(crate::inotify::types::Event { wd, mask: IN_IGNORED, cookie: 0, len: 0, obj: None, pid: 0 });
    Ok(())
}

/// `sys_inotify_rm_watch(fd, wd)`. Removes the watch from the fd's
/// InotifyData. EINVAL if no such wd.
/// # C: O(N_watches)
pub fn sys_inotify_rm_watch(args: &syscall::SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let wd = args.a1 as i32;
    let inotify = match fd_to_inotify(fd) {
        Ok(a) => a, Err(e) => return -(e.as_i32() as i64),
    };
    match remove_watch(&inotify, wd) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// Scope selected by a `fanotify_mark` flag word (default = inode). # C: O(1)
fn mark_scope(flags: u32) -> Result<MarkScope, Errno> {
    match flags & FANOTIFY_MARK_TYPE_BITS {
        0 => Ok(MarkScope::Inode),
        FAN_MARK_MOUNT => Ok(MarkScope::Mount),
        FAN_MARK_FILESYSTEM => Ok(MarkScope::Filesystem),
        FAN_MARK_MNTNS => Ok(MarkScope::MountNamespace),
        _ => Err(Errno::Einval),
    }
}

/// Linux `do_fanotify_mark` validation before fd lookup.
/// # C: O(1)
pub(crate) fn validate_fanotify_mark_prefd(flags: u32, mask: u64) -> Result<(), Errno> {
    if mask >> 32 != 0 { return Err(Errno::Einval); }
    if flags & !FAN_MARK_KNOWN != 0 { return Err(Errno::Einval); }
    let _ = mark_scope(flags)?;
    let op = flags & FANOTIFY_MARK_CMD_BITS;
    match op {
        FAN_MARK_ADD | FAN_MARK_REMOVE => {
            if mask == 0 { return Err(Errno::Einval); }
        }
        FAN_MARK_FLUSH => {
            if flags & !(FANOTIFY_MARK_TYPE_BITS | FAN_MARK_FLUSH) != 0 {
                return Err(Errno::Einval);
            }
        }
        _ => return Err(Errno::Einval),
    }
    let valid_mask = FANOTIFY_EVENTS | FANOTIFY_EVENT_FLAGS | PERM_BITS;
    if (mask as u32) & !valid_mask != 0 { return Err(Errno::Einval); }
    if flags & FANOTIFY_MARK_IGNORE_BITS == FANOTIFY_MARK_IGNORE_BITS {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Linux `do_fanotify_mark` validation after fd lookup, once group flags and
/// class are known.
/// # C: O(1)
pub(crate) fn validate_fanotify_mark_group(
    group: &InotifyData,
    scope: MarkScope,
    mask: u32,
    flags: u32,
) -> Result<(), Errno> {
    if !group.is_fanotify() { return Err(Errno::Einval); }
    if group.flags & FAN_REPORT_MNT != 0 {
        if mask & !FAN_MNT_EVENTS != 0 { return Err(Errno::Einval); }
        if scope != MarkScope::MountNamespace { return Err(Errno::Einval); }
    } else {
        if mask & FAN_MNT_EVENTS != 0 { return Err(Errno::Einval); }
        if scope == MarkScope::MountNamespace { return Err(Errno::Einval); }
    }
    let class = group.flags & FAN_ALL_CLASS_BITS;
    if mask & PERM_BITS != 0 && class == 0 { return Err(Errno::Einval); }
    if mask & FAN_PRE_ACCESS != 0 && class == FAN_CLASS_CONTENT { return Err(Errno::Einval); }
    if mask & FAN_FS_ERROR != 0 && scope != MarkScope::Filesystem { return Err(Errno::Einval); }
    if flags & FAN_MARK_EVICTABLE != 0 && scope != MarkScope::Inode {
        return Err(Errno::Einval);
    }
    let fid_mode = group.flags & FANOTIFY_FID_BITS;
    if mask & !(FANOTIFY_FD_EVENTS | FAN_MNT_EVENTS | FANOTIFY_EVENT_FLAGS) != 0
        && (fid_mode == 0 || scope == MarkScope::Mount) {
        return Err(Errno::Einval);
    }
    if mask & FAN_RENAME != 0 && fid_mode & FAN_REPORT_NAME == 0 {
        return Err(Errno::Einval);
    }
    if mask & FAN_PRE_ACCESS != 0 && mask & FAN_ONDIR != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Apply a parsed ADD/REMOVE mark to a group. `add`: ADD vs REMOVE; `ignored`:
/// the bits edit the per-mark ignore set (`FAN_MARK_IGNORED_MASK`) instead of
/// the event mask. Coalesces onto an existing same-scope/same-object mark;
/// a REMOVE that empties both masks retires the mark. Maintains MARK_COUNT +
/// PERM_MARK_COUNT. Returns 0 or the errno. # C: O(N_watches)
pub(crate) fn apply_mark(inotify: &Arc<InotifyData>, scope: MarkScope, key: usize, fsid: u64,
                         bits: u32, add: bool, ignored: bool) -> i64 {
    let mut g = inotify.watches.lock();
    let same = |w: &Watch| w.scope == scope
        && (if scope == MarkScope::Inode { w.inode_key == key } else { w.fsid == fsid });
    if let Some(i) = g.iter().position(|w| same(w)) {
        let old = g[i].mask;
        if ignored {
            if add { g[i].ignored |= bits; } else { g[i].ignored &= !bits; }
        } else if add { g[i].mask |= bits; } else { g[i].mask &= !bits; }
        perm_delta(old, g[i].mask);
        if g[i].mask == 0 && g[i].ignored == 0 {
            g.remove(i);
            MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
        }
        return 0;
    }
    if !add { return -(Errno::Enoent.as_i32() as i64); }
    let (mask, ign) = if ignored { (0, bits) } else { (bits, 0) };
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    g.push(Watch { wd, inode_key: key, fsid, scope, mask, flags: 0, ignored: ign });
    MARK_COUNT.fetch_add(1, Ordering::AcqRel);
    perm_delta(0, mask);
    0
}

/// `sys_fanotify_mark(fd, flags, mask, dirfd, pathname)` — slot 301. Adds /
/// removes / flushes an inode-, mount-, or filesystem-scope mark (Linux
/// `do_fanotify_mark`). # C: O(N_watches)
pub fn sys_fanotify_mark(args: &syscall::SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let flags = args.a1 as u32;
    let mask64 = args.a2;
    let _dirfd = args.a3 as i32;
    let path_p = args.a4;
    if let Err(e) = validate_fanotify_mark_prefd(flags, mask64) {
        return -(e.as_i32() as i64);
    }
    let mask = mask64 as u32;
    let inotify = match fd_to_inotify(fd) {
        Ok(a) => a, Err(e) => return -(e.as_i32() as i64),
    };
    let scope = match mark_scope(flags) {
        Ok(s) => s,
        Err(e) => return -(e.as_i32() as i64),
    };
    if let Err(e) = validate_fanotify_mark_group(&inotify, scope, mask, flags) {
        return -(e.as_i32() as i64);
    }
    let ignored = flags & (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE) != 0;
    if flags & FAN_MARK_FLUSH != 0 {
        let mut g = inotify.watches.lock();
        let (mut removed, mut perms) = (0usize, 0usize);
        g.retain(|w| {
            if w.scope == scope { removed += 1; if w.mask & PERM_BITS != 0 { perms += 1; } false }
            else { true }
        });
        if removed > 0 { MARK_COUNT.fetch_sub(removed, Ordering::AcqRel); }
        if perms > 0 { PERM_MARK_COUNT.fetch_sub(perms, Ordering::AcqRel); }
        return 0;
    }
    let bits = mask & FAN_ALL_EVENT_BITS;
    if bits == 0 { return -(Errno::Einval.as_i32() as i64); }
    let s = match read_watch_path(path_p) { Ok(s) => s, Err(rv) => return rv };
    let inode = match resolve_watch_path(&s, flags & FAN_MARK_DONT_FOLLOW != 0, false) {
        Ok(i) => i,
        Err(rv) => {
            #[cfg(feature = "debug-boot")]
            { klog::write_raw(b"[INOTIFY-ENOENT path="); klog::write_raw(s.as_bytes()); klog::write_raw(b"]\n"); }
            return rv;
        }
    };
    if flags & FAN_MARK_ONLYDIR != 0 && inode.file_type() != FileType::Directory {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let (key, fsid) = (inode_key(&inode), inode.fsid());
    apply_mark(&inotify, scope, key, fsid, bits, flags & FAN_MARK_ADD != 0, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_path_decode_preserves_non_utf8_bytes() {
        let s = decode_watch_path_bytes(b"/tmp/raw-\xff").unwrap();
        assert_eq!(vfs::path_into_bytes(&s), b"/tmp/raw-\xff");
    }

    #[test]
    fn watch_path_decode_rejects_empty_with_enoent() {
        assert_eq!(decode_watch_path_bytes(b""), Err(-(Errno::Enoent.as_i32() as i64)));
    }

    #[test]
    fn watch_path_decode_rejects_pathmax_bytes() {
        let long = alloc::vec![b'a'; vfs::path::PATH_MAX];
        assert_eq!(decode_watch_path_bytes(&long), Err(-(Errno::Enametoolong.as_i32() as i64)));
    }
}

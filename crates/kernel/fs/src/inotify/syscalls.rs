use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::{FileType, InodeRef};

use crate::inotify::group::make_inotify_inode;
use crate::inotify::types::{
    inode_key, perm_delta, InotifyData, MarkScope, Watch, FAN_ALL_EVENT_BITS, MARK_COUNT, PERM_BITS,
    PERM_MARK_COUNT,
};

const IN_NONBLOCK: u32 = 0o0_004_000;
const IN_CLOEXEC:  u32 = 0o2_000_000;

pub(crate) const FAN_CLOEXEC:           u32 = 0x0000_0001;
pub(crate) const FAN_NONBLOCK:          u32 = 0x0000_0002;
pub(crate) const FAN_CLASS_CONTENT:     u32 = 0x0000_0004;
pub(crate) const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
const FAN_ALL_CLASS_BITS:    u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;
const FAN_UNLIMITED_QUEUE:   u32 = 0x0000_0010;
const FAN_UNLIMITED_MARKS:   u32 = 0x0000_0020;
const FAN_ENABLE_AUDIT:      u32 = 0x0000_0040;
const FAN_REPORT_PIDFD:      u32 = 0x0000_0080;
const FAN_REPORT_TID:        u32 = 0x0000_0100;
const FAN_REPORT_FID:        u32 = 0x0000_0200;
pub(crate) const FAN_REPORT_DIR_FID:    u32 = 0x0000_0400;
pub(crate) const FAN_REPORT_NAME:       u32 = 0x0000_0800;
const FAN_INIT_KNOWN: u32 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS
    | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_PIDFD
    | FAN_REPORT_TID | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

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
pub(crate) const FAN_MARK_KNOWN: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM
    | FAN_MARK_EVICTABLE | FAN_MARK_IGNORE;

fn resolve_watch_path(raw: &str) -> Option<InodeRef> {
    let resolved = if raw.starts_with('/') {
        vfs::path::lexical_normalize(raw)?
    } else if let Some(cur) = sched::current() {
        // SAFETY: current task is the sole writer of its cwd slot on this CPU.
        let cwd = unsafe { (*cur.cwd.get()).clone() };
        vfs::path::resolve_against_cwd(&cwd, raw)?
    } else {
        raw.into()
    };
    vfs::mount::lookup(&resolved).ok()
}

fn fd_to_inotify(fd: i32) -> Option<Arc<InotifyData>> {
    let cur = sched::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(fd).ok()?;
    f.inode().i_private().clone().downcast::<InotifyData>().ok()
}

/// `sys_inotify_init(flags=0)` / `sys_inotify_init1(flags)`.
/// Allocates a fresh InotifyData at the lowest free fd.
/// # C: O(N_fds)
pub fn sys_inotify_init1(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    let flags = args.a0 as u32;
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

/// Validate a `fanotify_init` flag word the Linux way (`do_fanotify_init`):
/// reject unknown bits, an impossible class (`0xc`), and FAN_REPORT_NAME
/// without FAN_REPORT_DIR_FID. Returns the errno (>0) or 0 if valid.
/// # C: O(1)
pub(crate) fn validate_fanotify_init(flags: u32) -> i32 {
    if flags & !FAN_INIT_KNOWN != 0 { return Errno::Einval.as_i32(); }
    if flags & FAN_ALL_CLASS_BITS == FAN_ALL_CLASS_BITS { return Errno::Einval.as_i32(); }
    if flags & FAN_REPORT_NAME != 0 && flags & FAN_REPORT_DIR_FID == 0 {
        return Errno::Einval.as_i32();
    }
    0
}

/// `sys_fanotify_init(flags, event_f_flags)`. Allocates a fanotify GROUP fd
/// whose read() yields `fanotify_event_metadata`. `flags` carries the class
/// (NOTIF/CONTENT/PRE_CONTENT), FAN_CLOEXEC/FAN_NONBLOCK and the report-fid
/// modifiers; `event_f_flags` is the open mode for minted object fds.
/// # C: O(N_fds)
pub fn sys_fanotify_init(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    let flags = args.a0 as u32;
    let e = validate_fanotify_init(flags);
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

/// `sys_inotify_add_watch(fd, pathname, mask)`. Resolves `pathname`
/// via devfs, records a Watch on the fd's InotifyData, returns the wd.
/// # C: O(N_path)
pub fn sys_inotify_add_watch(args: &syscall::SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let path_p = args.a1;
    let mask = args.a2 as u32;
    let inotify = match fd_to_inotify(fd) {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    if path_p == 0 || path_p >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: path_p in user range; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(path_p, 256) };
    let s = match bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match resolve_watch_path(s) {
        Some(i) => i, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let key = inode_key(&inode);
    let mut g = inotify.watches.lock();
    for w in g.iter_mut() {
        if w.scope == MarkScope::Inode && w.inode_key == key {
            w.mask = mask;
            return w.wd as i64;
        }
    }
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    g.push(Watch { wd, inode_key: key, fsid: 0, scope: MarkScope::Inode, mask, ignored: 0 });
    MARK_COUNT.fetch_add(1, Ordering::AcqRel);
    wd as i64
}

/// `sys_inotify_rm_watch(fd, wd)`. Removes the watch from the fd's
/// InotifyData. EINVAL if no such wd.
/// # C: O(N_watches)
pub fn sys_inotify_rm_watch(args: &syscall::SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let wd = args.a1 as i32;
    let inotify = match fd_to_inotify(fd) {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut g = inotify.watches.lock();
    let n_before = g.len();
    g.retain(|w| w.wd != wd);
    let removed = n_before - g.len();
    if removed > 0 { MARK_COUNT.fetch_sub(removed, Ordering::AcqRel); }
    if removed == 0 { -(Errno::Einval.as_i32() as i64) } else { 0 }
}

/// Scope selected by a `fanotify_mark` flag word (default = inode). # C: O(1)
fn mark_scope(flags: u32) -> MarkScope {
    if flags & FAN_MARK_FILESYSTEM != 0 { MarkScope::Filesystem }
    else if flags & FAN_MARK_MOUNT != 0 { MarkScope::Mount }
    else { MarkScope::Inode }
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
    g.push(Watch { wd, inode_key: key, fsid, scope, mask, ignored: ign });
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
    let mask = args.a2 as u32;
    let _dirfd = args.a3 as i32;
    let path_p = args.a4;
    if flags & !FAN_MARK_KNOWN != 0 { return -(Errno::Einval.as_i32() as i64); }
    let op = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
    if op.count_ones() != 1 { return -(Errno::Einval.as_i32() as i64); }
    if flags & FAN_MARK_MOUNT != 0 && flags & FAN_MARK_FILESYSTEM != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inotify = match fd_to_inotify(fd) {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    let scope = mark_scope(flags);
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
    if path_p == 0 || path_p >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: path_p in user range; bounded read via existing helper.
    let s = match unsafe { devfs::read_user_cstr(path_p, 256) }
        .and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match resolve_watch_path(s) {
        Some(i) => i, None => return -(Errno::Enoent.as_i32() as i64),
    };
    if flags & FAN_MARK_ONLYDIR != 0 && inode.file_type() != FileType::Directory {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let (key, fsid) = (inode_key(&inode), inode.fsid());
    apply_mark(&inotify, scope, key, fsid, bits, flags & FAN_MARK_ADD != 0, ignored)
}

use alloc::sync::Arc;
use alloc::string::String;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::FileType;

use crate::inotify::group::make_inotify_inode;
use crate::inotify::path::resolve_watch_path;
use crate::inotify::types::{
    inode_key, perm_delta, InotifyData, MarkScope, Watch, FAN_ALL_EVENT_BITS, FAN_EVENT_ON_CHILD,
    IN_ALL_EVENTS, IN_IGNORED, INOTIFY_MARK_FLAGS,
    MARK_COUNT, MNTNS_MARK_COUNT, PERM_BITS, PERM_MARK_COUNT,
};
use crate::inotify::validate::*;

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
    let bytes = devfs::read_user_cstr(path_p, vfs::path::PATH_MAX)
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    decode_watch_path_bytes(&bytes)
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
    // `inotify_new_group`: the per-user instance ceiling is charged BEFORE the
    // fd is minted, and its failure is EMFILE — not the ENFILE/EMFILE the fd
    // table would raise. `InotifyData::Drop` releases the charge.
    let uid = current_euid();
    if !vfs::fsnotify::inc_ucount(uid, vfs::fsnotify::Ucount::InotifyInstances) {
        return -(Errno::Emfile.as_i32() as i64);
    }
    let inode = make_inotify_inode(InotifyData::new_owned(flags, false, uid, 0));
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

/// `current_euid()` — the ucount key a group's instance/mark charges are held
/// against. # C: O(1)
fn current_euid() -> u32 {
    sched::current().map(|c| c.creds.euid.load(Ordering::Acquire)).unwrap_or(0)
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
    );
    if e != 0 { return -(e as i64); }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // `inc_ucount(UCOUNT_FANOTIFY_GROUPS)` sits between the argument checks and
    // the group-construction checks, so an exhausted user sees EMFILE even for
    // a flag word the later checks would have rejected.
    let uid = current_euid();
    if !vfs::fsnotify::inc_ucount(uid, vfs::fsnotify::Ucount::FanotifyGroups) {
        return -(Errno::Emfile.as_i32() as i64);
    }
    let data = InotifyData::new_owned(flags, true, uid, event_f_flags);
    let e = validate_fanotify_init_post_charge(flags, current_has_cap(sched::cap::AUDIT_WRITE));
    if e != 0 { return -(e as i64); }
    let inode = make_inotify_inode(data);
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
            #[cfg(feature = "debug-inotify")]
            { klog::write_raw(b"[INOTIFY-ENOENT path="); klog::write_raw(s.as_bytes()); klog::write_raw(b"]\n"); }
            return rv;
        }
    };
    let key = inode_key(&inode);
    let is_dir = inode.file_type() == FileType::Directory;
    match add_or_update_watch(&inotify, key, inode.fsid(), mask, is_dir, Some(&inode)) {
        Ok(wd) => wd as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// `inotify_arg_to_mask`: the mark's stored mask is not what the caller asked
/// for. Every mark also receives the unmount notice regardless, and a mark on a
/// DIRECTORY watches its children — which is why inotify never needed a
/// `FAN_EVENT_ON_CHILD` of its own, and why a mark that omits the bit would
/// stop reporting anything about the files inside a watched directory.
/// # C: O(1)
pub(crate) fn inotify_arg_to_mask(arg: u32, is_dir: bool) -> u32 {
    let mut mask = arg & IN_ALL_EVENTS;
    if is_dir { mask |= FAN_EVENT_ON_CHILD; }
    mask
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
    is_dir: bool,
    pin: Option<&vfs::InodeRef>,
) -> Result<i32, Errno> {
    let event_mask = inotify_arg_to_mask(mask, is_dir);
    let mark_flags = mask & INOTIFY_MARK_FLAGS;
    let mut g = inotify.watches.lock();
    for w in g.iter_mut() {
        if w.scope == MarkScope::Inode && w.inode_key == key {
            if (mask & IN_MASK_CREATE) != 0 { return Err(Errno::Eexist); }
            if (mask & IN_MASK_ADD) != 0 {
                w.replace_mask(w.mask | event_mask);
                w.flags |= mark_flags;
            } else {
                w.replace_mask(event_mask);
                w.flags = mark_flags;
            }
            return Ok(w.wd);
        }
    }
    // `inotify_new_watch`: the wd is allocated first, then the per-user watch
    // ceiling is charged; failing it unwinds the wd and reports ENOSPC.
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    if !inotify.charge_mark() { return Err(Errno::Enospc); }
    // An inotify watch is never evictable: it pins the inode it watches, which
    // is why one watch is budgeted against the per-user ceiling at the cost of
    // a resident inode.
    g.push(Watch::new(wd, key, fsid, 0, MarkScope::Inode, event_mask, mark_flags,
                      0, false, false, pin, pin));
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
    let mut dead = g.remove(pos);
    let pin = dead.take_pin();
    drop(g);
    crate::inotify::types::release_pins(pin.into_iter().collect());
    inotify.release_marks(1);
    MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
    inotify.enqueue_event(crate::inotify::types::Event { wd, mask: IN_IGNORED, cookie: 0, name: alloc::vec::Vec::new(), obj: None, pid: 0, ..Default::default() });
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

/// Apply a parsed ADD/REMOVE mark to a group. `add`: ADD vs REMOVE; `ignored`:
/// the bits edit the per-mark ignore set (`FAN_MARK_IGNORED_MASK`) instead of
/// the event mask. Coalesces onto an existing same-scope/same-object mark;
/// a REMOVE that empties both masks retires the mark. Maintains MARK_COUNT +
/// PERM_MARK_COUNT. Returns 0 or the errno. # C: O(N_watches)
pub(crate) fn apply_mark(inotify: &Arc<InotifyData>, scope: MarkScope, key: usize, fsid: u64,
                         bits: u32, add: bool, ignored: bool, mflags: u32) -> i64 {
    apply_mark_ns(inotify, scope, key, fsid, 0, bits, add, ignored, mflags, None, None)
}

/// [`apply_mark`] for an INODE-scope mark, which pins the inode it is attached
/// to unless the caller asked for `FAN_MARK_EVICTABLE`. This is the arm
/// `fanotify_mark` takes for a default-scope mark; the key/fsid arms exist for
/// the scopes that have no inode. # C: O(N_watches)
pub(crate) fn apply_inode_mark(inotify: &Arc<InotifyData>, inode: &vfs::InodeRef,
                               bits: u32, add: bool, ignored: bool, mflags: u32) -> i64 {
    let pin = if mflags & FAN_MARK_EVICTABLE != 0 { None } else { Some(inode) };
    apply_mark_ns(inotify, MarkScope::Inode, inode_key(inode), inode.fsid(), 0,
                  bits, add, ignored, mflags, pin, Some(inode))
}

/// [`apply_mark`] for a mark whose object is a MOUNT NAMESPACE (`ns_id`), which
/// no inode key or `fsid` identifies. # C: O(N_watches)
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_mark_ns(inotify: &Arc<InotifyData>, scope: MarkScope, key: usize, fsid: u64,
                            ns_id: u64, bits: u32, add: bool, ignored: bool, mflags: u32,
                            pin: Option<&vfs::InodeRef>, target: Option<&vfs::InodeRef>) -> i64 {
    // `FAN_MARK_IGNORE` means the event flags in the ignore set mean what they
    // say; the legacy `FAN_MARK_IGNORED_MASK` has them reinterpreted (`mask`).
    let ignore_has_flags = mflags & FAN_MARK_IGNORE != 0;
    let survives = mflags & FAN_MARK_IGNORED_SURV_MODIFY != 0;
    let mut released: alloc::vec::Vec<vfs::InodeRef> = alloc::vec::Vec::new();
    let mut g = inotify.watches.lock();
    let same = |w: &Watch| w.scope == scope && match scope {
        MarkScope::Inode => w.inode_key == key,
        MarkScope::MountNamespace => w.ns_id == ns_id,
        _ => w.fsid == fsid,
    };
    if let Some(i) = g.iter().position(|w| same(w)) {
        let old = g[i].mask;
        let mut new_mask = old;
        if ignored {
            if add { g[i].ignored |= bits; } else { g[i].ignored &= !bits; }
        } else if add { new_mask |= bits; } else { new_mask &= !bits; }
        if !ignored { g[i].replace_mask(new_mask); }
        if ignored && add {
            g[i].ignore_has_flags = ignore_has_flags;
            g[i].ignore_survives_modify = survives;
        }
        // An ADD restates whether the mark pins its object, so a mark that
        // gains `FAN_MARK_EVICTABLE` gives its reference up and one that loses
        // it takes a fresh reference.
        if add { released.extend(g[i].repin(pin)); }
        perm_delta(old, g[i].mask);
        if g[i].mask == 0 && g[i].ignored == 0 {
            let mut dead = g.remove(i);
            released.extend(dead.take_pin());
            MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
            if scope == MarkScope::MountNamespace { MNTNS_MARK_COUNT.fetch_sub(1, Ordering::AcqRel); }
            drop(g);
            crate::inotify::types::release_pins(released);
            inotify.release_marks(1);
            return 0;
        }
        drop(g);
        crate::inotify::types::release_pins(released);
        return 0;
    }
    if !add { return -(Errno::Enoent.as_i32() as i64); }
    // `fanotify_add_new_mark`: the per-user mark ceiling is charged before the
    // mark exists; over it, ENOSPC.
    if !inotify.charge_mark() { return -(Errno::Enospc.as_i32() as i64); }
    let (mask, ign) = if ignored { (0, bits) } else { (bits, 0) };
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    g.push(Watch::new(wd, key, fsid, ns_id, scope, mask, 0, ign,
                      ignored && ignore_has_flags, ignored && survives, pin, target));
    MARK_COUNT.fetch_add(1, Ordering::AcqRel);
    if scope == MarkScope::MountNamespace { MNTNS_MARK_COUNT.fetch_add(1, Ordering::AcqRel); }
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
    if let Err(e) = validate_fanotify_mark_group(&inotify, scope, mask, flags,
                                                 current_has_cap(sched::cap::SYS_ADMIN)) {
        return -(e.as_i32() as i64);
    }
    let ignored = flags & (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE) != 0;
    if flags & FAN_MARK_FLUSH != 0 {
        let mut g = inotify.watches.lock();
        let (mut removed, mut perms) = (0usize, 0usize);
        let mut pins: alloc::vec::Vec<vfs::InodeRef> = alloc::vec::Vec::new();
        let mut i = 0usize;
        while i < g.len() {
            if g[i].scope != scope { i += 1; continue; }
            removed += 1;
            if g[i].mask & PERM_BITS != 0 { perms += 1; }
            let mut dead = g.remove(i);
            pins.extend(dead.take_pin());
        }
        drop(g);
        crate::inotify::types::release_pins(pins);
        if removed > 0 { MARK_COUNT.fetch_sub(removed, Ordering::AcqRel); }
        if perms > 0 { PERM_MARK_COUNT.fetch_sub(perms, Ordering::AcqRel); }
        if removed > 0 && scope == MarkScope::MountNamespace {
            MNTNS_MARK_COUNT.fetch_sub(removed, Ordering::AcqRel);
        }
        inotify.release_marks(removed);
        return 0;
    }
    let bits = mask & FAN_ALL_EVENT_BITS;
    if bits == 0 { return -(Errno::Einval.as_i32() as i64); }
    let s = match read_watch_path(path_p) { Ok(s) => s, Err(rv) => return rv };
    let inode = match resolve_watch_path(&s, flags & FAN_MARK_DONT_FOLLOW != 0, false) {
        Ok(i) => i,
        Err(rv) => {
            #[cfg(feature = "debug-inotify")]
            { klog::write_raw(b"[INOTIFY-ENOENT path="); klog::write_raw(s.as_bytes()); klog::write_raw(b"]\n"); }
            return rv;
        }
    };
    if flags & FAN_MARK_ONLYDIR != 0 && inode.file_type() != FileType::Directory {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    // A mount-namespace mark names the namespace its path resolves to, not the
    // node it resolved through: the object the mark attaches to is the mount
    // namespace itself, so a path that is not a mount-namespace node names no
    // object at all and the call is rejected.
    if scope == MarkScope::MountNamespace {
        let Some(ns) = mnt_ns_from_inode(&inode) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        return apply_mark_ns(&inotify, scope, 0, 0, ns, bits,
                             flags & FAN_MARK_ADD != 0, ignored, flags, None, None);
    }
    if scope == MarkScope::Inode {
        return apply_inode_mark(&inotify, &inode, bits, flags & FAN_MARK_ADD != 0, ignored, flags);
    }
    let (key, fsid) = (inode_key(&inode), inode.fsid());
    apply_mark(&inotify, scope, key, fsid, bits, flags & FAN_MARK_ADD != 0, ignored, flags)
}

/// The mount namespace a resolved path names, or `None` when the path is not a
/// mount-namespace node. The identity handed back is the namespace's own id —
/// the same key the mount tree stamps on every mount it owns — so a mark and
/// the mounts it will hear about agree by construction rather than through a
/// second table mapping one to the other. # C: O(1)
pub(crate) fn mnt_ns_from_inode(inode: &vfs::InodeRef) -> Option<u64> {
    let ns = inode.private::<nscg::proc_ns::NsInode>()?;
    if ns.kind != nscg::proc_ns::NsKind::Mnt { return None; }
    match ns.owner() {
        nscg::NsOwner::Mnt(m) => Some(m.id()),
        _ => None,
    }
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

use syscall::errno::Errno;

use crate::inotify::types::{
    InotifyData, MarkScope, FAN_ACCESS, FAN_ALL_EVENT_BITS, FAN_CLOSE, FAN_FS_ERROR,
    FAN_MNT_EVENTS, FAN_MODIFY, FAN_ONDIR, FAN_OPEN, FAN_OPEN_EXEC, FAN_PRE_ACCESS,
    FAN_Q_OVERFLOW, FAN_RENAME, IN_ALL_EVENTS, IN_EXCL_UNLINK, IN_IGNORED, IN_ONESHOT,
    IN_Q_OVERFLOW, PERM_BITS,
};

pub(super) const IN_NONBLOCK: u32 = 0o0_004_000;
pub(super) const IN_CLOEXEC:  u32 = 0o2_000_000;
const IN_INIT_KNOWN: u32 = IN_NONBLOCK | IN_CLOEXEC;
const IN_UNMOUNT:     u32 = 0x0000_2000;
pub(super) const IN_ONLYDIR:     u32 = 0x0100_0000;
pub(super) const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub(super) const IN_MASK_CREATE: u32 = 0x1000_0000;
pub(super) const IN_MASK_ADD:    u32 = 0x2000_0000;
const IN_ISDIR:       u32 = 0x4000_0000;
const ALL_INOTIFY_BITS: u32 = IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED
    | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD
    | IN_ISDIR | IN_ONESHOT;

pub(crate) const FAN_CLOEXEC:           u32 = 0x0000_0001;
pub(crate) const FAN_NONBLOCK:          u32 = 0x0000_0002;
pub(crate) const FAN_CLASS_CONTENT:     u32 = 0x0000_0004;
pub(crate) const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
pub(super) const FAN_ALL_CLASS_BITS:    u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;
pub(crate) const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub(crate) const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub(crate) const FAN_ENABLE_AUDIT:      u32 = 0x0000_0040;
const FAN_REPORT_PIDFD:      u32 = 0x0000_0080;
const FAN_REPORT_TID:        u32 = 0x0000_0100;
pub(crate) const FAN_REPORT_FID:        u32 = 0x0000_0200;
pub(crate) const FAN_REPORT_DIR_FID:    u32 = 0x0000_0400;
pub(crate) const FAN_REPORT_NAME:       u32 = 0x0000_0800;
pub(crate) const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
pub(crate) const FAN_REPORT_FD_ERROR:   u32 = 0x0000_2000;
pub(crate) const FAN_REPORT_MNT:        u32 = 0x0000_4000;
pub(super) const FANOTIFY_FID_BITS: u32 = FAN_REPORT_FID | FAN_REPORT_DIR_FID
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
pub(super) const FANOTIFY_MARK_TYPE_BITS: u32 = FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM;
pub(super) const FANOTIFY_MARK_CMD_BITS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;
pub(super) const FANOTIFY_MARK_IGNORE_BITS: u32 = FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE;
pub(super) const FANOTIFY_EVENT_FLAGS: u32 = FAN_EVENT_ON_CHILD | FAN_ONDIR;
const FAN_EVENT_ON_CHILD: u32 = 0x0800_0000;
pub(super) const FANOTIFY_EVENTS: u32 = FAN_ALL_EVENT_BITS & !(PERM_BITS | FANOTIFY_EVENT_FLAGS | FAN_Q_OVERFLOW);
pub(super) const FANOTIFY_FD_EVENTS: u32 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN
    | FAN_OPEN_EXEC | PERM_BITS;

/// Validate `inotify_init1` flags per Linux `do_inotify_init`: only
/// IN_CLOEXEC/O_CLOEXEC and IN_NONBLOCK/O_NONBLOCK are accepted.
/// # C: O(1)
pub(crate) fn validate_inotify_init_flags(flags: u32) -> Result<(), Errno> {
    if flags & !IN_INIT_KNOWN != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Validate `fanotify_init` inputs per Linux `fanotify_init`: userspace init
/// flags, event-fd flags, class/FID/report-mode dependencies, and capability
/// gates. Returns the errno (>0) or 0 if valid.
/// # C: O(1)
pub(crate) fn validate_fanotify_init_args(
    flags: u32,
    event_f_flags: u32,
    has_sys_admin: bool,
) -> i32 {
    let fid_mode = flags & FANOTIFY_FID_BITS;
    let class = flags & FAN_ALL_CLASS_BITS;
    if ((flags & FANOTIFY_ADMIN_INIT_FLAGS) != 0
        || (flags & (FANOTIFY_FID_BITS | FAN_REPORT_MNT)) == 0)
        && !has_sys_admin {
        return Errno::Eperm.as_i32();
    }
    if flags & !FAN_INIT_KNOWN != 0 { return Errno::Einval.as_i32(); }
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
    0
}

/// The two `fanotify_init` checks Linux runs while BUILDING the group, i.e.
/// after the per-user group ucount has already been charged: the class selector
/// has no `default:` arm before the group is allocated, so a flag word naming
/// BOTH classes only fails there, and `FAN_ENABLE_AUDIT`'s `CAP_AUDIT_WRITE`
/// gate is the last check of all. Ordering is user-visible: a user at their
/// group ceiling gets `EMFILE` for those two inputs, not `EINVAL`/`EPERM`.
/// # C: O(1)
pub(crate) fn validate_fanotify_init_post_charge(flags: u32, has_audit_write: bool) -> i32 {
    if flags & FAN_ALL_CLASS_BITS == FAN_ALL_CLASS_BITS { return Errno::Einval.as_i32(); }
    if (flags & FAN_ENABLE_AUDIT) != 0 && !has_audit_write { return Errno::Eperm.as_i32(); }
    0
}

/// Legacy helper retained for hosted tests that only exercise the flag word.
/// # C: O(1)
#[cfg(test)]
pub(crate) fn validate_fanotify_init(flags: u32) -> i32 {
    let e = validate_fanotify_init_args(flags, 0, true);
    if e != 0 { return e; }
    validate_fanotify_init_post_charge(flags, true)
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

/// Scope selected by a `fanotify_mark` flag word (default = inode). # C: O(1)
pub(super) fn mark_scope(flags: u32) -> Result<MarkScope, Errno> {
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

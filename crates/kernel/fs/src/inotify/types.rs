use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;

use vfs::{Ino, InodeRef};

pub(crate) const INOTIFY_INO_BASE: Ino = 0x7100_0000;

/// Linux IN_* event masks (subset).
pub const IN_ACCESS:        u32 = 0x0001;
pub const IN_MODIFY:        u32 = 0x0002;
pub const IN_ATTRIB:        u32 = 0x0004;
pub const IN_CLOSE_WRITE:   u32 = 0x0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0010;
pub const IN_OPEN:          u32 = 0x0020;
pub const IN_MOVED_FROM:    u32 = 0x0040;
pub const IN_MOVED_TO:      u32 = 0x0080;
pub const IN_CREATE:        u32 = 0x0100;
pub const IN_DELETE:        u32 = 0x0200;
pub const IN_ALL_EVENTS:    u32 = 0x0fff;
/// `IN_ISDIR` — the object the event happened to is a directory. Same bit as
/// `FAN_ONDIR` (Linux `FS_ISDIR`), but inotify REPORTS it to userspace while
/// legacy (fd-reporting) fanotify strips it (`fanotify_group_event_mask`:
/// `user_mask &= ~FANOTIFY_EVENT_FLAGS`).
pub const IN_ISDIR:         u32 = 0x4000_0000;
/// inotify never reported `IN_ISDIR` alongside these two. Linux
/// `inotify_handle_inode_event` masks the bit out deliberately ("It looks like
/// an oversight, but to avoid the risk of breaking existing inotify programs").
pub(crate) const IN_SELF_NO_ISDIR: u32 = FAN_DELETE_SELF | FAN_MOVE_SELF;
pub(crate) const IN_IGNORED:     u32 = 0x0000_8000;
pub(crate) const IN_Q_OVERFLOW:  u32 = 0x0000_4000;
pub(crate) const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub(crate) const IN_ONESHOT:     u32 = 0x8000_0000;
pub(crate) const INOTIFY_MARK_FLAGS: u32 = IN_EXCL_UNLINK | IN_ONESHOT;
pub(crate) const INOTIFY_DEFAULT_MAX_QUEUED_EVENTS: usize = 16_384;

// fanotify event-mask bits (`linux/fanotify.h`). The low bits coincide with the
// matching IN_* values, so the shared fire path treats a fanotify mask and an
// inotify mask uniformly; the high bits (perm/ondir/on-child) are fanotify-only.
pub(crate) const FAN_ACCESS:         u32 = 0x0000_0001;
pub(crate) const FAN_MODIFY:         u32 = 0x0000_0002;
pub(crate) const FAN_ATTRIB:         u32 = 0x0000_0004;
pub(crate) const FAN_CLOSE_WRITE:    u32 = 0x0000_0008;
pub(crate) const FAN_CLOSE_NOWRITE:  u32 = 0x0000_0010;
pub(crate) const FAN_OPEN:           u32 = 0x0000_0020;
pub(crate) const FAN_MOVED_FROM:     u32 = 0x0000_0040;
pub(crate) const FAN_MOVED_TO:       u32 = 0x0000_0080;
pub(crate) const FAN_CREATE:         u32 = 0x0000_0100;
pub(crate) const FAN_DELETE:         u32 = 0x0000_0200;
pub(crate) const FAN_DELETE_SELF:    u32 = 0x0000_0400;
pub(crate) const FAN_MOVE_SELF:      u32 = 0x0000_0800;
pub(crate) const FAN_OPEN_EXEC:      u32 = 0x0000_1000;
pub(crate) const FAN_Q_OVERFLOW:     u32 = 0x0000_4000;
pub(crate) const FAN_FS_ERROR:       u32 = 0x0000_8000;
pub(crate) const FAN_OPEN_PERM:      u32 = 0x0001_0000;
pub(crate) const FAN_ACCESS_PERM:    u32 = 0x0002_0000;
pub(crate) const FAN_OPEN_EXEC_PERM: u32 = 0x0004_0000;
pub(crate) const FAN_PRE_ACCESS:     u32 = 0x0010_0000;
pub(crate) const FAN_MNT_ATTACH:     u32 = 0x0100_0000;
pub(crate) const FAN_MNT_DETACH:     u32 = 0x0200_0000;
pub(crate) const FAN_EVENT_ON_CHILD: u32 = 0x0800_0000;
pub(crate) const FAN_RENAME:         u32 = 0x1000_0000;
pub(crate) const FAN_ONDIR:          u32 = 0x4000_0000;
pub(crate) const FAN_CLOSE: u32 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
pub(crate) const FAN_MOVE:  u32 = FAN_MOVED_FROM | FAN_MOVED_TO;
pub(crate) const FAN_MNT_EVENTS: u32 = FAN_MNT_ATTACH | FAN_MNT_DETACH;
pub(crate) const FAN_ALL_EVENT_BITS: u32 =
    FAN_ACCESS | FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE | FAN_OPEN | FAN_OPEN_EXEC
    | FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF | FAN_MOVE_SELF
    | FAN_Q_OVERFLOW | FAN_FS_ERROR | FAN_OPEN_PERM | FAN_ACCESS_PERM
    | FAN_OPEN_EXEC_PERM | FAN_PRE_ACCESS | FAN_MNT_EVENTS | FAN_EVENT_ON_CHILD
    | FAN_RENAME | FAN_ONDIR;
pub(crate) const PERM_BITS: u32 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM | FAN_PRE_ACCESS;
pub(crate) const FAN_ALLOW: u32 = 0x01;
pub(crate) const FAN_DENY:  u32 = 0x02;

/// A pending permission decision. The accessing task parks on `response`
/// (0 = pending) until the fanotify daemon writes a verdict, or the group
/// closes (auto-allow — never wedge an open on a dead daemon).
pub(crate) struct PermEvent {
    pub(crate) obj:      InodeRef,
    pub(crate) pid:      u32,
    pub(crate) mask:     u32,
    pub(crate) response: AtomicU32,
}

/// Number of live FAN_*_PERM marks. The open hot path early-returns when 0,
/// so a normal boot (no perm daemon) pays nothing and can never block.
pub(crate) static PERM_MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Total live marks across every group (inode + mount + filesystem). The event
/// fire paths early-return when 0, so a system with no watcher pays nothing.
pub(crate) static MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Monotonic rename cookie pairing a FAN_MOVED_FROM with its FAN_MOVED_TO
/// (Linux `fsnotify_get_cookie`).
pub(crate) static MOVE_COOKIE: AtomicU32 = AtomicU32::new(1);

/// fanotify mark scope (`FAN_MARK_INODE` default / `FAN_MARK_MOUNT` /
/// `FAN_MARK_FILESYSTEM`). Inode marks key on inode identity; mount and
/// filesystem marks key on the owning superblock's `st_dev` (`fsid`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkScope { Inode, Mount, Filesystem, MountNamespace }

#[derive(Clone)]
pub(crate) struct Watch {
    pub(crate) wd: i32,
    /// Inode identity for an `Inode`-scope mark (0 for mount/fs marks).
    pub(crate) inode_key: usize,
    /// Superblock `st_dev` for a `Mount`/`Filesystem`-scope mark (0 for inode).
    pub(crate) fsid: u64,
    pub(crate) scope: MarkScope,
    /// Events that generate a notification on a matching object.
    pub(crate) mask: u32,
    /// Inotify mark flags (`IN_ONESHOT`, `IN_EXCL_UNLINK`) that are not event bits.
    pub(crate) flags: u32,
    /// `FAN_MARK_IGNORED_MASK` / `FAN_MARK_IGNORE`: events suppressed on a
    /// matching object even when `mask` would request them.
    pub(crate) ignored: u32,
}

impl Watch {
    /// Does this mark cover the object identified by `(key, fsid)`?
    /// # C: O(1)
    pub(crate) fn applies(&self, key: usize, fsid: u64) -> bool {
        match self.scope {
            MarkScope::Inode => self.inode_key == key,
            _ => self.fsid != 0 && self.fsid == fsid,
        }
    }
}

/// Track PERM_MARK_COUNT across a mask transition on one watch: a watch gains a
/// perm bit (none→some) → +1; loses its last perm bit (some→none) → -1.
/// # C: O(1)
pub(crate) fn perm_delta(old: u32, new: u32) {
    let (o, n) = ((old & PERM_BITS) != 0, (new & PERM_BITS) != 0);
    if n && !o { PERM_MARK_COUNT.fetch_add(1, Ordering::AcqRel); }
    else if o && !n { PERM_MARK_COUNT.fetch_sub(1, Ordering::AcqRel); }
}

pub(crate) struct Event {
    pub(crate) wd:     i32,
    pub(crate) mask:   u32,
    pub(crate) cookie: u32,
    /// Linux `inotify_event_info::name` — the affected dir-entry leaf, held as
    /// raw bytes. Non-empty exactly when the event was reported on a WATCHED
    /// DIRECTORY about an entry inside it (create/delete/move, and any child
    /// open/access/modify/close reaching the parent's mark); empty for an event
    /// on the watched object itself. The wire `len` is derived from this at
    /// read time (`layout::round_event_name_len`) and is the PADDED length.
    pub(crate) name:   Vec<u8>,
    /// fanotify only: the object that triggered the event (read() opens a
    /// fresh fd to it for `fanotify_event_metadata.fd`). `None` for inotify.
    pub(crate) obj:    Option<InodeRef>,
    /// fanotify only: pid that caused the event (captured at fire time).
    pub(crate) pid:    u32,
}

pub struct InotifyData {
    pub flags:   u32,
    pub next_wd: AtomicI32,
    /// `true` for a `fanotify_init` group: read() emits the 24-byte
    /// `fanotify_event_metadata` (+ an object fd) instead of `inotify_event`.
    pub(crate) fanotify: bool,
    pub(crate) watches: Spinlock<Vec<Watch>, TaskListClass>,
    pub(crate) events:  Spinlock<VecDeque<Event>, TaskListClass>,
    /// fanotify perm events awaiting delivery to the daemon's read().
    pub(crate) perm_queue: Spinlock<VecDeque<Arc<PermEvent>>, TaskListClass>,
    pub(crate) poll_subs: Arc<PollSubscribers>,
    /// Perm events the daemon has read (minted-fd → event), awaiting its
    /// `fanotify_response` write.
    pub(crate) perm_pending: Spinlock<Vec<(i32, Arc<PermEvent>)>, TaskListClass>,
}

pub(crate) fn inode_key(inode: &InodeRef) -> usize {
    let fsid = inode.fsid();
    let ino = inode.ino();
    (fsid ^ ino.rotate_left(32)) as usize
}

// `AtomicU32` import keeps the Spinlock lock-class warning at bay; nothing
// else in this module uses it.
const _: AtomicU32 = AtomicU32::new(0);

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;

#[cfg(target_os = "oxide-kernel")]
pub(crate) use sched::live::wait_list::WaitList as ReadWaiters;

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) struct ReadWaiters;
#[cfg(not(target_os = "oxide-kernel"))]
impl ReadWaiters {
    pub(crate) const fn new() -> Self { Self }
    pub(crate) fn wake_all(&self) {}
    /// # SAFETY: hosted tests install no scheduler and never take the blocking arm.
    pub(crate) unsafe fn park(&self) { unreachable!("inotify wait under hosted") }
}

use vfs::InodeRef;

/// Every inotify/fanotify group used to carry the SAME number, the base of its
/// range. Linux gives each anon inode its own; userspace separates two
/// descriptions by `(st_dev, st_ino)`, so every group in the system reported
/// one identity to `lsof` and `/proc/<pid>/fdinfo`. Each group now draws its
/// own number, wrapping inside the range rather than escaping it.
pub(crate) static NEXT_INOTIFY_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::INOTIFY);

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
/// `IN_UNMOUNT` — the filesystem holding the watched object was unmounted.
/// Never requestable: `inotify_arg_to_mask` seeds every mark's mask with it, so
/// a watch receives it regardless of what the caller asked for.
pub(crate) const IN_UNMOUNT: u32 = 0x0000_2000;
#[cfg(test)]
pub(crate) const INOTIFY_DEFAULT_MAX_QUEUED_EVENTS: usize =
    vfs::fsnotify::INOTIFY_DEFAULT_MAX_QUEUED_EVENTS as usize;

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
/// Event bits that are not events: modifiers a mark carries to say WHICH
/// objects its events are about. Stripped from what a legacy (fd-reporting)
/// group reports back to userspace; kept for a fid-reporting group.
pub(crate) const FANOTIFY_EVENT_FLAGS: u32 = FAN_EVENT_ON_CHILD | FAN_ONDIR;
pub(crate) const FAN_ALL_EVENT_BITS: u32 =
    FAN_ACCESS | FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE | FAN_OPEN | FAN_OPEN_EXEC
    | FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF | FAN_MOVE_SELF
    | FAN_Q_OVERFLOW | FAN_FS_ERROR | FAN_OPEN_PERM | FAN_ACCESS_PERM
    | FAN_OPEN_EXEC_PERM | FAN_PRE_ACCESS | FAN_MNT_EVENTS | FAN_EVENT_ON_CHILD
    | FAN_RENAME | FAN_ONDIR;
pub(crate) const PERM_BITS: u32 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM | FAN_PRE_ACCESS;

/// A permission event that has been queued but not yet handed to a reader.
pub(crate) const PERM_INIT: u32 = 0;
/// A reader has dequeued it and minted its descriptor; it now sits on the
/// group's pending list awaiting a `fanotify_response` write.
pub(crate) const PERM_REPORTED: u32 = 1;
/// A verdict has been stored; the blocked accessor may proceed.
pub(crate) const PERM_ANSWERED: u32 = 2;
/// The blocked accessor abandoned the wait (a fatal signal). A verdict that
/// arrives afterwards has nobody to deliver it to.
pub(crate) const PERM_CANCELED: u32 = 3;

/// A pending permission decision, shared between the blocked accessor and the
/// fanotify daemon's reader/writer. The accessor parks until `verdict` is
/// published (or the group closes — a dead daemon must never wedge an open).
pub(crate) struct PermState {
    /// `PERM_INIT` → `PERM_REPORTED` → `PERM_ANSWERED`, or `PERM_CANCELED`.
    pub(crate) state:   AtomicU32,
    /// The validated response word, published once. `0` while pending — no
    /// valid response word is zero, since one verdict bit is always set. The
    /// descriptor the daemon answers by is NOT held here: the group's pending
    /// list is keyed by it and is the only place it lives.
    pub(crate) verdict: AtomicU32,
    /// The `FAN_INFO` audit record the verdict arrived with, if any. Published
    /// BEFORE the verdict, so a reader that has seen an answer has also seen
    /// the record that justifies it.
    audit_rule: Spinlock<Option<crate::inotify::response::AuditRule>, TaskListClass>,
}

impl PermState {
    /// # C: O(1)
    pub(crate) fn new() -> Self {
        Self { state: AtomicU32::new(PERM_INIT), verdict: AtomicU32::new(0),
               audit_rule: Spinlock::new(None) }
    }

    /// Record the `FAN_INFO` audit rule a verdict arrived with. # C: O(1)
    pub(crate) fn set_audit_rule(&self, r: crate::inotify::response::AuditRule) {
        *self.audit_rule.lock() = Some(r);
    }

    /// The audit rule recorded against this decision, or `None` when the
    /// verdict carried no record. # C: O(1)
    pub(crate) fn audit_rule(&self) -> Option<crate::inotify::response::AuditRule> {
        *self.audit_rule.lock()
    }

    /// Mark the event handed to the daemon. # C: O(1)
    pub(crate) fn report(&self) { let _ = self.state.compare_exchange(
        PERM_INIT, PERM_REPORTED, Ordering::AcqRel, Ordering::Acquire); }

    /// Abandon the wait: a verdict arriving afterwards has nobody to deliver it
    /// to and must be discarded rather than resuming a dead accessor. # C: O(1)
    pub(crate) fn cancel(&self) { self.state.store(PERM_CANCELED, Ordering::Release); }

    /// Publish a verdict. `false` when the accessor already abandoned the
    /// wait — the event is finished either way, but nothing is resumed.
    /// # C: O(1)
    pub(crate) fn answer(&self, response: u32) -> bool {
        if self.state.load(Ordering::Acquire) == PERM_CANCELED { return false; }
        self.verdict.store(response, Ordering::Release);
        self.state.store(PERM_ANSWERED, Ordering::Release);
        true
    }

    /// The published response word, or `None` while still pending. # C: O(1)
    pub(crate) fn answered(&self) -> Option<u32> {
        let v = self.verdict.load(Ordering::Acquire);
        if v == 0 { None } else { Some(v) }
    }
}

/// Number of live FAN_*_PERM marks. The open hot path early-returns when 0,
/// so a normal boot (no perm daemon) pays nothing and can never block.
pub(crate) static PERM_MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Total live marks across every group (inode + mount + filesystem). The event
/// fire paths early-return when 0, so a system with no watcher pays nothing.
pub(crate) static MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Number of live `FAN_MARK_MNTNS` marks. The mount-tree attach/detach/move
/// choke points early-return when 0, so a system with no mount watcher — every
/// system that is not running one — pays nothing per mount.
pub(crate) static MNTNS_MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Monotonic rename cookie pairing a FAN_MOVED_FROM with its FAN_MOVED_TO
/// (Linux `fsnotify_get_cookie`).
pub(crate) static MOVE_COOKIE: AtomicU32 = AtomicU32::new(1);

/// fanotify mark scope (`FAN_MARK_INODE` default / `FAN_MARK_MOUNT` /
/// `FAN_MARK_FILESYSTEM` / `FAN_MARK_MNTNS`). Inode marks key on inode
/// identity; mount and filesystem marks key on the owning superblock's
/// `st_dev` (`fsid`); mount-namespace marks key on the mount namespace's id
/// and match no inode at all.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkScope { Inode, Mount, Filesystem, MountNamespace }

pub(crate) struct Watch {
    pub(crate) wd: i32,
    /// Inode identity for an `Inode`-scope mark (0 for mount/fs marks).
    pub(crate) inode_key: usize,
    /// Superblock `st_dev` for a `Mount`/`Filesystem`-scope mark (0 for inode).
    pub(crate) fsid: u64,
    /// Mount-namespace id for a `MountNamespace`-scope mark (0 otherwise). A
    /// SEPARATE field from `fsid` on purpose: a namespace id and an `st_dev`
    /// are unrelated number spaces, and sharing one field would let the
    /// superblock teardown sweep (`unmount_fs_marks`) retire a mount-namespace
    /// mark whose id happened to collide with a dying filesystem's.
    pub(crate) ns_id: u64,
    pub(crate) scope: MarkScope,
    /// Events that generate a notification on a matching object.
    pub(crate) mask: u32,
    /// Inotify mark flags (`IN_ONESHOT`, `IN_EXCL_UNLINK`) that are not event bits.
    pub(crate) flags: u32,
    /// `FAN_MARK_IGNORED_MASK` / `FAN_MARK_IGNORE`: events suppressed on a
    /// matching object even when `mask` would request them.
    pub(crate) ignored: u32,
    /// The ignore set was established through `FAN_MARK_IGNORE`, whose event
    /// flags mean what they say, rather than through the legacy
    /// `FAN_MARK_IGNORED_MASK`, whose stored set is reinterpreted (`mask.rs`).
    pub(crate) ignore_has_flags: bool,
    /// `FAN_MARK_IGNORED_SURV_MODIFY` — the ignore set survives a modification
    /// of the watched object. Without it, one `FAN_MODIFY` clears the set, so
    /// a watcher that suppressed its own writes starts hearing about the file
    /// again as soon as anything else changes it.
    pub(crate) ignore_survives_modify: bool,
    /// The reference this mark holds on the inode it is attached to, which is
    /// what keeps that inode resident for as long as the mark exists. `None`
    /// for a mount/filesystem/namespace mark (they are attached to no inode)
    /// and for an inode mark created with `FAN_MARK_EVICTABLE`, which asked
    /// NOT to pin its object.
    ///
    /// The pin IS the evictable distinction — there is no separate flag, so
    /// the two can never disagree. An ordinary mark's inode cannot reach the
    /// eviction path at all, and an evictable mark's inode can, taking the
    /// mark with it. Modelling `FAN_MARK_EVICTABLE` as a bool while every mark
    /// was keyed on `(fsid, ino)` made the flag meaningless: an ordinary mark
    /// survived eviction only by construction, and its object was free to be
    /// reclaimed and its inode number handed to a different file underneath it.
    ///
    /// Released through [`Watch::take_pin`] with NO lock held — dropping the
    /// last reference runs the inode's eviction, which re-enters the mark
    /// tables through the eviction hook.
    pin: Option<InodeRef>,
}

impl Watch {
    /// Does this mark cover the object identified by `(key, fsid)`?
    /// # C: O(1)
    pub(crate) fn applies(&self, key: usize, fsid: u64) -> bool {
        match self.scope {
            MarkScope::Inode => self.inode_key == key,
            // A mount-namespace mark is not attached to any object with an
            // inode: it only ever receives mount-tree changes, never an event
            // about a file. Matching one here would deliver every event on
            // every filesystem to a `FAN_REPORT_MNT` group.
            MarkScope::MountNamespace => false,
            _ => self.fsid != 0 && self.fsid == fsid,
        }
    }

    /// How a notification about the object this mark is ATTACHED TO reaches it.
    /// The parent leg is not this: a mark reached because the event happened to
    /// an entry inside it is `IterType::Parent`, decided by the fire path, not
    /// by the mark. # C: O(1)
    pub(crate) fn iter_type(&self) -> crate::inotify::mask::IterType {
        use crate::inotify::mask::IterType;
        match self.scope {
            MarkScope::Inode => IterType::Self_,
            MarkScope::Mount => IterType::Mount,
            MarkScope::Filesystem | MarkScope::MountNamespace => IterType::Filesystem,
        }
    }

    /// The ignore set that applies to one notification (`mask::effective_ignore_mask`).
    /// # C: O(1)
    pub(crate) fn effective_ignore(&self, is_dir: bool, iter: crate::inotify::mask::IterType) -> u32 {
        crate::inotify::mask::effective_ignore_mask(self.ignored, self.mask,
                                                    self.ignore_has_flags, is_dir, iter)
    }

    /// A new mark on `pin`'s object. An inode mark takes a reference on the
    /// inode unless the caller asked for an evictable one; every other scope
    /// is attached to no inode and takes none. # C: O(1)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(wd: i32, inode_key: usize, fsid: u64, ns_id: u64, scope: MarkScope,
                      mask: u32, flags: u32, ignored: u32, ignore_has_flags: bool,
                      ignore_survives_modify: bool, pin: Option<&InodeRef>) -> Self {
        let pin = pin.map(|i| { i.igrab(); i.clone() });
        Self { wd, inode_key, fsid, ns_id, scope, mask, flags, ignored, ignore_has_flags,
               ignore_survives_modify, pin }
    }

    /// This mark holds no reference on its object: either it is not an inode
    /// mark, or it was created `FAN_MARK_EVICTABLE`. # C: O(1)
    pub(crate) fn is_evictable(&self) -> bool { self.pin.is_none() }

    /// Detach the inode reference so it can be released once every mark table
    /// lock is dropped. # C: O(1)
    pub(crate) fn take_pin(&mut self) -> Option<InodeRef> { self.pin.take() }

    /// Re-establish the pin an `FAN_MARK_ADD` without `FAN_MARK_EVICTABLE`
    /// implies on a mark that had none, and hand back the reference a mark
    /// that is BECOMING evictable must give up. # C: O(1)
    pub(crate) fn repin(&mut self, pin: Option<&InodeRef>) -> Option<InodeRef> {
        match (pin, self.pin.is_some()) {
            (Some(i), false) => { i.igrab(); self.pin = Some(i.clone()); None }
            (None, true)     => self.pin.take(),
            _ => None,
        }
    }
}

/// Release inode references detached from destroyed marks. Runs with NO mark
/// table lock held: the last reference dropping evicts the inode, and eviction
/// re-enters those tables through the eviction hook. # C: O(N)
pub(crate) fn release_pins(pins: Vec<InodeRef>) {
    for i in pins {
        match i.i_sb() { Some(sb) => sb.iput(i), None => { i.i_count_dec(); } }
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

/// One queued notification. Most fields are common to every family; the tail
/// carries the payload only one family has, so a record that is not of that
/// family leaves it at the zero value (`Default`) and every construction site
/// names only what it actually reports.
#[derive(Default)]
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
    /// Set exactly on a `FAN_*_PERM` record: the shared state the accessing
    /// task is parked on. Its presence is what makes the record unmergeable
    /// and what a reader keys the minted descriptor to.
    pub(crate) perm:   Option<Arc<PermState>>,
    /// The mount a `FAN_MNT_ATTACH`/`FAN_MNT_DETACH` record is about, reported
    /// in a `FAN_EVENT_INFO_TYPE_MNT` info record. `0` on every other record —
    /// mount ids start at 1, so it is never a real mount.
    pub(crate) mnt_id: u64,
    /// `FAN_RENAME` only: the DESTINATION parent directory. The SOURCE parent
    /// is the ordinary `obj`/`name` pair, so ONE record carries both halves of
    /// the rename and userspace never has to re-pair two events. `None` on
    /// every other record, and also on a rename reported to a mark that covers
    /// only the destination — such a mark is told the new parent alone, in
    /// `obj`/`name`.
    pub(crate) dir2:   Option<InodeRef>,
    /// `FAN_RENAME` only: the entry name inside `dir2`.
    pub(crate) name2:  Vec<u8>,
    /// `FAN_FS_ERROR` only: the errno the filesystem reported, as the POSITIVE
    /// number userspace reads out of the record.
    pub(crate) error:  i32,
    /// The `st_dev` of the filesystem a record whose object is the FILESYSTEM
    /// itself is about (`FAN_FS_ERROR`). Every other family derives its fsid
    /// from `obj`, which such a record may not have — a corrupt filesystem
    /// often cannot name an inode at all.
    pub(crate) fsid:   u64,
    /// `FAN_FS_ERROR` only: how many errors this record stands for. Starts at
    /// 1 and rises every time another error on the same filesystem is folded
    /// into it, so a filesystem failing continuously produces one record with a
    /// climbing count instead of flooding the queue.
    pub(crate) err_count: u32,
    /// `FAN_PRE_ACCESS` only: the PAGE-ALIGNED byte range the access covers, as
    /// `(offset, count)`. `None` when the access names no range — such an event
    /// carries no range record at all.
    pub(crate) range:  Option<(u64, u64)>,
}

pub struct InotifyData {
    pub flags:   u32,
    /// `fanotify_init`'s second argument: the open mode every descriptor this
    /// group mints for an event carries. Stored at group creation because the
    /// minting happens much later, in an unrelated task's read().
    pub(crate) event_f_flags: u32,
    pub next_wd: AtomicI32,
    /// euid that created the group — the ucount key its instance/watch charges
    /// are released against when the group dies (Linux `group->*_data.ucounts`).
    pub(crate) uid: u32,
    /// `group->max_events`: the notification-queue depth, SNAPSHOT from the
    /// `max_queued_events` sysctl at group creation. A later sysctl write does
    /// not resize a live group, exactly as Linux.
    pub(crate) max_events: usize,
    /// `true` for a `fanotify_init` group: read() emits the 24-byte
    /// `fanotify_event_metadata` (+ an object fd) instead of `inotify_event`.
    pub(crate) fanotify: bool,
    pub(crate) watches: Spinlock<Vec<Watch>, TaskListClass>,
    /// The ONE notification queue. Permission events sit in it in arrival
    /// order alongside ordinary notifications, exactly as a reader must see
    /// them: a daemon that keeps a second queue for permission events reports
    /// them out of order relative to the notifications that explain them.
    pub(crate) events:  Spinlock<crate::inotify::queue::EventQueue, TaskListClass>,
    /// `true` once the group's last descriptor is closed. Stops new events
    /// from entering the queue, so a permission event can never be queued
    /// after the release path has already answered everything.
    pub(crate) closed:  core::sync::atomic::AtomicBool,
    pub(crate) poll_subs: Arc<PollSubscribers>,
    /// Sleepers in a BLOCKING `read(2)`. `poll_subs` wakes epoll/poll waiters;
    /// it does not wake a reader parked in the read path — those are different
    /// mechanisms, and having only the former is why a blocking inotify read
    /// returned `EAGAIN` and a fanotify one spun on `tick_yield`.
    pub(crate) read_waiters: ReadWaiters,
    /// Accessors parked waiting for a verdict on a permission event of this
    /// group. Distinct from `read_waiters`: those are daemons waiting for
    /// events to arrive, these are ordinary tasks blocked mid-syscall.
    pub(crate) access_waiters: ReadWaiters,
    /// `access_list`: permission events a reader has already handed to the
    /// daemon (minted-fd → state), awaiting its `fanotify_response` write.
    pub(crate) perm_pending: Spinlock<Vec<(i32, Arc<PermState>)>, TaskListClass>,
}

impl InotifyData {
    /// A pre-content-class group sits early enough in the access path that a
    /// denial may name its own errno. # C: O(1)
    pub(crate) fn is_pre_content(&self) -> bool {
        self.flags & crate::inotify::validate::FAN_CLASS_PRE_CONTENT != 0
    }

    /// `FAN_ENABLE_AUDIT` — the group may set `FAN_AUDIT` on a verdict.
    /// # C: O(1)
    pub(crate) fn audit_enabled(&self) -> bool {
        self.flags & crate::inotify::validate::FAN_ENABLE_AUDIT != 0
    }
}

pub(crate) fn inode_key(inode: &InodeRef) -> usize {
    let fsid = inode.fsid();
    let ino = inode.ino();
    (fsid ^ ino.rotate_left(32)) as usize
}

// `AtomicU32` import keeps the Spinlock lock-class warning at bay; nothing
// else in this module uses it.
const _: AtomicU32 = AtomicU32::new(0);

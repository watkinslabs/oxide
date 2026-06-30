// Real inotify per Linux 2.6.13. Per-fd watch table + per-fd event
// queue + vfs::File::write hook for IN_MODIFY firing. Programs that
// inotify_add_watch on a path then write to it now see real events
// via inotify_inode.read.
//
// v1 limits:
//   * IN_MODIFY only — fired from File::write after successful inode write.
//     IN_OPEN / IN_CLOSE / IN_CREATE / IN_DELETE / IN_MOVED_* ride v2
//     once the corresponding VFS paths grow hooks.
//   * watches are inode-pointer-keyed (same identity scheme as
//     inode_times / xattr_overlay). On distinct path resolution to
//     the same inode, both watches fire (Linux behaviour).
//   * No recursive watches (no IN_ONLYDIR / IN_DONT_FOLLOW honouring).








use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};

const INOTIFY_INO_BASE: Ino = 0x7100_0000;

/// Linux IN_* event masks (subset).
pub const IN_ACCESS:        u32 = 0x0001;
pub const IN_MODIFY:        u32 = 0x0002;
pub const IN_ATTRIB:        u32 = 0x0004;
pub const IN_CLOSE_WRITE:   u32 = 0x0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0010;
pub const IN_OPEN:          u32 = 0x0020;
pub const IN_ALL_EVENTS:    u32 = 0x0fff;

// fanotify event-mask bits (`linux/fanotify.h`). The low bits coincide with the
// matching IN_* values, so the shared fire path treats a fanotify mask and an
// inotify mask uniformly; the high bits (perm/ondir/on-child) are fanotify-only.
pub const FAN_ACCESS:         u32 = 0x0000_0001;
pub const FAN_MODIFY:         u32 = 0x0000_0002;
pub const FAN_ATTRIB:         u32 = 0x0000_0004;
pub const FAN_CLOSE_WRITE:    u32 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE:  u32 = 0x0000_0010;
pub const FAN_OPEN:           u32 = 0x0000_0020;
pub const FAN_MOVED_FROM:     u32 = 0x0000_0040;
pub const FAN_MOVED_TO:       u32 = 0x0000_0080;
pub const FAN_CREATE:         u32 = 0x0000_0100;
pub const FAN_DELETE:         u32 = 0x0000_0200;
pub const FAN_DELETE_SELF:    u32 = 0x0000_0400;
pub const FAN_MOVE_SELF:      u32 = 0x0000_0800;
pub const FAN_OPEN_EXEC:      u32 = 0x0000_1000;
pub const FAN_Q_OVERFLOW:     u32 = 0x0000_4000;
pub const FAN_FS_ERROR:       u32 = 0x0000_8000;
// Permission events: the kernel blocks the operation until the listener replies.
pub const FAN_OPEN_PERM:      u32 = 0x0001_0000;
pub const FAN_ACCESS_PERM:    u32 = 0x0002_0000;
pub const FAN_OPEN_EXEC_PERM: u32 = 0x0004_0000;
pub const FAN_EVENT_ON_CHILD: u32 = 0x0800_0000;
pub const FAN_ONDIR:          u32 = 0x4000_0000;
/// Composite helpers (`linux/fanotify.h`).
pub const FAN_CLOSE: u32 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
pub const FAN_MOVE:  u32 = FAN_MOVED_FROM | FAN_MOVED_TO;
/// Every event/modifier bit a mark may legitimately request; unknown bits in a
/// `fanotify_mark` mask are dropped (Linux `fanotify_group_flags`/mask filter).
const FAN_ALL_EVENT_BITS: u32 =
    FAN_ACCESS | FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE | FAN_OPEN | FAN_OPEN_EXEC
    | FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF | FAN_MOVE_SELF
    | FAN_Q_OVERFLOW | FAN_FS_ERROR | FAN_OPEN_PERM | FAN_ACCESS_PERM
    | FAN_OPEN_EXEC_PERM | FAN_EVENT_ON_CHILD | FAN_ONDIR;
/// The three permission-event bits (a mark carrying any of these blocks ops).
const PERM_BITS: u32 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY:  u32 = 0x02;

/// A pending permission decision. The accessing task parks on `response`
/// (0 = pending) until the fanotify daemon writes a verdict, or the group
/// closes (auto-allow — never wedge an open on a dead daemon).
struct PermEvent {
    obj:      InodeRef,
    pid:      u32,
    mask:     u32,       // FAN_OPEN_PERM or FAN_ACCESS_PERM
    response: AtomicU32, // 0 pending, FAN_ALLOW, FAN_DENY
}

/// Number of live FAN_*_PERM marks. The open hot path early-returns when 0,
/// so a normal boot (no perm daemon) pays nothing and can never block.
static PERM_MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Total live marks across every group (inode + mount + filesystem). The event
/// fire paths early-return when 0, so a system with no watcher pays nothing.
static MARK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Monotonic rename cookie pairing a FAN_MOVED_FROM with its FAN_MOVED_TO
/// (Linux `fsnotify_get_cookie`).
static MOVE_COOKIE: AtomicU32 = AtomicU32::new(1);

/// fanotify mark scope (`FAN_MARK_INODE` default / `FAN_MARK_MOUNT` /
/// `FAN_MARK_FILESYSTEM`). Inode marks key on inode identity; mount and
/// filesystem marks key on the owning superblock's `st_dev` (`fsid`). The VFS
/// event hooks deliver only an inode, so a mount mark is matched at superblock
/// granularity — see the module residual note below.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkScope { Inode, Mount, Filesystem }

#[derive(Clone)]
struct Watch {
    wd: i32,
    /// Inode identity for an `Inode`-scope mark (0 for mount/fs marks).
    inode_key: usize,
    /// Superblock `st_dev` for a `Mount`/`Filesystem`-scope mark (0 for inode).
    fsid: u64,
    scope: MarkScope,
    /// Events that generate a notification on a matching object.
    mask: u32,
    /// `FAN_MARK_IGNORED_MASK` / `FAN_MARK_IGNORE`: events suppressed on a
    /// matching object even when `mask` would request them.
    ignored: u32,
}

impl Watch {
    /// Does this mark cover the object identified by `(key, fsid)`?
    /// # C: O(1)
    fn applies(&self, key: usize, fsid: u64) -> bool {
        match self.scope {
            MarkScope::Inode => self.inode_key == key,
            // Mount and filesystem marks both match on superblock identity.
            _ => self.fsid != 0 && self.fsid == fsid,
        }
    }
}

/// Track PERM_MARK_COUNT across a mask transition on one watch: a watch gains a
/// perm bit (none→some) → +1; loses its last perm bit (some→none) → -1.
/// # C: O(1)
fn perm_delta(old: u32, new: u32) {
    let (o, n) = ((old & PERM_BITS) != 0, (new & PERM_BITS) != 0);
    if n && !o { PERM_MARK_COUNT.fetch_add(1, Ordering::AcqRel); }
    else if o && !n { PERM_MARK_COUNT.fetch_sub(1, Ordering::AcqRel); }
}

struct Event {
    wd:     i32,
    mask:   u32,
    cookie: u32,
    /// Length of the trailing name field (0 — v1 doesn't track names yet).
    len:    u32,
    /// fanotify only: the object that triggered the event (read() opens a
    /// fresh fd to it for `fanotify_event_metadata.fd`). `None` for inotify.
    obj:    Option<InodeRef>,
    /// fanotify only: pid that caused the event (captured at fire time).
    pid:    u32,
}

pub struct InotifyData {
    pub flags:   u32,
    pub next_wd: AtomicI32,
    /// `true` for a `fanotify_init` group: read() emits the 24-byte
    /// `fanotify_event_metadata` (+ an object fd) instead of `inotify_event`.
    fanotify: bool,
    watches: Spinlock<Vec<Watch>, TaskListClass>,
    events:  Spinlock<VecDeque<Event>, TaskListClass>,
    /// fanotify perm events awaiting delivery to the daemon's read().
    perm_queue: Spinlock<VecDeque<Arc<PermEvent>>, TaskListClass>,
    /// Perm events the daemon has read (minted-fd → event), awaiting its
    /// `fanotify_response` write.
    perm_pending: Spinlock<Vec<(i32, Arc<PermEvent>)>, TaskListClass>,
}

impl InotifyData {
    /// Construct + register in the global instance list so the vfs
    /// write hook can find this inotify when an inode it watches is
    /// modified. Drop unregisters.
    /// # C: O(1)
    pub fn new(flags: u32) -> Arc<Self> { Self::new_kind(flags, false) }

    /// `fanotify_init` group (read() yields `fanotify_event_metadata`).
    /// # C: O(1)
    pub fn new_fanotify(flags: u32) -> Arc<Self> { Self::new_kind(flags, true) }

    fn new_kind(flags: u32, fanotify: bool) -> Arc<Self> {
        let arc = Arc::new(Self {
            flags,
            next_wd: AtomicI32::new(1),
            fanotify,
            watches: Spinlock::new(Vec::new()),
            events:  Spinlock::new(VecDeque::new()),
            perm_queue:   Spinlock::new(VecDeque::new()),
            perm_pending: Spinlock::new(Vec::new()),
        });
        register_instance(Arc::downgrade(&arc));
        arc
    }

    /// Install a fresh O_RDONLY fd referring to `obj` in the current task's
    /// fd table for a `fanotify_event_metadata.fd`. Returns FAN_NOFD (-1)
    /// when there is no task or the fd table is full.
    /// # C: O(1)
    fn install_obj_fd(obj: &InodeRef) -> i32 {
        let cur = match sched::current() { Some(c) => c, None => return -1 };
        // SAFETY: running task on this CPU; sole reader of its fd-table slot.
        let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -1 };
        let dentry = vfs::dcache::d_alloc_pseudo("[fanotify]", obj.clone(), &crate::anon_dname::ANON_INODE_OPS);
        let file = vfs::File::new(obj.clone(), dentry, vfs::OpenFlags::O_RDONLY);
        fdt.alloc_limit(file, cur.nofile_soft()).unwrap_or(-1)
    }

    /// Drain queued events as Linux `struct fanotify_event_metadata` (24 B):
    /// {event_len u32, vers u8=3, reserved u8, metadata_len u16=24, mask u64,
    /// fd i32, pid i32}. Each event installs a fresh O_RDONLY fd to its object
    /// (FAN_NOFD=-1 if unavailable). EAGAIN on an empty queue (no EOF).
    /// # C: O(events drained)
    fn read_fanotify(&self, buf: &mut [u8]) -> KResult<usize> {
        const META: usize = 24;
        const FAN_METADATA_VERSION: u8 = 3;
        let emit = |s: &mut [u8], mask: u32, fd: i32, pid: u32| {
            s[0..4].copy_from_slice(&(META as u32).to_le_bytes());
            s[4] = FAN_METADATA_VERSION;
            s[5] = 0;
            s[6..8].copy_from_slice(&(META as u16).to_le_bytes());
            s[8..16].copy_from_slice(&(mask as u64).to_le_bytes());
            s[16..20].copy_from_slice(&fd.to_le_bytes());
            s[20..24].copy_from_slice(&(pid as i32).to_le_bytes());
        };
        let mut written = 0;
        // Perm events first: the accessor is blocked, so the daemon must see
        // them ahead of notification events. Each minted fd is recorded in
        // perm_pending so the daemon's response write() can match it.
        while written + META <= buf.len() {
            let pev = { self.perm_queue.lock().pop_front() };
            let pev = match pev { Some(p) => p, None => break };
            let fd = Self::install_obj_fd(&pev.obj);
            self.perm_pending.lock().push((fd, pev.clone()));
            emit(&mut buf[written..written + META], pev.mask, fd, pev.pid);
            written += META;
        }
        let mut q = self.events.lock();
        while written + META <= buf.len() {
            let ev = match q.pop_front() { Some(e) => e, None => break };
            let fd = match &ev.obj { Some(o) => Self::install_obj_fd(o), None => -1 };
            emit(&mut buf[written..written + META], ev.mask, fd, ev.pid);
            written += META;
        }
        if written == 0 { return Err(VfsError::Eagain); }
        Ok(written)
    }

    /// `true` for a `fanotify_init` group. # C: O(1)
    pub fn is_fanotify(&self) -> bool { self.fanotify }

    /// Apply a `struct fanotify_response { __s32 fd; __u32 response }` write:
    /// match the pending perm event by its minted fd, store the verdict so
    /// the parked accessor wakes. # C: O(N_pending)
    fn apply_response(&self, fd: i32, response: u32) {
        let mut pend = self.perm_pending.lock();
        if let Some(pos) = pend.iter().position(|(f, _)| *f == fd) {
            let (_, ev) = pend.remove(pos);
            let v = if response == FAN_DENY { FAN_DENY } else { FAN_ALLOW };
            ev.response.store(v, Ordering::Release);
        }
    }

    /// On group close, auto-ALLOW every still-pending perm event so a dead
    /// or exited daemon never wedges a blocked open (Linux `fanotify_release`).
    /// # C: O(N_pending + N_queued)
    fn release_perms(&self) {
        for ev in self.perm_queue.lock().drain(..) { ev.response.store(FAN_ALLOW, Ordering::Release); }
        for (_, ev) in self.perm_pending.lock().drain(..) { ev.response.store(FAN_ALLOW, Ordering::Release); }
    }
}

/// FAN_OPEN_PERM hook for the open path. # C: O(1) fast / O(groups)+park
pub fn check_open_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_PERM) }

/// FAN_ACCESS_PERM hook for the read path. # C: O(1) fast / O(groups)+park
pub fn check_access_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_ACCESS_PERM) }

/// FAN_OPEN_EXEC_PERM hook for the execve path. # C: O(1) fast / O(groups)+park
pub fn check_open_exec_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_EXEC_PERM) }

/// Permission-event core. Returns `true` to allow, `false` to deny (caller
/// returns -EACCES). Fast-paths to allow when no FAN_*_PERM marks exist
/// anywhere (zero overhead on the open/read hot paths — never blocks boot).
/// Otherwise queues a perm event (tagged `perm_mask`) to each matching group
/// and parks until a verdict arrives.
/// # C: O(1) fast path; else O(groups) + park
fn check_perm(inode: &InodeRef, perm_mask: u32) -> bool {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return true; }
    let key = inode_key(inode);
    let fsid = inode.fsid();
    #[cfg(target_os = "oxide-kernel")]
    let pid = sched::current().map(|t| t.tgid.load(Ordering::Relaxed)).unwrap_or(0);
    #[cfg(not(target_os = "oxide-kernel"))]
    let pid = 0u32;
    let ev = Arc::new(PermEvent { obj: inode.clone(), pid, mask: perm_mask, response: AtomicU32::new(0) });
    let mut queued = false;
    {
        let g = INSTANCES.lock();
        for w in g.iter() {
            let arc = match w.upgrade() { Some(a) => a, None => continue };
            if !arc.fanotify { continue; }
            // A mark blocks only if it requests this perm bit AND does not
            // ignore it — inode, mount or filesystem scope (Linux fanotify
            // marks at any scope can carry permission events).
            let hit = arc.watches.lock().iter().any(|wi|
                wi.applies(key, fsid) && (wi.mask & perm_mask) != 0 && (wi.ignored & perm_mask) == 0);
            if hit { arc.perm_queue.lock().push_back(ev.clone()); queued = true; }
        }
    }
    if !queued { return true; }
    // Park until the daemon responds (or a group close auto-allows).
    loop {
        let r = ev.response.load(Ordering::Acquire);
        if r != 0 { return r == FAN_ALLOW; }
        #[cfg(target_os = "oxide-kernel")]
        // SAFETY: open syscall context; runqueue installed; yield until the
        // fanotify daemon writes a verdict or the group closes.
        unsafe { sched::live::tick_yield(); }
        #[cfg(not(target_os = "oxide-kernel"))]
        return true;
    }
}

/// `make_inotify_inode(flags, fanotify)` — a CharDev pseudo-inode whose `read`
/// drains the event queue. The `InotifyData` lives both in `i_private` and in
/// the global INSTANCES list (the vfs write-hook walks it). # C: O(1)
pub fn make_inotify_inode(data: Arc<InotifyData>) -> InodeRef {
    InodeBuilder::new(INOTIFY_INO_BASE, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), Arc::new(InotifyFileOps))
        .private(data)
        .build()
}

/// `i_fop` for an inotify/fanotify group inode. Reads `InotifyData` off
/// `i_private` and delegates to its inherent methods. # C: O(1)
struct InotifyFileOps;
impl FileOps for InotifyFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match inode.private::<InotifyData>() { Some(d) => d.read(off, buf), None => Err(VfsError::Einval) }
    }
    fn read_nonblock(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match inode.private::<InotifyData>() { Some(d) => d.read_nonblock(off, buf), None => Err(VfsError::Einval) }
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        match inode.private::<InotifyData>() { Some(d) => d.write(off, buf), None => Err(VfsError::Einval) }
    }
    fn poll(&self, inode: &Inode) -> u32 {
        inode.private::<InotifyData>().map_or(0, |d| d.poll())
    }
    fn on_release(&self, inode: &Inode) {
        if let Some(d) = inode.private::<InotifyData>() { d.on_release(); }
    }
}

impl InotifyData {
    /// Drain queued events into `buf` in Linux `struct inotify_event`
    /// shape: {wd: i32, mask: u32, cookie: u32, len: u32, name[len]}.
    /// v1 always emits len=0 (no name tail).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.fanotify {
            // A blocking fanotify group read parks until an event is queued
            // (Linux default; O_NONBLOCK routes to read_nonblock → EAGAIN).
            loop {
                match self.read_fanotify(buf) {
                    Err(VfsError::Eagain) => {
                        #[cfg(target_os = "oxide-kernel")]
                        // SAFETY: read syscall context; runqueue installed; yield until an event arrives.
                        unsafe { sched::live::tick_yield(); }
                        #[cfg(not(target_os = "oxide-kernel"))]
                        return Err(VfsError::Eagain);
                    }
                    other => return other,
                }
            }
        }
        const HDR: usize = 16;
        let mut written = 0;
        let mut q = self.events.lock();
        while written + HDR <= buf.len() {
            let ev = match q.pop_front() { Some(e) => e, None => break };
            let s = &mut buf[written..written + HDR];
            s[0..4].copy_from_slice(&ev.wd.to_le_bytes());
            s[4..8].copy_from_slice(&ev.mask.to_le_bytes());
            s[8..12].copy_from_slice(&ev.cookie.to_le_bytes());
            s[12..16].copy_from_slice(&ev.len.to_le_bytes());
            written += HDR;
        }
        // An inotify fd has no EOF: an empty queue means "no events yet",
        // which is EAGAIN (would-block), NOT 0. Returning 0 makes an
        // epoll-driven reader (systemd's sd-event) spin forever — poll
        // reports readable, read yields 0, repeat. Linux returns EAGAIN.
        if written == 0 { return Err(VfsError::Eagain); }
        Ok(written)
    }
    /// O_NONBLOCK read: never parks. fanotify drains once (EAGAIN if empty);
    /// inotify already drains non-blocking. # C: O(events drained)
    fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.fanotify { return self.read_fanotify(buf); }
        self.read(off, buf)
    }
    /// POLLIN only when at least one event is queued. The default inode
    /// poll() reports always-readable, which drives an inotify watcher's
    /// event loop into a busy spin (read returns EAGAIN, poll says ready).
    /// # C: O(1)
    fn poll(&self) -> u32 {
        let ready = !self.events.lock().is_empty()
            || (self.fanotify && !self.perm_queue.lock().is_empty());
        if ready { vfs::POLL_IN } else { 0 }
    }
    /// fanotify: a `struct fanotify_response { __s32 fd; __u32 response }`
    /// (8 B) verdict from the daemon unblocks the matching perm event.
    /// inotify fds are not writable (EIO).
    /// # C: O(N_pending)
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        if !self.fanotify { return Err(VfsError::Eio); }
        let mut off = 0;
        while off + 8 <= buf.len() {
            let fd = i32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
            let resp = u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
            self.apply_response(fd, resp);
            off += 8;
        }
        if off == 0 { return Err(VfsError::Einval); }
        Ok(off)
    }
    /// Last close of a fanotify group auto-allows pending perm events so a
    /// crashed/exited daemon never wedges a blocked open.
    fn on_release(&self) { if self.fanotify { self.release_perms(); } }
}


/// Global registry of weak refs to every live InotifyData. Walked
/// on each VFS write-hook call to find watches matching the modified
/// inode.
static INSTANCES: Spinlock<Vec<Weak<InotifyData>>, TaskListClass> =
    Spinlock::new(Vec::new());

fn register_instance(w: Weak<InotifyData>) {
    let mut g = INSTANCES.lock();
    // Garbage-collect dead weak refs while we're here.
    g.retain(|w| w.upgrade().is_some());
    g.push(w);
}

/// Core event dispatch. Walks the live group list and pushes one event per
/// matching mark (inode / mount / filesystem scope). `self_event` = the event
/// is on `inode` itself (open/read/write/close/attrib/*_self); `false` = a
/// dir-entry event reported on the watched directory `inode` (create/delete/
/// moved_*). `cookie` pairs the two halves of a rename. fanotify groups honor
/// FAN_ONDIR (directory self-events) and the per-mark ignore mask; inotify
/// groups keep verbatim inotify semantics. # C: O(N_groups * N_watches)
fn dispatch(inode: &InodeRef, mask_bit: u32, self_event: bool, cookie: u32) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let key = inode_key(inode);
    let fsid = inode.fsid();
    let is_dir = inode.file_type() == FileType::Directory;
    // pid that caused the event, captured here in its context — fanotify
    // reports it; inotify ignores it.
    #[cfg(target_os = "oxide-kernel")]
    let pid = sched::current().map(|t| t.tgid.load(Ordering::Relaxed)).unwrap_or(0);
    #[cfg(not(target_os = "oxide-kernel"))]
    let pid = 0u32;
    let g = INSTANCES.lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let watches = arc.watches.lock();
        for wi in watches.iter() {
            if !wi.applies(key, fsid) { continue; }
            if (wi.ignored & mask_bit) != 0 { continue; }   // suppressed on this object
            if (wi.mask & mask_bit) == 0 { continue; }
            let mut report = mask_bit;
            if arc.fanotify {
                // A self-event on a directory object is delivered only when the
                // mark set FAN_ONDIR; the reported mask then carries FAN_ONDIR.
                if self_event && is_dir && (wi.mask & FAN_ONDIR) == 0 { continue; }
                if is_dir { report |= FAN_ONDIR; }
            }
            // fanotify needs the object to mint an fd on read; inotify skips it.
            let obj = if arc.fanotify { Some(inode.clone()) } else { None };
            arc.events.lock().push_back(Event { wd: wi.wd, mask: report, cookie, len: 0, obj, pid });
        }
    }
}

/// An event on `inode` itself. # C: O(N_groups * N_watches)
fn fire_self(inode: &InodeRef, mask_bit: u32) { dispatch(inode, mask_bit, true, 0); }
/// A dir-entry event reported on watched directory `parent`. # C: as dispatch
fn fire_child(parent: &InodeRef, mask_bit: u32, cookie: u32) { dispatch(parent, mask_bit, false, cookie); }

/// Fire `IN_MODIFY` on the inode currently registered at `path`.
/// Leaf crates (cgroup) that mutate a synthetic file's content without
/// going through the VFS write path use this to emit the
/// change-notification Linux's `cgroup_file_notify` provides — e.g.
/// `cgroup.events` when `populated`/`frozen` flips. No-op if `path`
/// resolves to nothing (cgroup already rmdir'd).
/// # C: O(N_inotify * N_watches) + O(path components)
pub fn fire_modify_path(path: &str) {
    if let Ok(inode) = vfs::resolve_abs(path) {
        fire_self(&inode, IN_MODIFY);
    }
}

/// FAN_ATTRIB / IN_ATTRIB — metadata change (chmod/chown/utimes/link-count).
/// Wired from the chmod/chown syscall handlers (Linux `fsnotify_change`).
/// # C: O(N_groups * N_watches)
pub fn fire_attrib(inode: &InodeRef) {
    fire_self(inode, FAN_ATTRIB);
    // dnotify DN_ATTRIB: fires when the watched directory's OWN attrs change
    // (chmod/chown on a dir holding an F_NOTIFY watch). A DN_ATTRIB on a child
    // file requires the parent-dentry context the chmod/chown VFS hook does not
    // carry; that child case rides the per-child fsnotify-parent hook.
    vfs::file::dnotify_emit(inode, vfs::file::DN_ATTRIB);
}

/// FAN_OPEN_EXEC — a file opened for program execution (Linux
/// `fsnotify_open` with `FMODE_EXEC`). Wired from the execve path.
/// # C: O(N_groups * N_watches)
pub fn fire_open_exec(inode: &InodeRef) { fire_self(inode, FAN_OPEN_EXEC); }

/// FAN_DELETE_SELF / IN_DELETE_SELF — the watched object itself was unlinked.
/// # C: O(N_groups * N_watches)
pub fn fire_delete_self(inode: &InodeRef) { fire_self(inode, FAN_DELETE_SELF); }

/// Rename notification triple (Linux `fsnotify_move`): FAN_MOVED_FROM on the
/// source directory + FAN_MOVED_TO on the destination directory share one
/// cookie, and FAN_MOVE_SELF fires on the moved object.
/// # C: O(N_groups * N_watches)
pub fn fire_move(old_parent: &InodeRef, new_parent: &InodeRef, moved: Option<&InodeRef>) {
    let c = MOVE_COOKIE.fetch_add(1, Ordering::Relaxed);
    fire_child(old_parent, FAN_MOVED_FROM, c);
    fire_child(new_parent, FAN_MOVED_TO, c);
    if let Some(m) = moved { fire_self(m, FAN_MOVE_SELF); }
    // dnotify DN_RENAME on both the source and destination dir watches (Linux
    // `dnotify_parent` for FS_MOVED_FROM/TO). Zero-cost without an armed watch.
    vfs::file::dnotify_emit(old_parent, vfs::file::DN_RENAME);
    vfs::file::dnotify_emit(new_parent, vfs::file::DN_RENAME);
}

fn vfs_write_notify(inode: &InodeRef) { fire_self(inode, IN_MODIFY); }
fn vfs_open_notify(inode: &InodeRef)  { fire_self(inode, IN_OPEN); }
fn vfs_read_notify(inode: &InodeRef)  { fire_self(inode, IN_ACCESS); }
fn vfs_close_notify(inode: &InodeRef, was_writable: bool) {
    fire_self(inode, if was_writable { IN_CLOSE_WRITE } else { IN_CLOSE_NOWRITE });
    // Pipe writer/reader-count tracking lives in pipe.rs's own
    // close hook (see `pipe::install_close_hook`). Doing it here
    // too would double-decrement on every File::drop, driving
    // writers/readers below zero on the first close.
}

/// Install all inotify event hooks into vfs. Called once at kernel_main.
/// # C: O(1)
pub fn install_write_hook() {
    vfs::set_write_hook(vfs_write_notify);
    vfs::set_open_hook(vfs_open_notify);
    vfs::set_read_hook(vfs_read_notify);
    vfs::set_close_hook(vfs_close_notify);
    vfs::set_dirent_create_hook(vfs_dirent_create);
    vfs::set_dirent_delete_hook(vfs_dirent_delete);
}

/// Dirent-mutation event firing (F123 / `16§R02`). For each live
/// inotify instance whose watch list mentions the parent path's
/// inode (resolved via the VFS namei walk), push an event with the leaf
/// name in the trailing `name[]` field of inotify_event.
///
/// V1 limit: events still emit `len=0` because read() encoding hasn't
/// been extended to write the name tail. The hook fires (so the count
/// is visible via SIZE_UNREAD-style probes); name carriage rides v3
/// alongside the read() format extension.
fn vfs_dirent_create(parent: &str, _leaf: &str) {
    if let Ok(parent_inode) = vfs::mount::lookup(parent) {
        fire_child(&parent_inode, IN_CREATE, 0);
        // dnotify DN_CREATE on the parent dir's F_NOTIFY watch (Linux
        // `dnotify_parent`/`fsnotify_create`). Zero-cost when no watch is armed.
        vfs::file::dnotify_emit(&parent_inode, vfs::file::DN_CREATE);
    }
}
fn vfs_dirent_delete(parent: &str, _leaf: &str) {
    if let Ok(parent_inode) = vfs::mount::lookup(parent) {
        fire_child(&parent_inode, IN_DELETE, 0);
        // dnotify DN_DELETE on the parent dir's watch (Linux `fsnotify_unlink`).
        vfs::file::dnotify_emit(&parent_inode, vfs::file::DN_DELETE);
    }
}

/// IN_CREATE / IN_DELETE bit values per `linux/inotify.h`.
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO:   u32 = 0x80;

fn inode_key(inode: &InodeRef) -> usize {
    let raw: *const Inode = Arc::as_ptr(inode);
    raw as *const u8 as usize
}

fn resolve_watch_path(raw: &str) -> Option<InodeRef> {
    // D26-fs: a lexical-normalization miss resolves to nothing (caller maps to
    // ENOENT), never a nondeterministic raw-string fallback.
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

/// `sys_inotify_init(flags=0)` / `sys_inotify_init1(flags)`.
/// Allocates a fresh InotifyData at the lowest free fd.
/// # C: O(N_fds)
pub fn sys_inotify_init1(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    let flags = args.a0 as u32;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    const IN_NONBLOCK: u32 = 0o0_004_000;
    const IN_CLOEXEC:  u32 = 0o2_000_000;
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

// fanotify_init flags (`linux/fanotify.h`).
const FAN_CLOEXEC:          u32 = 0x0000_0001;
const FAN_NONBLOCK:         u32 = 0x0000_0002;
// FAN_CLASS_NOTIF = 0 (the implicit default class).
const FAN_CLASS_CONTENT:    u32 = 0x0000_0004;
const FAN_CLASS_PRE_CONTENT:u32 = 0x0000_0008;
const FAN_ALL_CLASS_BITS:   u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT; // 0xc mask
const FAN_UNLIMITED_QUEUE:  u32 = 0x0000_0010;
const FAN_UNLIMITED_MARKS:  u32 = 0x0000_0020;
const FAN_ENABLE_AUDIT:     u32 = 0x0000_0040;
const FAN_REPORT_PIDFD:     u32 = 0x0000_0080;
const FAN_REPORT_TID:       u32 = 0x0000_0100;
const FAN_REPORT_FID:       u32 = 0x0000_0200;
const FAN_REPORT_DIR_FID:   u32 = 0x0000_0400;
const FAN_REPORT_NAME:      u32 = 0x0000_0800;
const FAN_INIT_KNOWN: u32 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS
    | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_PIDFD
    | FAN_REPORT_TID | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

/// Validate a `fanotify_init` flag word the Linux way (`do_fanotify_init`):
/// reject unknown bits, an impossible class (`0xc`), and FAN_REPORT_NAME
/// without FAN_REPORT_DIR_FID. Returns the errno (>0) or 0 if valid.
/// # C: O(1)
fn validate_fanotify_init(flags: u32) -> i32 {
    use syscall::errno::Errno;
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
    use syscall::errno::Errno;
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
    // A fanotify group fd is read (events) AND write (responses) — must be
    // O_RDWR or the response write() is rejected EBADF before the inode.
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

fn fd_to_inotify(fd: i32) -> Option<Arc<InotifyData>> {
    let cur = sched::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(fd).ok()?;
    // Recover the Arc<InotifyData> directly off the inode's i_private.
    f.inode().i_private().clone().downcast::<InotifyData>().ok()
}

/// `sys_inotify_add_watch(fd, pathname, mask)`. Resolves `pathname`
/// via devfs (v1's only namespace), records a Watch on the fd's
/// InotifyData, returns the wd.
/// # C: O(N_path)
pub fn sys_inotify_add_watch(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let path_p = args.a1;
    let mask   = args.a2 as u32;
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
    // If a watch on the same inode exists, replace its mask + return existing wd.
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
    use syscall::errno::Errno;
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

// `AtomicU32` import keeps the Spinlock lock-class warning at bay; nothing
// else in this module uses it.
const _: AtomicU32 = AtomicU32::new(0);

// === fanotify(7) marks ===
//
// fanotify shares the per-group watch-table + event-queue substrate with
// inotify (the read() side diverges: fanotify emits `fanotify_event_metadata`
// + a minted object fd). A fanotify mark adds a scope (inode / mount /
// filesystem) and an ignore mask on top of an inotify watch. The full Linux
// event set is mapped through the shared `dispatch`/`fire_*` path above.

// fanotify_mark flags (`linux/fanotify.h`).
const FAN_MARK_ADD:                 u32 = 0x0000_0001;
const FAN_MARK_REMOVE:              u32 = 0x0000_0002;
const FAN_MARK_DONT_FOLLOW:         u32 = 0x0000_0004;
const FAN_MARK_ONLYDIR:             u32 = 0x0000_0008;
const FAN_MARK_MOUNT:               u32 = 0x0000_0010;
const FAN_MARK_IGNORED_MASK:        u32 = 0x0000_0020;
const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
const FAN_MARK_FLUSH:               u32 = 0x0000_0080;
const FAN_MARK_FILESYSTEM:          u32 = 0x0000_0100;
const FAN_MARK_EVICTABLE:           u32 = 0x0000_0200;
const FAN_MARK_IGNORE:              u32 = 0x0000_0400;
const FAN_MARK_KNOWN: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM
    | FAN_MARK_EVICTABLE | FAN_MARK_IGNORE;

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
fn apply_mark(inotify: &Arc<InotifyData>, scope: MarkScope, key: usize, fsid: u64,
              bits: u32, add: bool, ignored: bool) -> i64 {
    use syscall::errno::Errno;
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
    use syscall::errno::Errno;
    let fd     = args.a0 as i32;
    let flags  = args.a1 as u32;
    let mask   = args.a2 as u32;
    let _dirfd = args.a3 as i32;
    let path_p = args.a4;
    // Flag-word + operation-selector validation (Linux do_fanotify_mark).
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
        // FLUSH ignores mask + path and drops every mark of the selected scope.
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
    // Drop unknown bits; keep the full event/perm/ONDIR/on-child set.
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
    // FAN_MARK_ONLYDIR rejects a non-directory target (Linux → ENOTDIR).
    if flags & FAN_MARK_ONLYDIR != 0 && inode.file_type() != FileType::Directory {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let (key, fsid) = (inode_key(&inode), inode.fsid());
    apply_mark(&inotify, scope, key, fsid, bits, flags & FAN_MARK_ADD != 0, ignored)
}

#[cfg(test)]
#[path = "inotify_fan_tests.rs"]
mod fan_tests;

#[cfg(test)]
mod tests {
    use super::*;

    // An empty inotify fd is EAGAIN (would-block), never EOF(0), and
    // poll() reports not-readable — else an epoll-driven reader spins.
    #[test]
    fn empty_inotify_is_eagain_and_not_pollable() {
        let ino = InotifyData::new(0);
        let mut buf = [0u8; 64];
        assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
        assert_eq!(ino.poll(), 0);
    }

    // With an event queued, poll() is readable and read() drains a
    // 16-byte inotify_event; a second read returns to EAGAIN.
    #[test]
    fn queued_event_is_readable_then_drains_to_eagain() {
        let ino = InotifyData::new(0);
        ino.events.lock().push_back(Event { wd: 1, mask: IN_MODIFY, cookie: 0, len: 0, obj: None, pid: 0 });
        assert_eq!(ino.poll(), vfs::POLL_IN);
        let mut buf = [0u8; 64];
        assert_eq!(ino.read(0, &mut buf), Ok(16));
        assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), IN_MODIFY);
        // Queue now empty → back to EAGAIN / not pollable.
        assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
        assert_eq!(ino.poll(), 0);
    }
}

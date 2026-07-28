use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};

use crate::inotify::dispatch::register_instance;
use crate::inotify::layout::{encode_event, event_record_len};
use crate::inotify::types::{
    inode_key, InotifyData, PermEvent, FAN_ACCESS_PERM, FAN_ALLOW, FAN_DENY, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM,
    Event, INOTIFY_DEFAULT_MAX_QUEUED_EVENTS, INOTIFY_INO_BASE, IN_Q_OVERFLOW, PERM_MARK_COUNT,
};

/// `signal_pending(current)` — Linux breaks the read loop with `-ERESTARTSYS`
/// on a deliverable signal. Hosted builds install no scheduler and never take
/// the blocking arm. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn signals_pending() -> bool { sched::live::deliverable_signals_self() != 0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn signals_pending() -> bool { false }

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
            next_wd: core::sync::atomic::AtomicI32::new(1),
            fanotify,
            watches: sync::Spinlock::new(Vec::new()),
            events: sync::Spinlock::new(alloc::collections::VecDeque::new()),
            perm_queue: sync::Spinlock::new(alloc::collections::VecDeque::new()),
            poll_subs: Arc::new(PollSubscribers::new()),
            read_waiters: crate::inotify::types::ReadWaiters::new(),
            perm_pending: sync::Spinlock::new(Vec::new()),
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
    pub(crate) fn read_fanotify(&self, buf: &mut [u8]) -> KResult<usize> {
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

    /// Queue one notification, applying Linux's bounded per-group queue shape:
    /// when full, drop the new event and retain one overflow marker.
    /// # C: O(N_queue) only while already overflowed/full
    pub(crate) fn enqueue_event(&self, ev: Event) {
        let mut q = self.events.lock();
        if q.len() < INOTIFY_DEFAULT_MAX_QUEUED_EVENTS {
            q.push_back(ev);
            drop(q);
            self.poll_subs.notify_mask(vfs::POLL_IN);
            self.read_waiters.wake_all();
            return;
        }
        if q.iter().any(|e| (e.mask & IN_Q_OVERFLOW) != 0) { return; }
        q.push_back(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: Vec::new(), obj: None, pid: 0 });
        drop(q);
        self.poll_subs.notify_mask(vfs::POLL_IN);
        self.read_waiters.wake_all();
    }

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

    /// Drain queued events into `buf` in Linux `struct inotify_event` shape:
    /// `{wd: i32, mask: u32, cookie: u32, len: u32, name[len]}`, where `len` is
    /// the NAME PADDED up to a whole 16-byte header (`layout`). Records are
    /// variable-length, so the queue is PEEKED before popping: a caller whose
    /// remaining buffer cannot hold the next whole event gets what has already
    /// been copied, or `EINVAL` when that is nothing (Linux `get_one_event`
    /// returns `ERR_PTR(-EINVAL)` and `inotify_read` propagates it). A partial
    /// event is never emitted.
    pub(crate) fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.inotify_read(buf, false)
    }

    /// O_NONBLOCK read. Linux has ONE `inotify_read`; the `O_NONBLOCK` flag
    /// only decides whether the empty-queue arm breaks with `EAGAIN` or sleeps.
    /// Modelled the same way, so the two paths cannot drift.
    ///
    /// This must NOT delegate to a blocking read. It used to, which was
    /// harmless only while that read returned `EAGAIN` instead of sleeping —
    /// the moment it sleeps, every `O_NONBLOCK` reader blocks forever, and an
    /// epoll-driven inotify consumer (systemd, glib) is exactly that.
    /// # C: O(events drained)
    pub(crate) fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.inotify_read(buf, true)
    }

    /// Linux `get_one_event` (`fs/notify/inotify/inotify_user.c`): peek the
    /// head under the notification lock; `None` when the queue is empty;
    /// `Some(Err(EINVAL))` when the head's whole record cannot fit in `count`;
    /// otherwise pop and return it. The peek-then-pop under one lock hold is
    /// what guarantees the popped event is the one that was size-checked.
    /// # C: O(1)
    fn get_one_event(&self, count: usize) -> Option<KResult<Event>> {
        let mut q = self.events.lock();
        let event_size = event_record_len(q.front()?.name.len());
        if event_size > count { return Some(Err(VfsError::Einval)); }
        q.pop_front().map(Ok)
    }

    /// Linux `inotify_read`, structurally: register on the wait queue once,
    /// then loop { get_one_event -> copy -> continue } until the queue is
    /// empty, and only then consider EAGAIN / ERESTARTSYS / sleeping. The
    /// closing `if (start != buf && ret != -EFAULT) ret = buf - start` rule
    /// means every error arm reports the bytes ALREADY copied instead of the
    /// error, so a short buffer or a signal never discards delivered events.
    /// # C: O(events drained) + at most one sleep per empty poll
    fn inotify_read(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if self.fanotify { return self.fanotify_read(buf, nonblock); }
        let mut written = 0usize;
        loop {
            match self.get_one_event(buf.len() - written) {
                Some(Ok(ev)) => {
                    written += encode_event(&mut buf[written..], ev.wd, ev.mask, ev.cookie, &ev.name);
                    continue;
                }
                // `ret = PTR_ERR(kevent); break;` — then the tail rule turns a
                // non-empty copy into a byte count (EINVAL only on the FIRST).
                Some(Err(e)) => return if written != 0 { Ok(written) } else { Err(e) },
                None => {}
            }
            // `ret = -EAGAIN; if (f_flags & O_NONBLOCK) break;`
            if nonblock { return if written != 0 { Ok(written) } else { Err(VfsError::Eagain) }; }
            // `ret = -ERESTARTSYS; if (signal_pending(current)) break;`
            if signals_pending() { return if written != 0 { Ok(written) } else { Err(VfsError::Erestartsys) }; }
            // `if (start != buf) break;` — never sleep holding delivered bytes.
            if written != 0 { return Ok(written); }
            // `wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT)`.
            #[cfg(target_os = "oxide-kernel")]
            self.wait_for_event();
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// fanotify's `fanotify_read` shares the same shape: drain, then EAGAIN or
    /// sleep. Its records are fixed-size, so there is no short-buffer EINVAL.
    /// # C: O(events drained) + at most one sleep per empty poll
    fn fanotify_read(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        loop {
            match self.read_fanotify(buf) {
                Err(VfsError::Eagain) => {}
                other => return other,
            }
            if nonblock { return Err(VfsError::Eagain); }
            if signals_pending() { return Err(VfsError::Erestartsys); }
            #[cfg(target_os = "oxide-kernel")]
            self.wait_for_event();
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// `wait_woken(TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT)`.
    ///
    /// Linux calls `add_wait_queue` ONCE before the loop, so it is registered
    /// across the condition check and cannot miss a wake. `park_*` here
    /// publishes `Sleeping` BEFORE pushing onto the waiter list, so a
    /// producer's `wake_all` landing in that gap finds an empty list
    /// (`if g.is_empty() { return; }`) and wakes nobody — a PERMANENTLY lost
    /// wakeup, since inotify passes no deadline to break it out (timerfd
    /// survives the identical gap only because it does). Re-checking after
    /// registering restores Linux's ordering without needing the producer's
    /// lock, which matters because fanotify has two independent producer
    /// queues that share no lock.
    /// # C: O(1) + one sleep
    #[cfg(target_os = "oxide-kernel")]
    fn wait_for_event(&self) {
        // SAFETY: read syscall context, no locks held; the re-check below cancels
        // the park if an event or signal arrived while we were publishing.
        unsafe { self.read_waiters.park_interruptible_with_deadline(0); }
        if self.has_queued_events() || signals_pending() {
            self.read_waiters.cancel_current_park();
            return;
        }
        // SAFETY: this task published Sleeping through the wait list and holds no locks.
        unsafe { sched::live::schedule::schedule(); }
        self.read_waiters.remove_current();
    }

    /// Whether any queue a reader drains is non-empty — the condition
    /// re-checked after registering. # C: O(1)
    fn has_queued_events(&self) -> bool {
        if !self.events.lock().is_empty() { return true; }
        if self.fanotify && !self.perm_queue.lock().is_empty() { return true; }
        false
    }

    /// POLLIN only when at least one event is queued. The default inode
    /// poll() reports always-readable, which drives an inotify watcher's
    /// event loop into a busy spin (read returns EAGAIN, poll says ready).
    /// # C: O(1)
    pub(crate) fn poll(&self) -> u32 {
        let ready = !self.events.lock().is_empty()
            || (self.fanotify && !self.perm_queue.lock().is_empty());
        if ready { vfs::POLL_IN } else { 0 }
    }

    /// fanotify: a `struct fanotify_response { __s32 fd; __u32 response }`
    /// (8 B) verdict from the daemon unblocks the matching perm event.
    /// inotify fds are not writable (EIO).
    /// # C: O(N_pending)
    pub(crate) fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        if !self.fanotify { return Err(VfsError::Eio); }
        let mut off = 0;
        while off + 8 <= buf.len() {
            let fd = i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            let resp = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
            self.apply_response(fd, resp);
            off += 8;
        }
        if off == 0 { return Err(VfsError::Einval); }
        Ok(off)
    }

    /// Last close of a fanotify group auto-allows pending perm events so a
    /// crashed/exited daemon never wedges a blocked open.
    pub(crate) fn on_release(&self) { if self.fanotify { self.release_perms(); } }
}

/// FAN_OPEN_PERM hook for the open path. # C: O(1) fast / O(groups)+park
pub fn check_open_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_PERM) }

/// FAN_ACCESS_PERM hook for the read path. # C: O(1) fast / O(groups)+park
pub fn check_access_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_ACCESS_PERM) }

/// FAN_OPEN_EXEC_PERM hook for the execve path. # C: O(1) fast / O(groups)+park
pub fn check_open_exec_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_EXEC_PERM) }

/// Boot fast-path gate: `true` iff any `FAN_*_PERM` mark is armed anywhere.
/// Lets the execve perm-gate skip its inode resolve entirely at boot (no perm
/// marks → byte-identical to the pre-gate path). # C: O(1)
pub fn perm_marks_present() -> bool { PERM_MARK_COUNT.load(Ordering::Acquire) != 0 }

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
    let ev = Arc::new(PermEvent { obj: inode.clone(), pid, mask: perm_mask, response: core::sync::atomic::AtomicU32::new(0) });
    let mut queued = false;
    {
        let g = crate::inotify::dispatch::instances().lock();
        for w in g.iter() {
            let arc = match w.upgrade() { Some(a) => a, None => continue };
            if !arc.fanotify { continue; }
            let hit = arc.watches.lock().iter().any(|wi|
                wi.applies(key, fsid) && (wi.mask & perm_mask) != 0 && (wi.ignored & perm_mask) == 0);
            if hit { arc.perm_queue.lock().push_back(ev.clone()); arc.poll_subs.notify_mask(vfs::POLL_IN); arc.read_waiters.wake_all(); queued = true; }
        }
    }
    if !queued { return true; }
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
/// the global instance list (the vfs write-hook walks it). # C: O(1)
pub fn make_inotify_inode(data: Arc<InotifyData>) -> InodeRef {
    let subs = Arc::clone(&data.poll_subs);
    InodeBuilder::new(INOTIFY_INO_BASE, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), Arc::new(InotifyFileOps))
        .private(data)
        .poll_subs_arc(subs)
        .build()
}

/// `i_fop` for an inotify/fanotify group inode. Reads `InotifyData` off
/// `i_private` and delegates to its inherent methods. # C: O(1)
pub(crate) struct InotifyFileOps;

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

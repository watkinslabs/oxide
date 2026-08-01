use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::fsnotify::Ucount;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};

use crate::inotify::dispatch::register_instance;
use crate::inotify::layout::{encode_event, event_record_len};
use crate::inotify::response::{parse_response_info, validate_response, validate_response_fd,
    AuditRule, AUDIT_RULE_LEN, FAN_ALLOW, FAN_INFO, RESPONSE_LEN};
use crate::inotify::types::{
    Event, InotifyData, PermState, IN_Q_OVERFLOW, MARK_COUNT, MNTNS_MARK_COUNT, NEXT_INOTIFY_INO,
    PERM_BITS, PERM_MARK_COUNT,
};
use crate::inotify::validate::{FAN_CLASS_PRE_CONTENT, FAN_ENABLE_AUDIT, FAN_REPORT_DIR_FID,
    FAN_REPORT_FID, FAN_REPORT_NAME, FAN_REPORT_PIDFD, FAN_REPORT_TID,
    FAN_UNLIMITED_MARKS, FAN_UNLIMITED_QUEUE};

/// `signal_pending(current)` — Linux breaks the read loop with `-ERESTARTSYS`
/// on a deliverable signal. Hosted builds install no scheduler and never take
/// the blocking arm. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn signals_pending() -> bool { sched::live::deliverable_signals_self() != 0 }
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn signals_pending() -> bool { false }

impl InotifyData {
    /// Construct + register in the global instance list so the vfs
    /// write hook can find this inotify when an inode it watches is
    /// modified. Drop unregisters.
    /// # C: O(1)
    pub fn new(flags: u32) -> Arc<Self> { Self::new_kind(flags, false, 0, 0) }

    /// `fanotify_init` group (read() yields `fanotify_event_metadata`).
    /// # C: O(1)
    pub fn new_fanotify(flags: u32) -> Arc<Self> { Self::new_kind(flags, true, 0, 0) }

    /// Group owned by `uid`, whose instance/group ucount charge the caller has
    /// ALREADY taken — `Drop` releases it. `event_f_flags` is the open mode
    /// every descriptor this group mints for an event carries. # C: O(1)
    pub(crate) fn new_owned(flags: u32, fanotify: bool, uid: u32, event_f_flags: u32) -> Arc<Self> {
        Self::new_kind(flags, fanotify, uid, event_f_flags)
    }

    fn new_kind(flags: u32, fanotify: bool, uid: u32, event_f_flags: u32) -> Arc<Self> {
        // `group->max_events = <sysctl>` — snapshot, not a live read, so a
        // later sysctl write never resizes a running group's queue.
        let max_events = if fanotify {
            if flags & FAN_UNLIMITED_QUEUE != 0 { usize::MAX }
            else { vfs::fsnotify::fanotify_max_queued_events().max(0) as usize }
        } else {
            vfs::fsnotify::max_queued_events().max(0) as usize
        };
        let arc = Arc::new(Self {
            flags,
            event_f_flags,
            next_wd: core::sync::atomic::AtomicI32::new(1),
            uid,
            max_events,
            fanotify,
            watches: sync::Spinlock::new(Vec::new()),
            events: sync::Spinlock::new(crate::inotify::queue::EventQueue::new()),
            closed: core::sync::atomic::AtomicBool::new(false),
            poll_subs: Arc::new(PollSubscribers::new()),
            read_waiters: crate::inotify::types::ReadWaiters::new(),
            access_waiters: crate::inotify::types::ReadWaiters::new(),
            perm_pending: sync::Spinlock::new(Vec::new()),
        });
        register_instance(Arc::downgrade(&arc));
        arc
    }

    /// `FAN_REPORT_DIR_FID` — the group can carry an entry name in a
    /// `DFID_NAME` record, so the fire path records it. # C: O(1)
    pub(crate) fn reports_dir_fid(&self) -> bool { self.flags & FAN_REPORT_DIR_FID != 0 }

    /// A group in any fid-reporting mode reports the event flags
    /// (`FAN_ONDIR`) back to userspace; a legacy fd-reporting group strips
    /// them. # C: O(1)
    pub(crate) fn reports_event_flags(&self) -> bool {
        self.fanotify && self.flags & (FAN_REPORT_FID | FAN_REPORT_DIR_FID) != 0
    }

    /// The group's `FANOTIFY_INFO_MODES` triple. # C: O(1)
    pub(crate) fn fid_mode(&self) -> (bool, bool, bool) {
        (self.flags & FAN_REPORT_FID != 0,
         self.flags & FAN_REPORT_DIR_FID != 0,
         self.flags & FAN_REPORT_NAME != 0)
    }

    /// `FAN_REPORT_PIDFD` — a pidfd info record follows each event. # C: O(1)
    pub(crate) fn reports_pidfd(&self) -> bool { self.flags & FAN_REPORT_PIDFD != 0 }

    /// `FAN_REPORT_TID` — the reported id is the acting THREAD's, not its
    /// thread group's. # C: O(1)
    pub(crate) fn reports_tid(&self) -> bool { self.flags & FAN_REPORT_TID != 0 }

    /// `true` for a `fanotify_init` group. # C: O(1)
    pub fn is_fanotify(&self) -> bool { self.fanotify }

    /// Which per-user ceiling one of this group's marks is charged against.
    /// # C: O(1)
    pub(crate) fn mark_ucount(&self) -> Ucount {
        if self.fanotify { Ucount::FanotifyMarks } else { Ucount::InotifyWatches }
    }

    /// `FAN_UNLIMITED_MARKS` exempts a group's marks from the per-user mark
    /// ceiling entirely — such a group contributes nothing to the account, so
    /// neither its charges nor its releases are taken. # C: O(1)
    pub(crate) fn marks_are_charged(&self) -> bool {
        !(self.fanotify && self.flags & FAN_UNLIMITED_MARKS != 0)
    }

    /// Charge one mark to the owning user, or report the ceiling was reached
    /// (`inotify_add_watch` → `ENOSPC`, `fanotify_mark` → `ENOSPC`). # C: O(N_users)
    pub(crate) fn charge_mark(&self) -> bool {
        if !self.marks_are_charged() { return true; }
        vfs::fsnotify::inc_ucount(self.uid, self.mark_ucount())
    }

    /// Release `n` mark charges. # C: O(N_users)
    pub(crate) fn release_marks(&self, n: usize) {
        if n == 0 || !self.marks_are_charged() { return; }
        vfs::fsnotify::dec_ucount(self.uid, self.mark_ucount(), n as i64);
    }

    /// Queue one notification in `fsnotify_add_event` order: refuse once the
    /// group is closed, then the overflow arm (`q_len >= max_events` → one
    /// retained overflow marker, the new event dropped), then the group's
    /// `merge` callback, otherwise queue.
    ///
    /// inotify's merge (`merges_into_tail`) folds a record indistinguishable
    /// from the queue TAIL into it. fanotify's (`fanotify_should_merge`) looks
    /// further back and OR-s the masks together. Neither merges a permission
    /// event, because the accessor blocked on one has to be able to name the
    /// single record it is waiting for.
    ///
    /// A merged event does NOT wake readers — the record it merged into
    /// already did.
    ///
    /// Returns whether the event was queued as its own record.
    /// # C: O(FANOTIFY_MAX_MERGE_EVENTS) for fanotify, O(1) for inotify
    pub(crate) fn enqueue_event(&self, ev: Event) -> bool {
        let queued = {
            let mut q = self.events.lock();
            if self.closed.load(Ordering::Acquire) { return false; }
            if q.len() >= self.max_events {
                if q.iter().any(|e| (e.mask & IN_Q_OVERFLOW) != 0) { return false; }
                q.push(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: Vec::new(),
                               obj: None, pid: 0, perm: None, mnt_id: 0 });
                true
            } else if self.merge_into_queue(&mut q, &ev) {
                false
            } else {
                q.push(ev);
                true
            }
        };
        if queued {
            self.poll_subs.notify_mask(vfs::POLL_IN);
            self.read_waiters.wake_all();
        }
        queued
    }

    /// The group's merge callback. `true` when `ev` was folded into a record
    /// already in the queue and must not be queued again.
    ///
    /// inotify compares against the queue TAIL alone; fanotify hashes the event
    /// on the object it happened to and searches only that bucket, so a
    /// mergeable pair finds each other however deep the queue has grown.
    /// # C: O(1) inotify / O(FANOTIFY_MAX_MERGE_EVENTS) fanotify
    fn merge_into_queue(&self, q: &mut crate::inotify::queue::EventQueue, ev: &Event) -> bool {
        if !self.fanotify {
            return q.back().is_some_and(|t| crate::inotify::queue::merges_into_tail(t, ev));
        }
        q.merge_fanotify(ev)
    }

    /// Apply one validated `struct fanotify_response`: find the pending
    /// permission event the minted descriptor names, publish the verdict, and
    /// wake the parked accessor. `ENOENT` when no pending event carries that
    /// descriptor — a stale or invented fd is reported, not ignored.
    /// # C: O(N_pending)
    fn apply_response(&self, fd: i32, response: u32, rule: Option<AuditRule>)
        -> Result<(), VfsError> {
        let taken = {
            let mut pend = self.perm_pending.lock();
            pend.iter().position(|(f, _)| *f == fd).map(|pos| pend.remove(pos))
        };
        let Some((_, st)) = taken else { return Err(VfsError::Enoent) };
        if let Some(r) = rule { st.set_audit_rule(r); }
        if st.answer(response) { self.access_waiters.wake_all(); }
        Ok(())
    }

    /// Group release: stop queueing, then auto-ALLOW every permission event —
    /// both those a reader already handed to the daemon and those still in the
    /// queue — so a crashed or exited daemon never wedges a blocked accessor.
    /// # C: O(N_pending + N_queued)
    fn release_perms(&self) {
        self.closed.store(true, Ordering::Release);
        for (_, st) in self.perm_pending.lock().drain(..) { st.answer(FAN_ALLOW); }
        {
            let mut q = self.events.lock();
            for ev in q.iter() {
                if let Some(st) = &ev.perm { st.answer(FAN_ALLOW); }
            }
            q.clear();
        }
        self.access_waiters.wake_all();
    }

    /// Drain queued events into `buf` in `struct inotify_event` shape:
    /// `{wd: i32, mask: u32, cookie: u32, len: u32, name[len]}`, where `len` is
    /// the NAME PADDED up to a whole 16-byte header (`layout`). Records are
    /// variable-length, so the queue is PEEKED before popping: a caller whose
    /// remaining buffer cannot hold the next whole event gets what has already
    /// been copied, or `EINVAL` when that is nothing. A partial event is never
    /// emitted.
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

    /// Linux `get_one_event`: peek the head under the notification lock;
    /// `None` when the queue is empty; `Some(Err(EINVAL))` when the head's
    /// whole record cannot fit in `count`; otherwise pop and return it. The
    /// peek-then-pop under one lock hold is what guarantees the popped event is
    /// the one that was size-checked.
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
    /// sleep. # C: O(events drained) + at most one sleep per empty poll
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
    /// wakeup, since inotify passes no deadline to break it out. Re-checking
    /// after registering restores the ordering without needing the producer's
    /// lock.
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

    /// Whether the queue a reader drains is non-empty — the condition
    /// re-checked after registering. # C: O(1)
    fn has_queued_events(&self) -> bool { !self.events.lock().is_empty() }

    /// POLLIN only when at least one event is queued. The default inode
    /// poll() reports always-readable, which drives an inotify watcher's
    /// event loop into a busy spin (read returns EAGAIN, poll says ready).
    /// # C: O(1)
    pub(crate) fn poll(&self) -> u32 {
        if self.events.lock().is_empty() { 0 } else { vfs::POLL_IN }
    }

    /// fanotify: one `struct fanotify_response { __s32 fd; __u32 response }`
    /// (8 B) verdict from the daemon unblocks the matching permission event.
    ///
    /// EXACTLY ONE response per write, whatever the caller's count — a longer
    /// write carries an optional info record for that single response, never a
    /// second response. A short write is EINVAL; an unknown descriptor is
    /// ENOENT. inotify fds are not writable.
    ///
    /// The return value is the response struct plus the info record the write
    /// actually carried, so a daemon that attaches a record and gets back `8`
    /// knows the record was not taken. `FAN_INFO`'s record is parsed BEFORE the
    /// descriptor is admitted, and a `FAN_NOFD` descriptor with a valid record
    /// is accepted for the record alone — such a write names no event, so it
    /// neither answers one nor reports ENOENT.
    /// # C: O(N_pending)
    pub(crate) fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        if !self.fanotify { return Err(VfsError::Eio); }
        if buf.len() < RESPONSE_LEN { return Err(VfsError::Einval); }
        let fd = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let resp = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let pre_content = self.flags & FAN_CLASS_PRE_CONTENT != 0;
        let audit = self.flags & FAN_ENABLE_AUDIT != 0;
        let _ = validate_response(resp, pre_content, audit).map_err(|_| VfsError::Einval)?;
        let mut rule = None;
        let mut consumed = 0usize;
        if resp & FAN_INFO != 0 {
            rule = Some(parse_response_info(&buf[RESPONSE_LEN..]).map_err(|_| VfsError::Einval)?);
            consumed = AUDIT_RULE_LEN;
            if fd == crate::inotify::fan_layout::FAN_NOFD { return Ok(RESPONSE_LEN + consumed); }
        }
        let fd = validate_response_fd(fd).map_err(|_| VfsError::Einval)?;
        // `event->response = response & ~FAN_INFO` — the record is stored
        // beside the verdict, not inside it, so a re-read of the stored word
        // never claims a record that is no longer attached to it.
        self.apply_response(fd, resp & !FAN_INFO, rule)?;
        Ok(RESPONSE_LEN + consumed)
    }

    /// Last close of a fanotify group auto-allows pending permission events so
    /// a crashed/exited daemon never wedges a blocked accessor.
    pub(crate) fn on_release(&self) { if self.fanotify { self.release_perms(); } }

    /// Record a permission event on this group's queue and hand back the state
    /// the accessor parks on. `None` when the group is closed or the queue
    /// refused the record — an accessor with nothing to wait for proceeds.
    /// # C: O(1)
    pub(crate) fn queue_perm_event(&self, ev: Event) -> Option<Arc<PermState>> {
        let st = ev.perm.clone()?;
        if self.enqueue_event(ev) { Some(st) } else { None }
    }
}

/// Releasing the last reference to a group returns every resource it holds to
/// the owning user's account (`fsnotify_destroy_group` → `dec_ucount` plus each
/// mark's own release). Without this a process that opens and closes inotify
/// fds in a loop exhausts its `max_user_instances` permanently and every later
/// `inotify_init` is EMFILE.
/// # C: O(N_users)
impl Drop for InotifyData {
    fn drop(&mut self) {
        // A group can reach Drop without its file ever being released (an
        // error path between construction and fd install), so the perm
        // auto-allow runs here too — a blocked accessor must never outlive the
        // group it is waiting on.
        if self.fanotify { self.release_perms(); }
        let (held, perms, mntns) = {
            let g = self.watches.lock();
            (g.len(), g.iter().filter(|w| w.mask & PERM_BITS != 0).count(),
             g.iter().filter(|w| w.scope == crate::inotify::types::MarkScope::MountNamespace).count())
        };
        self.release_marks(held);
        if perms > 0 { PERM_MARK_COUNT.fetch_sub(perms, Ordering::AcqRel); }
        // The mount-tree fast path keys on this count, so a group dying with
        // live mount-namespace marks must give them back or every mount in the
        // system keeps paying for a watcher that no longer exists.
        if mntns > 0 { MNTNS_MARK_COUNT.fetch_sub(mntns, Ordering::AcqRel); }
        let group_kind = if self.fanotify { Ucount::FanotifyGroups } else { Ucount::InotifyInstances };
        vfs::fsnotify::dec_ucount(self.uid, group_kind, 1);
        // The live marks the group still held are gone with it.
        if held > 0 { MARK_COUNT.fetch_sub(held, Ordering::AcqRel); }
    }
}

/// `make_inotify_inode(flags, fanotify)` — a CharDev pseudo-inode whose `read`
/// drains the event queue. The `InotifyData` lives both in `i_private` and in
/// the global instance list (the vfs write-hook walks it). # C: O(1)
pub fn make_inotify_inode(data: Arc<InotifyData>) -> InodeRef {
    let subs = Arc::clone(&data.poll_subs);
    InodeBuilder::new(NEXT_INOTIFY_INO.alloc(), mk_mode(FileType::CharDev, 0),
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
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &Inode) -> u32 {
        inode.private::<InotifyData>().map_or(0, |d| d.poll())
    }
    fn on_release(&self, inode: &Inode) {
        if let Some(d) = inode.private::<InotifyData>() { d.on_release(); }
    }
}

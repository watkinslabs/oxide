use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::fsnotify::Ucount;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};

use crate::inotify::dispatch::register_instance;
use crate::inotify::fan_layout;
use crate::inotify::layout::{encode_event, event_record_len};
use crate::inotify::types::{
    InotifyData, FAN_ALLOW, FAN_DENY,
    Event, NEXT_INOTIFY_INO, IN_Q_OVERFLOW, MARK_COUNT, PERM_BITS, PERM_MARK_COUNT,
};
use crate::inotify::validate::{FAN_REPORT_DIR_FID, FAN_REPORT_FID, FAN_REPORT_NAME,
    FAN_UNLIMITED_MARKS, FAN_UNLIMITED_QUEUE};

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
    pub fn new(flags: u32) -> Arc<Self> { Self::new_kind(flags, false, 0) }

    /// `fanotify_init` group (read() yields `fanotify_event_metadata`).
    /// # C: O(1)
    pub fn new_fanotify(flags: u32) -> Arc<Self> { Self::new_kind(flags, true, 0) }

    /// Group owned by `uid`, whose instance/group ucount charge the caller has
    /// ALREADY taken — `Drop` releases it. # C: O(1)
    pub(crate) fn new_owned(flags: u32, fanotify: bool, uid: u32) -> Arc<Self> {
        Self::new_kind(flags, fanotify, uid)
    }

    fn new_kind(flags: u32, fanotify: bool, uid: u32) -> Arc<Self> {
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
            next_wd: core::sync::atomic::AtomicI32::new(1),
            uid,
            max_events,
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

    /// Drain queued events as `struct fanotify_event_metadata`, each optionally
    /// followed by the info record the group's report mode asks for (`fan_layout`).
    /// A legacy group installs a fresh O_RDONLY fd to the event's object; a
    /// FID-mode group reports `FAN_NOFD` and a file handle instead. `EAGAIN` on
    /// an empty queue (no EOF); `EINVAL` when the FIRST event does not fit.
    /// # C: O(events drained)
    pub(crate) fn read_fanotify(&self, buf: &mut [u8]) -> KResult<usize> {
        let mut written = 0;
        // Permission events first: an accessor is parked on each one, so a
        // daemon must be able to see them without draining the whole queue.
        loop {
            let need = fan_layout::FAN_EVENT_METADATA_LEN;
            if written + need > buf.len() { break; }
            let pev = { self.perm_queue.lock().pop_front() };
            let pev = match pev { Some(p) => p, None => break };
            let fd = Self::install_obj_fd(&pev.obj);
            self.perm_pending.lock().push((fd, pev.clone()));
            fan_layout::encode_metadata(&mut buf[written..written + need], need, pev.mask, fd, pev.pid);
            written += need;
        }
        loop {
            match self.get_one_fan_event(buf.len() - written) {
                Some(Ok(ev)) => written += self.emit_fan_event(&mut buf[written..], &ev),
                // `get_one_event` returns `ERR_PTR(-EINVAL)` when the head's
                // whole record cannot fit the caller's remaining count; the
                // tail rule turns a non-empty copy into a byte count, so EINVAL
                // only surfaces when nothing was delivered at all.
                Some(Err(e)) => return if written != 0 { Ok(written) } else { Err(e) },
                None => break,
            }
        }
        if written == 0 { return Err(VfsError::Eagain); }
        Ok(written)
    }

    /// `FAN_REPORT_DIR_FID` — the group can carry an entry name in a
    /// `DFID_NAME` record, so the fire path records it. # C: O(1)
    pub(crate) fn reports_dir_fid(&self) -> bool { self.flags & FAN_REPORT_DIR_FID != 0 }

    /// The group's `FANOTIFY_INFO_MODES` triple. # C: O(1)
    fn fid_mode(&self) -> (bool, bool, bool) {
        (self.flags & FAN_REPORT_FID != 0,
         self.flags & FAN_REPORT_DIR_FID != 0,
         self.flags & FAN_REPORT_NAME != 0)
    }

    /// Bytes `ev` will occupy in a reader's buffer under this group's report
    /// mode. # C: O(1)
    fn fan_event_len(&self, ev: &Event) -> usize {
        let (fid, dfid, nm) = self.fid_mode();
        let ty = fan_layout::info_type_for(fid, dfid, nm, !ev.name.is_empty());
        fan_layout::event_len(ty, fan_layout::FILEID_INO32_GEN_LEN, ev.name.len())
    }

    /// fanotify's `get_one_event`: peek, size-check against the caller's
    /// remaining count, and only then pop — all under one lock hold, so the
    /// popped event is the one that was measured. # C: O(1)
    fn get_one_fan_event(&self, count: usize) -> Option<KResult<Event>> {
        let mut q = self.events.lock();
        let need = self.fan_event_len(q.front()?);
        if need > count { return Some(Err(VfsError::Einval)); }
        q.pop_front().map(Ok)
    }

    /// Write one event: the metadata record, then the group's info record when
    /// it is in a FID mode. A FID-mode group reports NO descriptor — Linux
    /// records a file handle instead of a path for such a group, so there is
    /// nothing to open and `metadata.fd` is `FAN_NOFD`.
    /// # C: O(name.len())
    fn emit_fan_event(&self, dst: &mut [u8], ev: &Event) -> usize {
        let (fid, dfid, nm) = self.fid_mode();
        let ty = fan_layout::info_type_for(fid, dfid, nm, !ev.name.is_empty());
        let total = self.fan_event_len(ev);
        let fd = match ty {
            Some(_) => fan_layout::FAN_NOFD,
            None => match &ev.obj { Some(o) => Self::install_obj_fd(o), None => fan_layout::FAN_NOFD },
        };
        let meta = fan_layout::FAN_EVENT_METADATA_LEN;
        fan_layout::encode_metadata(&mut dst[..meta], total, ev.mask, fd, ev.pid);
        if let Some(t) = ty {
            let (s_dev, ino) = match &ev.obj { Some(o) => (o.fsid(), o.ino()), None => (0, 0) };
            let fh = fan_layout::ino32_gen_handle(ino, 0);
            fan_layout::encode_fid_info(&mut dst[meta..total], t, s_dev,
                                        fan_layout::FILEID_INO32_GEN, &fh, &ev.name);
        }
        total
    }

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

    /// Queue one notification in Linux `fsnotify_add_event` order: the overflow
    /// arm first (`q_len >= max_events` → one retained overflow marker, the new
    /// event dropped), otherwise the group's `merge` callback, otherwise queue.
    ///
    /// The merge arm is inotify's `inotify_merge` (`queue::merges_into_tail`):
    /// a record indistinguishable from the queue tail is folded into it and
    /// NOT queued — and, as in Linux, does not wake readers, because the tail
    /// it merged into already did. Skipping this made every duplicate leg of a
    /// fire path (the same bit reaching a mark twice) reach userspace twice.
    /// fanotify has its own merge in Linux (`fanotify_merge`, keyed on a hash
    /// over the whole event) and is left alone here.
    /// # C: O(N_queue) only while already overflowed/full
    pub(crate) fn enqueue_event(&self, ev: Event) {
        let mut q = self.events.lock();
        if q.len() >= self.max_events {
            if q.iter().any(|e| (e.mask & IN_Q_OVERFLOW) != 0) { return; }
            q.push_back(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: Vec::new(), obj: None, pid: 0 });
        } else {
            if !self.fanotify {
                if let Some(tail) = q.back() {
                    if crate::inotify::queue::merges_into_tail(tail, &ev) { return; }
                }
            }
            q.push_back(ev);
        }
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

/// Releasing the last reference to a group returns every resource it holds to
/// the owning user's account (Linux `fsnotify_destroy_group` →
/// `dec_ucount(group->*_data.ucounts)` plus each mark's own release). Without
/// this a process that opens and closes inotify fds in a loop exhausts its
/// `max_user_instances` permanently and every later `inotify_init` is EMFILE.
/// # C: O(N_users)
impl Drop for InotifyData {
    fn drop(&mut self) {
        let (held, perms) = {
            let g = self.watches.lock();
            (g.len(), g.iter().filter(|w| w.mask & PERM_BITS != 0).count())
        };
        self.release_marks(held);
        if perms > 0 { PERM_MARK_COUNT.fetch_sub(perms, Ordering::AcqRel); }
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

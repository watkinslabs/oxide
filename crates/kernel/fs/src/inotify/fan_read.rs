// fanotify READ path: turn queued events into `struct fanotify_event_metadata`
// plus the info records the group's report mode asks for, mint the descriptors
// an event carries, and move a permission event onto the group's pending list
// so the daemon's response can name it.

use alloc::sync::Arc;

use vfs::{InodeRef, KResult, VfsError};

use crate::inotify::fan_layout;
use crate::inotify::types::{Event, InotifyData, PermState};

impl InotifyData {
    /// Install a fresh descriptor referring to `obj` in the current task's fd
    /// table for a `fanotify_event_metadata.fd`. The open mode is the group's
    /// `event_f_flags`, which is the whole point of that argument: a daemon
    /// that asked for `O_RDWR` descriptors and silently received read-only
    /// ones fails on its first write. Returns `FAN_NOFD` when there is no task
    /// or the fd table is full.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub(crate) fn install_obj_fd(&self, obj: &InodeRef) -> i32 {
        let cur = match sched::current() { Some(c) => c, None => return fan_layout::FAN_NOFD };
        // SAFETY: running task on this CPU; sole reader of its fd-table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return fan_layout::FAN_NOFD,
        };
        let dentry = vfs::dcache::d_alloc_pseudo("[fanotify]", obj.clone(), &crate::anon_dname::ANON_INODE_OPS);
        let oflags = vfs::OpenFlags::from_bits_truncate(self.event_f_flags)
            - vfs::OpenFlags::O_CLOEXEC;
        let file = vfs::File::new(obj.clone(), dentry, oflags);
        let fd = fdt.alloc_limit(file, cur.nofile_soft()).unwrap_or(fan_layout::FAN_NOFD);
        if fd >= 0 && self.event_f_flags & vfs::OpenFlags::O_CLOEXEC.bits() != 0 {
            let _ = fdt.set_cloexec(fd, true);
        }
        fd
    }

    /// Hosted builds install no fd table, but a permission event is answered BY
    /// its descriptor, so one still has to be distinct per event or the
    /// response ladder cannot be exercised at all. A counter supplies it.
    /// # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) fn install_obj_fd(&self, _obj: &InodeRef) -> i32 {
        static NEXT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(1);
        NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }

    /// A descriptor referring to the process an event is reported for
    /// (`FAN_REPORT_PIDFD`). `FAN_EPIDFD` when the process is gone or no
    /// descriptor could be minted, which userspace must distinguish from
    /// `FAN_NOPIDFD`. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    fn install_pidfd(&self, pid: u32) -> i32 {
        let cur = match sched::current() { Some(c) => c, None => return fan_layout::FAN_EPIDFD };
        // A process that has already exited is FAN_NOPIDFD; a mint that failed
        // for any other reason is FAN_EPIDFD, and userspace acts on the two
        // differently.
        let file = match pidfd::file_for_pid(cur, pid) { Some(f) => f, None => return fan_layout::FAN_NOPIDFD };
        // SAFETY: running task on this CPU; sole reader of its fd-table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return fan_layout::FAN_EPIDFD,
        };
        fdt.alloc_limit(file, cur.nofile_soft()).unwrap_or(fan_layout::FAN_EPIDFD)
    }

    /// # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    fn install_pidfd(&self, _pid: u32) -> i32 { fan_layout::FAN_NOPIDFD }

    /// Which info record — if any — this group reports for `ev`. # C: O(1)
    fn info_type(&self, ev: &Event) -> Option<u8> {
        let (fid, dfid, nm) = self.fid_mode();
        fan_layout::info_type_for(fid, dfid, nm, !ev.name.is_empty())
    }

    /// Bytes `ev` occupies in a reader's buffer under this group's report mode:
    /// the fixed metadata, the optional fid record, and the optional pidfd
    /// record. # C: O(1)
    pub(crate) fn fan_event_len(&self, ev: &Event) -> usize {
        let mut n = fan_layout::event_len(self.info_type(ev), fan_layout::FANOTIFY_FID_LEN,
                                          ev.name.len());
        if self.reports_pidfd() { n += fan_layout::PIDFD_INFO_LEN; }
        n
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

    /// Drain queued events as `struct fanotify_event_metadata`, each followed
    /// by whatever info records the group's report mode asks for. Permission
    /// events are drained in the SAME order as ordinary notifications, because
    /// they share one queue — a daemon reading its fd sees exactly the sequence
    /// the accesses happened in. `EAGAIN` on an empty queue (no EOF); `EINVAL`
    /// when the FIRST event does not fit.
    /// # C: O(events drained)
    pub(crate) fn read_fanotify(&self, buf: &mut [u8]) -> KResult<usize> {
        let mut written = 0;
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

    /// Write one event: the metadata record, then the group's info records. A
    /// FID-mode group reports NO descriptor for the object — a file handle is
    /// recorded instead of a path, so there is nothing to open and
    /// `metadata.fd` is `FAN_NOFD`.
    ///
    /// A permission event always mints a descriptor regardless of report mode:
    /// the daemon's response names the event BY that descriptor, so an event
    /// without one could never be answered.
    /// # C: O(name.len())
    fn emit_fan_event(&self, dst: &mut [u8], ev: &Event) -> usize {
        let ty = self.info_type(ev);
        let total = self.fan_event_len(ev);
        let want_obj_fd = ty.is_none() || ev.perm.is_some();
        let fd = match (want_obj_fd, &ev.obj) {
            (true, Some(o)) => self.install_obj_fd(o),
            _ => fan_layout::FAN_NOFD,
        };
        if let Some(st) = &ev.perm { self.report_perm_event(st, fd); }
        let meta = fan_layout::FAN_EVENT_METADATA_LEN;
        fan_layout::encode_metadata(&mut dst[..meta], total, ev.mask, fd, ev.pid);
        let mut off = meta;
        if let Some(t) = ty {
            // The fid a watcher is handed must be the handle
            // `open_by_handle_at` decodes, generation included — a fid that
            // cannot be opened is not a fid.
            let (s_dev, ino, gen) = match &ev.obj {
                Some(o) => (o.fsid(), o.ino(), o.i_generation()),
                None => (0, 0, vfs::export::GENERATION_ANY),
            };
            let fh = fan_layout::fid_handle(ino, gen);
            off += fan_layout::encode_fid_info(&mut dst[off..total], t, s_dev,
                                               fan_layout::FANOTIFY_FID_TYPE, &fh, &ev.name);
        }
        if self.reports_pidfd() {
            let pidfd = self.install_pidfd(ev.pid);
            fan_layout::encode_pidfd_info(&mut dst[off..total], pidfd);
        }
        total
    }

    /// Move a permission event onto the group's pending list under the
    /// descriptor the daemon will answer with. Done BEFORE the metadata
    /// reaches the caller's buffer, so a response cannot race ahead of the
    /// event being findable.
    /// # C: O(1)
    fn report_perm_event(&self, st: &Arc<PermState>, fd: i32) {
        st.report();
        self.perm_pending.lock().push((fd, st.clone()));
    }
}

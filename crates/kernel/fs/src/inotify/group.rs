use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use crate::inotify::dispatch::register_instance;
use crate::inotify::types::{
    inode_key, InotifyData, PermEvent, FAN_ACCESS_PERM, FAN_ALLOW, FAN_DENY, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM,
    INOTIFY_INO_BASE, PERM_MARK_COUNT,
};

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

    /// Drain queued events into `buf` in Linux `struct inotify_event`
    /// shape: {wd: i32, mask: u32, cookie: u32, len: u32, name[len]}.
    /// v1 always emits len=0 (no name tail).
    pub(crate) fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.fanotify {
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
        if written == 0 { return Err(VfsError::Eagain); }
        Ok(written)
    }

    /// O_NONBLOCK read: never parks. fanotify drains once (EAGAIN if empty);
    /// inotify already drains non-blocking. # C: O(events drained)
    pub(crate) fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.fanotify { return self.read_fanotify(buf); }
        self.read(off, buf)
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
            if hit { arc.perm_queue.lock().push_back(ev.clone()); queued = true; }
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
    InodeBuilder::new(INOTIFY_INO_BASE, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), Arc::new(InotifyFileOps))
        .private(data)
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

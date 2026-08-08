// The event a monitor reads, the blocking read/poll that delivers it, and the
// ONE path every registration mode takes to hand a fault over.
//
// Adding a mode adds a flag to the message, not a delivery path: the queueing,
// the monitor wake, the poll notification, the block and the wake-generation
// protocol are written once here and shared, so no mode can drift into
// delivering differently from the others.

use core::sync::atomic::Ordering;

use vfs::{FileOps, Inode, KResult};
use vmm::UffdFaultKind;

use super::policy;
#[cfg(target_os = "oxide-kernel")]
use super::uapi;
use super::uapi::{UFFD_EVENT_PAGEFAULT, UFFD_PAGEFAULT_FLAG_MINOR,
                  UFFD_PAGEFAULT_FLAG_WP, UFFD_PAGEFAULT_FLAG_WRITE};
use super::UfData;

/// `struct uffd_msg` — 32 bytes per message. Field ORDER is ABI: a one-byte
/// event code, seven bytes of padding, then a THREE-SLOT union every message
/// type reuses. The slots are named by position, not by any one type's meaning,
/// because they hold different things per event:
///
/// ```text
/// PAGEFAULT  a0 = flags        a1 = address   a2 = thread id
/// FORK       a0 = descriptor   —              —
/// REMAP      a0 = from         a1 = to        a2 = length
/// REMOVE     a0 = start        a1 = end       —
/// UNMAP      a0 = start        a1 = end       —
/// ```
///
/// A monitor reads the fault address at byte 16 and the remap source at byte 8;
/// naming the slots after the pagefault arm is what makes that easy to get
/// wrong when a second event type is added.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdMsg {
    pub event:  u8,
    pub _r0:    u8,
    pub _r1:    u16,
    pub _r2:    u32,
    pub a0:     u64,
    pub a1:     u64,
    pub a2:     u64,
}

impl UffdMsg {
    /// The three-slot union, zeroed, under `event`. # C: O(1)
    pub fn new(event: u8, a0: u64, a1: u64, a2: u64) -> Self {
        UffdMsg { event, _r0: 0, _r1: 0, _r2: 0, a0, a1, a2 }
    }

    /// Fault address — slot 1 for a PAGEFAULT message. # C: O(1)
    pub fn addr(&self) -> u64 { self.a1 }

    /// Fault flags — slot 0 for a PAGEFAULT message. # C: O(1)
    pub fn flags(&self) -> u64 { self.a0 }
}

/// `i_fop` for a userfaultfd inode. # C: O(1)
pub(super) struct UffdFileOps;

impl FileOps for UffdFileOps {
    /// BLOCKING read: pop the next queued event; if the queue is empty, PARK
    /// until a fault enqueues one (interruptible). A short buffer is EINVAL.
    ///
    /// The handshake test runs BEFORE the short-buffer test, so a pre-handshake
    /// read with a short buffer is EINVAL for the handshake reason.
    /// # C: O(1) + block
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) {
            return Err(vfs::VfsError::Einval);
        }
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        loop {
            if let Some(r) = take_next(d, buf) { return r; }
            #[cfg(target_os = "oxide-kernel")]
            {
                // A pending signal ends the wait so the read restarts rather
                // than swallowing the signal.
                if sched::live::deliverable_signals_self() != 0 {
                    return Err(vfs::VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before we schedule, and a fault enqueue will wake read_waiters.
                unsafe { d.read_waiters.park(); }
                // SAFETY: process ctx; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a fault wake fires.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(vfs::VfsError::Eagain);
        }
    }

    /// Non-blocking read: EAGAIN on an empty queue, never EINVAL and never a
    /// park. # C: O(1)
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = match inode.private::<UfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) {
            return Err(vfs::VfsError::Einval);
        }
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        take_next(d, buf).unwrap_or(Err(vfs::VfsError::Eagain))
    }

    /// This description has a poll method. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// POLLIN iff an event is queued (a read won't block), POLLERR before the
    /// API handshake.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let Some(d) = inode.private::<UfData>() else { return 0 };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) { return vfs::POLL_ERR; }
        let g = d.state.lock();
        let ready = policy::next_message(!g.faults.is_empty(), !g.events.is_empty());
        if ready != policy::NextMessage::None { vfs::POLL_IN } else { 0 }
    }

    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// Pop whatever a reader should be handed next, or `None` when both queues are
/// empty. Faults first, always (`policy::next_message`).
///
/// A fork announcement can only be completed in the READING process, because
/// the descriptor it carries has to land in that process's table. If that
/// fails the announcement goes back to the FRONT of the queue and its
/// generator stays blocked — losing it would strand the forking thread
/// forever, and losing the child context would strand the child's faults.
/// # C: O(1)
fn take_next(d: &UfData, buf: &mut [u8]) -> Option<KResult<usize>> {
    enum Picked { Fault(UffdMsg), Event(super::PendingEvent) }
    let picked = {
        let mut g = d.state.lock();
        match policy::next_message(!g.faults.is_empty(), !g.events.is_empty()) {
            policy::NextMessage::Fault =>
                Picked::Fault(g.faults.pop_front().expect("a fault was reported queued")),
            policy::NextMessage::Event =>
                Picked::Event(g.events.pop_front().expect("an event was reported queued")),
            policy::NextMessage::None => return None,
        }
    };
    match picked {
        Picked::Fault(m) => Some(Ok(copy_msg_out(&m, buf))),
        Picked::Event(ev) => {
            let a0 = match ev.fork_child.as_ref() {
                None => ev.a0,
                Some(child) => match install_fork_fd(child.clone()) {
                    Ok(fd) => fd,
                    Err(e) => { d.state.lock().events.push_front(ev); return Some(Err(e)); }
                },
            };
            let n = copy_msg_out(&UffdMsg::new(ev.event, a0, ev.a1, ev.a2), buf);
            d.finish_event(&ev);
            Some(Ok(n))
        }
    }
}

/// Give the READING process a descriptor for a fork child's context.
///
/// The descriptor is created here rather than at fork time on purpose: the fork
/// happens in the process being monitored, and a descriptor minted there would
/// land in the wrong table — the monitor would never get it, and the monitored
/// process would hold a fd it has no use for.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn install_fork_fd(child: alloc::sync::Arc<UfData>) -> KResult<u64> {
    use vfs::{File, OpenFlags};
    let Some(cur) = sched::current() else { return Err(vfs::VfsError::Esrch) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(vfs::VfsError::Ebadf) };
    let fdt = fdt.clone();
    let flags = child.flags.load(Ordering::Acquire);
    let inode = super::inode_for(child);
    let dentry = vfs::dcache::d_alloc_pseudo("[userfaultfd]", inode.clone(),
                                             &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if flags & uapi::O_NONBLOCK != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let fd = fdt.alloc_limit(File::new(inode, dentry, fl), cur.nofile_soft())?;
    if flags & uapi::O_CLOEXEC != 0 { let _ = fdt.set_cloexec(fd, true); }
    Ok(fd as u64)
}

/// Hosted counterpart: there is no process to receive the descriptor, so the
/// announcement is left queued and its generator left blocked — the same arm
/// the live path takes when the reader's table is full.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn install_fork_fd(_child: alloc::sync::Arc<UfData>) -> KResult<u64> {
    Err(vfs::VfsError::Esrch)
}

/// Serialise one event into the caller's buffer. # C: O(1)
fn copy_msg_out(m: &UffdMsg, buf: &mut [u8]) -> usize {
    // SAFETY: UffdMsg is repr(C) + Copy with no padding-sensitive reads; transmute_copy reads exactly size_of::<UffdMsg>() bytes from the aligned `m`.
    let bytes: [u8; core::mem::size_of::<UffdMsg>()] = unsafe { core::mem::transmute_copy(m) };
    buf[..bytes.len()].copy_from_slice(&bytes);
    bytes.len()
}

/// The message flag each fault kind carries. A monitor registered for several
/// modes tells them apart by this alone, so the mapping lives in one place.
/// # C: O(1)
pub fn kind_flag(kind: UffdFaultKind) -> u64 {
    match kind {
        UffdFaultKind::Missing => 0,
        UffdFaultKind::Wp      => UFFD_PAGEFAULT_FLAG_WP,
        UffdFaultKind::Minor   => UFFD_PAGEFAULT_FLAG_MINOR,
    }
}

impl vmm::UffdContext for UfData {
    /// Enqueue a PAGEFAULT event for `addr`, wake the monitor and its pollers,
    /// then BLOCK this faulting thread until a resolve bumps the wake
    /// generation. Returns `true` so the fault handler retries the instruction
    /// — which either hits the now-resolved page or re-faults and re-enqueues.
    ///
    /// Returns `false` WITHOUT enqueueing when the fault came from kernel mode
    /// and this context is user-mode-only. That is what makes the flag mean
    /// something: it is the escape hatch every unprivileged caller is granted,
    /// so if it were unenforced an unprivileged uffd could still stall the
    /// KERNEL inside a copy-from-user on a registered page.
    /// # C: O(1) enqueue + block
    fn fault(&self, addr: u64, kind: UffdFaultKind, write: bool, user_mode: bool) -> bool {
        if !policy::may_deliver_fault(self.flags.load(Ordering::Acquire), user_mode) {
            return false;
        }
        let feats = self.features.load(Ordering::Acquire);
        // The tid is filled ONLY when the monitor negotiated the thread-id
        // feature; otherwise the field reads 0.
        #[cfg(target_os = "oxide-kernel")]
        let ptid = if feats & uapi::feature::THREAD_ID != 0 {
            sched::live::current().map(|c| c.tid as u64).unwrap_or(0)
        } else { 0 };
        #[cfg(not(target_os = "oxide-kernel"))]
        let ptid = 0u64;
        let msg = UffdMsg::new(UFFD_EVENT_PAGEFAULT,
                               kind_flag(kind) | if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
                               addr, ptid);
        let _ = feats;
        // Snapshot the wake generation BEFORE publishing: any resolve that
        // races between here and the park below advances it, so the loop
        // returns instead of sleeping through the wake.
        let start_gen = self.wake_gen.load(Ordering::Acquire);
        self.state.lock().faults.push_back(msg);
        self.read_waiters.wake_all();
        self.poll.notify();
        #[cfg(target_os = "oxide-kernel")]
        loop {
            if self.wake_gen.load(Ordering::Acquire) != start_gen { break; }
            // A deliverable (e.g. fatal) signal breaks the wait — return so the
            // fault path retries and the signal is delivered to userspace.
            if sched::live::deliverable_signals_self() != 0 { break; }
            // SAFETY: running (faulting) task; preempt-off; park marks Sleeping + bumps the Arc before schedule, and a resolve will wake fault_waiters.
            unsafe { self.fault_waiters.park(); }
            // SAFETY: fault ctx entered from user mode with a saved frame; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a resolve wake fires.
            unsafe { sched::live::schedule::schedule(); }
        }
        // Silence unused-var warning on hosted (no loop reads start_gen).
        let _ = start_gen;
        true
    }

    /// # C: O(1)
    fn wp_async(&self) -> bool { policy::wp_async(self.features.load(Ordering::Acquire)) }

    /// # C: O(1)
    fn wp_unpopulated(&self) -> bool {
        policy::wp_unpopulated(self.features.load(Ordering::Acquire))
    }

    /// # C: O(1)
    fn wants_event(&self, kind: vmm::UffdEventKind) -> bool { self.wants(kind) }

    /// # C: O(1)
    fn change_begin(&self) { self.charge_change(); }

    /// # C: O(1) enqueue + block
    fn change_complete(&self, ev: vmm::UffdEvent) { self.announce(ev); }

    /// # C: O(1)
    fn change_abort(&self) { self.release_change(); }

    /// # C: O(1)
    fn fork_dup(&self, child_mm: alloc::sync::Weak<vmm::AddressSpace>)
        -> Option<alloc::sync::Arc<dyn vmm::UffdContext>> {
        if !self.wants(vmm::UffdEventKind::Fork) { return None; }
        Some(self.dup_for_fork(child_mm))
    }
}

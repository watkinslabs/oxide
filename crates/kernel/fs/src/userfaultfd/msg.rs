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

/// `struct uffd_msg` — 32 bytes per event. Field ORDER is ABI: the pagefault
/// arm places `flags` at byte 8 and `address` at byte 16 (a real monitor reads
/// the address at offset 16), with the thread id at byte 24.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdMsg {
    pub event:  u8,
    pub _r0:    u8,
    pub _r1:    u16,
    pub _r2:    u32,
    pub flags:  u64,
    pub addr:   u64,
    pub ptid:   u64,
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
            if let Some(m) = d.state.lock().events.pop_front() {
                return Ok(copy_msg_out(&m, buf));
            }
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
        match d.state.lock().events.pop_front() {
            Some(m) => Ok(copy_msg_out(&m, buf)),
            None    => Err(vfs::VfsError::Eagain),
        }
    }

    /// This description has a poll method. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// POLLIN iff an event is queued (a read won't block), POLLERR before the
    /// API handshake.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let Some(d) = inode.private::<UfData>() else { return 0 };
        if !policy::is_initialized(d.features.load(Ordering::Acquire)) { return vfs::POLL_ERR; }
        if !d.state.lock().events.is_empty() { vfs::POLL_IN } else { 0 }
    }

    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(vfs::VfsError::Einval) }
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
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _r0: 0, _r1: 0, _r2: 0,
            addr,
            flags: kind_flag(kind) | if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
            ptid,
        };
        let _ = feats;
        // Snapshot the wake generation BEFORE publishing: any resolve that
        // races between here and the park below advances it, so the loop
        // returns instead of sleeping through the wake.
        let start_gen = self.wake_gen.load(Ordering::Acquire);
        self.state.lock().events.push_back(msg);
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
}

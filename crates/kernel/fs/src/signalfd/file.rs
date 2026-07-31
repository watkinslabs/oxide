//! signalfd inode + file operations: readiness, dequeue, blocking read and
//! `/proc/<pid>/fdinfo/<n>` rendering.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{File, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers,
    VfsError, default_inode_ops, mk_mode};

use super::siginfo;
use super::uapi::SIGINFO_SIZE;

mod ids {
    use vfs::Ino;
    pub(crate) const INO_BASE: Ino = 0x7200_0000;
}

/// Per-inode signalfd state (Linux `signalfd_ctx`): the accepted signal mask.
/// Stored in POSITIVE form (bits set = signals this fd drains), which is also
/// the form `fdinfo` reports.
pub struct SignalfdData {
    pub mask: AtomicU64,
}

/// Build a signalfd pseudo-inode owning `mask`. # C: O(1)
pub fn make_signalfd_inode(mask: u64) -> InodeRef {
    InodeBuilder::new(ids::INO_BASE, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), Arc::new(SignalfdFileOps))
        .private(Arc::new(SignalfdData { mask: AtomicU64::new(mask) }))
        .build()
}

/// Linux `do_sigpending`'s union — thread-private OR process-directed pending.
/// A signalfd that inspected only its own thread's set was blind to every
/// process-directed `kill(2)`, which is the common case for a service manager.
/// # C: O(1)
pub(super) fn all_pending(task: &sched::Task) -> u64 {
    task.pending_signals() | task.thread_group.shared_pending()
}

/// `i_fop` for a signalfd inode. # C: O(1)
pub(super) struct SignalfdFileOps;

impl FileOps for SignalfdFileOps {
    /// Blocking `read(2)`: fill as many complete records as `buf` holds,
    /// parking until the first one arrives. Only the FIRST dequeue may sleep —
    /// once a record is in hand the read returns what it has rather than
    /// waiting for the buffer to fill.
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        read_records(inode, buf, false)
    }

    /// Non-blocking `read(2)` (`O_NONBLOCK` / `SFD_NONBLOCK`): EAGAIN when no
    /// masked signal is pending.
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        read_records(inode, buf, true)
    }

    /// A signalfd is opened `O_RDWR` but has no write operation.
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    /// POLLIN only when a signal in this fd's mask is pending for the calling
    /// thread OR for its process. The default always-ready poll made epoll
    /// spin: a service manager registers a signalfd, so an always-ready poll
    /// busy-looped `epoll_pwait` forever.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let mask = match inode.private::<SignalfdData>() {
            Some(d) => d.mask.load(Ordering::Acquire), None => return 0,
        };
        let cur = sched::current();
        let deliver = cur.as_ref().map_or(0, |c| all_pending(c)) & mask;
        if deliver != 0 { vfs::POLL_IN } else { 0 }
    }

    fn poll_subscribers(&self, _file: &File) -> Option<Arc<PollSubscribers>> {
        sched::current().map(|c| c.sigpending.poll_subscribers())
    }

    /// `show_fdinfo`: `sigmask:\t` plus the ACCEPTED set as 16 hex nibbles,
    /// most significant first (signal 64 is the top bit of the first nibble).
    /// # C: O(1)
    fn fdinfo_extra(&self, inode: &Inode, out: &mut Vec<u8>) {
        let Some(d) = inode.private::<SignalfdData>() else { return };
        let rendered = d.mask.load(Ordering::Acquire);
        out.extend_from_slice(b"sigmask:\t");
        for shift in (0..16).rev() {
            let nib = ((rendered >> (shift * 4)) & 0xf) as u8;
            out.push(if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) });
        }
        out.push(b'\n');
    }
}

/// Linux `signalfd_read_iter`: `count / sizeof(record)` records, EINVAL when
/// the buffer cannot hold even one. `total ? total : ret` — an error after at
/// least one record is swallowed and the short count returned.
/// # C: O(records)
fn read_records(inode: &Inode, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
    if buf.len() < SIGINFO_SIZE { return Err(VfsError::Einval); }
    let d = match inode.private::<SignalfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
    let cur = match sched::current() { Some(c) => c, None => return Err(VfsError::Eagain) };
    let mut total = 0;
    // Linux re-reads ctx->sigmask on every dequeue; an update through
    // `signalfd(fd, …)` on another thread must take effect mid-read.
    let mut blocking = !nonblock;
    while total + SIGINFO_SIZE <= buf.len() {
        let mask = d.mask.load(Ordering::Acquire);
        match dequeue(&cur, mask, blocking) {
            Ok((sig, rec)) => {
                siginfo::encode(sig, rec.as_ref(), &mut buf[total..total + SIGINFO_SIZE]);
                total += SIGINFO_SIZE;
                // Only the first record may wait.
                blocking = false;
            }
            Err(e) => { if total != 0 { break; } return Err(e); }
        }
    }
    Ok(total)
}

/// Linux `signalfd_dequeue`: claim one pending signal inside `mask`, selected
/// by `next_signal`. Blocking waits until one arrives; `ERESTARTSYS` when a signal
/// OUTSIDE the mask becomes deliverable first (Linux restarts the read rather
/// than reporting EINTR, so an `SA_RESTART` handler resumes it).
/// # C: O(1) per attempt
fn dequeue(cur: &sched::Task, mask: u64, blocking: bool)
    -> Result<(u32, Option<sched::SigInfo>), VfsError>
{
    loop {
        if let Some(sig) = sched::signum::next_signal(all_pending(cur), mask) {
            // One owner of the private-then-shared claim protocol, shared with
            // `rt_sigtimedwait` and handler delivery. `None` = a concurrent
            // consumer won the claim; re-loop.
            if let Some(rec) = cur.dequeue_pending(sig) { return Ok((sig, rec)); }
            continue;
        }
        if !blocking { return Err(VfsError::Eagain); }
        #[cfg(target_os = "oxide-kernel")]
        {
            if sched::live::sigpend::deliverable_signals_self() & !mask != 0 {
                super::wait::leave();
                return Err(VfsError::Erestartsys);
            }
            // Publish Sleeping BEFORE the post-park recheck; a concurrent
            // sender either observes it and enqueues us, or lands just before
            // and the recheck catches it.
            super::wait::park();
            if all_pending(cur) & mask != 0
                || sched::live::sigpend::deliverable_signals_self() & !mask != 0
            {
                super::wait::cancel();
                continue;
            }
            super::wait::yield_now();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(VfsError::Eagain);
    }
}

#[cfg(test)]
mod tests;

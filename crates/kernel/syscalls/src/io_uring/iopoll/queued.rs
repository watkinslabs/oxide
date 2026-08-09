// Submit-then-poll: a transfer on a polled ring that is handed to its backend
// and returns with NO completion posted, to be completed later by the poll.
//
// This is the half of `IORING_SETUP_IOPOLL` that makes the mode pay for
// anything. Every other read and write in this kernel finishes inside the call
// that issued it, which meant a polled transfer had already posted its result
// before the poll loop could look at it: the loop's precheck saw a completion
// waiting and returned, and the poll was load-bearing only for work a worker
// happened to be holding. Linux's `-EIOCBQUEUED` arm is what closes that, and
// this is it.
//
// Ownership, which is where a double completion or a use-after-free would
// live:
//   * the backend's completion continuation owns an `Arc<Queued>` and nothing
//     else — it fills a slot and never touches the request, the ring, or user
//     memory, so it is safe from any context and at any time, including after
//     the ring is gone;
//   * the request owns the other `Arc<Queued>`, so the slot outlives whichever
//     of the two ends last;
//   * exactly one completion is posted because the reaper goes through
//     `IoReq::claim`, the same compare-exchange a cancellation and a deadline
//     go through. A cancelled request is claimed by the canceller, and the
//     backend's later completion then fills a slot nobody reads.
//
// The bytes never move in the backend's context. A read's landing zone is a
// kernel buffer the transfer owns; it is scattered into the caller's memory by
// the REAPER, which runs in a task, and into the submitter's address space by
// its page-table root rather than through whatever address space the reaper
// happens to be in.

use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use syscall::errno::Errno;
use vfs::file_ops::{DirectIo, DirectSubmit};
use vfs::File;

use sync::{Spinlock, TaskList as QueuedLockClass};

use crate::io_uring_abi::iopoll::{admit_rw, is_write, RwTarget};

use super::super::req::IoReq;

/// Where a transfer's bytes come from, and where a completed read puts them.
enum Sink {
    /// Segments of the SUBMITTER's user memory. Written through the address
    /// space's page-table root, never through the current one: the task that
    /// reaps a polled ring need not be the task that submitted to it.
    User(Vec<(u64, usize)>),
    /// A window inside a registered buffer. Kernel memory, pinned at
    /// registration, so it needs no address space at all.
    Fixed { buf: Arc<super::super::pin::PinnedRange>, off: u64 },
}

/// One transfer the backend owns.
pub struct Queued {
    sink: Sink,
    /// Filled once, by the backend's completion. `None` until then.
    slot: Spinlock<Option<(Vec<u8>, Result<usize, vfs::VfsError>)>, QueuedLockClass>,
    /// Published by the completion AFTER the slot, read before it.
    ready: AtomicBool,
    /// Monotonic nanoseconds when the transfer was issued — the reference's
    /// `req->iopoll_start`, and the base its hybrid service-time estimate is
    /// measured from.
    issued_at: AtomicU64,
    /// This transfer has already paid the hybrid sleep. The reference's
    /// `REQ_F_IOPOLL_STATE`: the sleep skips the front of one transfer's
    /// service time, so paying it once per poll pass would make a device
    /// slower the more often it was polled.
    slept: AtomicBool,
}

impl Queued {
    /// # C: O(1)
    fn new(sink: Sink) -> Arc<Self> {
        Arc::new(Self {
            sink,
            slot: Spinlock::new(None),
            ready: AtomicBool::new(false),
            issued_at: AtomicU64::new(0),
            slept: AtomicBool::new(false),
        })
    }

    /// # C: O(1)
    pub fn is_ready(&self) -> bool { self.ready.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn issued_at(&self) -> u64 { self.issued_at.load(Ordering::Acquire) }

    /// Whether this transfer still owes the hybrid sleep, marking it paid.
    /// # C: O(1)
    pub fn take_sleep_turn(&self) -> bool { !self.slept.swap(true, Ordering::AcqRel) }
}

/// Gather the transfer's segments and its byte count out of the entry, in the
/// SUBMITTING task: an iovec array and a user address mean nothing once the
/// submitting call has returned. # C: O(iovcnt)
fn sink_of(req: &Arc<IoReq>) -> Result<(Sink, usize), Errno> {
    use crate::io_uring_abi::ops::*;
    let sqe = &req.sqe;
    match sqe.opcode {
        IORING_OP_READ | IORING_OP_WRITE =>
            Ok((Sink::User(alloc::vec![(sqe.addr, sqe.len as usize)]), sqe.len as usize)),
        IORING_OP_READV | IORING_OP_WRITEV => {
            let dir = if is_write(sqe.opcode) { crate::iov::IovDir::Source } else { crate::iov::IovDir::Dest };
            let segs = crate::iov::import_iovec(sqe.addr, sqe.len as u64, dir)
                .map_err(|_| Errno::Efault)?;
            let total = segs.iter().map(|s| s.1).sum();
            Ok((Sink::User(segs), total))
        }
        IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED => {
            let buf = {
                let g = req.ring.reg.lock();
                let bufs = g.buffers.as_ref().ok_or(Errno::Efault)?;
                let slot = bufs.get(sqe.buf_index as usize).ok_or(Errno::Efault)?;
                Arc::clone(&slot.buf)
            };
            if buf.is_empty() { return Err(Errno::Efault); }
            let off = sqe.addr.checked_sub(buf.base).ok_or(Errno::Efault)?;
            Ok((Sink::Fixed { buf, off }, sqe.len as usize))
        }
        _ => Err(Errno::Einval),
    }
}

/// Fill the transfer's kernel buffer from the caller's bytes — a write's
/// payload, read in the submitting task before it leaves. # C: O(len)
fn gather(sink: &Sink, len: usize) -> Result<Vec<u8>, Errno> {
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(len).map_err(|_| Errno::Enomem)?;
    out.resize(len, 0);
    match sink {
        Sink::User(segs) => {
            let mut at = 0usize;
            for &(va, n) in segs {
                let n = core::cmp::min(n, len - at);
                if n == 0 { break; }
                // SAFETY: raw_copy_from_user is the extable-protected copy; `out` is a kernel Vec writable for `n` bytes at `at`, and the segment was validated by the importer.
                let left = unsafe { uaccess::raw_copy_from_user(out[at..].as_mut_ptr(), va, n) };
                if left != 0 { return Err(Errno::Efault); }
                at += n;
            }
        }
        Sink::Fixed { buf, off } => {
            buf.read_at(*off, &mut out[..]).map_err(|_| Errno::Efault)?;
        }
    }
    Ok(out)
}

/// Put a completed read's bytes where the caller asked for them. Returns how
/// many actually landed, which is what the completion reports: a caller told it
/// read more bytes than reached its buffer would act on data that is not there.
/// # C: O(n)
fn scatter(sink: &Sink, root_pa: u64, src: &[u8]) -> usize {
    match sink {
        Sink::User(segs) => {
            let mut at = 0usize;
            for &(va, n) in segs {
                let n = core::cmp::min(n, src.len() - at);
                if n == 0 { break; }
                // SAFETY: the request holds the submitter's AddressSpace Arc for its whole life, so `root_pa` names live page tables; write_foreign_user refuses non-writable leaves and stops at the first unmapped one.
                let put = unsafe { pmm::user_as::write_foreign_user(root_pa, va, &src[at..at + n]) };
                at += put;
                if put < n { break; }
            }
            at
        }
        Sink::Fixed { buf, off } => {
            let mut at = 0usize;
            buf.for_each_chunk(*off, src.len() as u64, |chunk| {
                let n = core::cmp::min(chunk.len(), src.len() - at);
                if n == 0 { return None; }
                chunk[..n].copy_from_slice(&src[at..at + n]);
                at += n;
                Some(n)
            }).ok();
            at
        }
    }
}

/// Whether this entry's DESCRIPTION can serve a queued transfer at all — the
/// reference's `io_rw_init_file` ladder, asked before the entry is committed to
/// the submit-then-poll path.
///
/// Asked HERE rather than during preparation so that a description which cannot
/// serve one keeps the ordinary path, where the very same ladder reports
/// `EOPNOTSUPP` as the operation's result. Reporting it from preparation
/// instead would make it a SUBMISSION failure, which stops the rest of the
/// batch — a caller that submitted eight entries would see seven of them
/// silently not run because the first named a buffered file. # C: O(1)
pub fn eligible(fd: i32) -> bool {
    let Ok(file) = resolve(fd) else { return false };
    admit_rw(&RwTarget {
        ring_iopoll: true,
        direct: file.flags().contains(vfs::OpenFlags::O_DIRECT),
        file_pollable: file.can_iopoll(),
        hipri: false,
    }).is_ok()
}

/// Read whatever this transfer needs out of the submitter's address space.
///
/// Never fails the submission. Anything that stops a transfer being prepared —
/// an unreadable iovec array, a registered buffer that is not there, no memory
/// for the landing zone — leaves the request without queued state, and it then
/// takes the ordinary path, which reports exactly the errno it always did. A
/// preparation that reported its own errno would turn an operation's result
/// into a submission failure and take the rest of the batch down with it.
/// # C: O(len)
pub fn prepare(req: &Arc<IoReq>) -> Result<(), Errno> {
    let _ = try_prepare(req);
    Ok(())
}

/// # C: O(len)
fn try_prepare(req: &Arc<IoReq>) -> Result<(), Errno> {
    let file = resolve(req.sqe.fd)?;
    let (sink, len) = sink_of(req)?;
    let buf = if is_write(req.sqe.opcode) { gather(&sink, len)? } else {
        let mut v: Vec<u8> = Vec::new();
        v.try_reserve(len).map_err(|_| Errno::Enomem)?;
        v.resize(len, 0);
        v
    };
    let q = Queued::new(sink);
    let mut g = req.inner.lock();
    g.iopoll_file = Some(file);
    g.iopoll_buf = Some(buf);
    g.iopoll_io = Some(q);
    Ok(())
}

/// The description an entry names, in the submitting task. # C: O(1)
fn resolve(fd: i32) -> Result<Arc<File>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU in the submission path; sole reader of the fd_table slot, which is not mutated across this read.
    let fdt = (unsafe { cur.fd_table_ref() }).ok_or(Errno::Ebadf)?;
    fdt.clone().get(fd).map_err(|_| Errno::Ebadf)
}

/// Hand the prepared transfer to its backend. `Ok(true)` means the backend
/// owns it and the poll will complete it; `Ok(false)` means this backend queues
/// nothing, so the caller runs the operation the ordinary way instead of
/// leaving a request nothing will ever finish. # C: O(1)
pub fn issue(req: &Arc<IoReq>) -> Result<bool, Errno> {
    let (file, buf, q) = {
        let mut g = req.inner.lock();
        let Some(q) = g.iopoll_io.clone() else { return Ok(false) };
        let Some(file) = g.iopoll_file.clone() else { return Ok(false) };
        let Some(buf) = g.iopoll_buf.take() else { return Ok(false) };
        (file, buf, q)
    };
    let sink = Arc::clone(&q);
    q.issued_at.store(timekeeper::monotonic_ns(), Ordering::Release);
    let io = DirectIo {
        write: is_write(req.sqe.opcode),
        off: req.sqe.off,
        buf,
        done: alloc::boxed::Box::new(move |buf, res| {
            *sink.slot.lock() = Some((buf, res));
            // Published last: a reaper that saw the flag must see the slot.
            sink.ready.store(true, Ordering::Release);
        }),
    };
    match file.submit_direct(io) {
        DirectSubmit::Queued => {
            // Tracked BEFORE the poll can run, and strongly: nothing else holds
            // a queued transfer, so a request dropped here would leave its
            // completion with nowhere to be posted.
            req.ring.track_queued(req);
            req.ring.track(req);
            Ok(true)
        }
        DirectSubmit::Failed(e) => Err(crate::io_uring_abi::iopoll::submit_errno(e)),
        DirectSubmit::Unsupported(io) => {
            // Nothing was queued and the completion never ran; give the buffer
            // back so the fallback path does not have to rebuild it.
            let mut g = req.inner.lock();
            g.iopoll_buf = Some(io.buf);
            g.iopoll_io = None;
            Ok(false)
        }
    }
}

/// Complete every transfer whose backend has finished, and report how many
/// completions were posted.
///
/// Exactly one completion per request, guaranteed by `claim`: a request a
/// cancellation already took is not claimed here, and its backend's completion
/// then fills a slot nobody reads. # C: O(N_inflight)
pub fn reap(inode: &Arc<super::super::ctx::IoUringInode>) -> usize {
    let mut posted = 0usize;
    for req in inode.queued_reqs() {
        let q = { let g = req.inner.lock(); g.iopoll_io.clone() };
        let Some(q) = q else { continue };
        if !q.is_ready() { continue; }
        if !req.claim() { continue; }
        let taken = q.slot.lock().take();
        let res = match taken {
            None => -(Errno::Eio.as_i32() as i64),
            Some((buf, Err(e))) => {
                drop(buf);
                -(crate::io_uring_abi::iopoll::submit_errno(e).as_i32() as i64)
            }
            Some((buf, Ok(n))) => {
                let write = is_write(req.sqe.opcode);
                let n = core::cmp::min(n, buf.len());
                let landed = if write { n } else {
                    let root = req.owner.mm.as_ref().map(|m| m.root_pa());
                    match (&q.sink, root) {
                        (Sink::Fixed { .. }, _) => scatter(&q.sink, 0, &buf[..n]),
                        (Sink::User(_), Some(root)) => scatter(&q.sink, root, &buf[..n]),
                        // No address space to write into: the submitter is gone,
                        // so the bytes have nowhere to land.
                        (Sink::User(_), None) => 0,
                    }
                };
                crate::io_uring_abi::iopoll::completed_res(write, n, landed)
            }
        };
        // The request leaves the polled set before its completion is posted, so
        // a poll pass that races this one finds nothing left to reap for it.
        req.inner.lock().iopoll_io = None;
        inode.untrack_queued(&req);
        super::super::iowq::run::complete(&req, res, 0);
        posted += 1;
    }
    posted
}

// `f_op->read_iter`/`write_iter` under `IOCB_DIRECT | IOCB_HIPRI`: a transfer
// handed to the backend that returns WITHOUT having completed.
//
// This is Linux's `-EIOCBQUEUED` arm, and it exists for exactly one caller —
// a polled io_uring ring. Every other read and write in this kernel finishes
// inside the call that issued it, which is correct and is also why polling had
// nothing to find: a transfer that has already posted its result is not a
// transfer a poll can complete. Submit-then-poll is the missing half.
//
// The buffer is OWNED by the transfer and handed back through the completion,
// rather than being a borrowed user slice: the backend fills it after the
// submitting call has returned, possibly on another CPU, and a user address is
// meaningless at that point. Whoever queued the transfer copies the bytes
// where they belong when it reaps the completion.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::types::VfsError;

/// What runs when a queued direct transfer finishes: the buffer it owned, and
/// how many bytes moved (or why none did).
///
/// `Send` because it runs from wherever the backend's completion path runs —
/// a driver's used-ring drain, a softirq, or the poll that reaped it.
pub type DirectDone = Box<dyn FnOnce(Vec<u8>, Result<usize, VfsError>) + Send>;

/// One direct transfer to queue.
pub struct DirectIo {
    /// The bytes move OUT of `buf` to the backend.
    pub write: bool,
    /// Byte offset into the description's backing store.
    pub off: u64,
    /// The write payload, or the landing zone a read fills. Its length is the
    /// transfer length; a backend never resizes it.
    pub buf: Vec<u8>,
    /// Runs exactly once, unless the submission was refused.
    pub done: DirectDone,
}

impl DirectIo {
    /// # C: O(1)
    pub fn len(&self) -> usize { self.buf.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }
}

/// What a [`super::FileOps::submit_direct`] attempt did.
///
/// Three outcomes rather than a `Result`, because "this backend has no direct
/// path" is not a failure of the transfer: the caller falls back to the
/// ordinary synchronous read or write and the operation still succeeds. Giving
/// the request back on that arm is what lets it do so without rebuilding the
/// buffer it already filled.
pub enum DirectSubmit {
    /// The backend owns the transfer. `done` will run exactly once, later.
    Queued,
    /// This backend queues nothing. `done` has NOT run; the request is
    /// returned intact for the caller to serve some other way.
    Unsupported(DirectIo),
    /// The transfer was refused before it was queued — a misaligned offset, a
    /// length past the end of the device. `done` has NOT run.
    Failed(VfsError),
}

impl DirectSubmit {
    /// # C: O(1)
    pub fn is_queued(&self) -> bool { matches!(self, Self::Queued) }
}

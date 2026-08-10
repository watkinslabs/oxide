// The copy fallback's decision: how one contiguous run of received bytes is
// spread over buffers taken from the instance's freelist, and what that one
// operation reports.
//
// Two things here are contract rather than bookkeeping, and both are wrong in
// the obvious implementation:
//
//   * the copy counter counts OPERATIONS, not buffers. A caller reading the
//     statistics record is asking how many times the stack had to fall back to
//     copying, and a run that happened to need four buffers is still one
//     fallback. Counting buffers makes the number a function of the buffer size
//     the caller chose, which tells it nothing.
//   * running out of buffers mid-run is a SHORT copy, not a failure, and it
//     posts no notification of its own. The no-buffers notification belongs to
//     the allocation path a bound device queue draws through; posting it here
//     as well would report the same shortage twice, once per receive, to a
//     caller that has already been told.
//
// A run that placed nothing is the only failure, and it is `ENOMEM`: the
// caller has handed nothing back, so the receive could not start. Reporting
// zero bytes instead would be indistinguishable from an empty socket.

use syscall::errno::Errno;

use super::ZCRX_NOTIF_COPY;

/// What one copy operation did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopyReport {
    /// Bytes placed in the caller's area.
    pub copied: usize,
    /// Added to the copy-operation counter.
    pub copy_count: u64,
    /// Added to the copied-byte counter.
    pub copy_bytes: u64,
    /// The one notification this operation posts, if any.
    pub notif: Option<u32>,
}

/// Spread `total` bytes over buffers of `buf_len`, calling `place(off, len)`
/// once per buffer. `place` reports whether a buffer was available AND filled;
/// a false stops the run where it is.
///
/// | outcome | result |
/// |---|---|
/// | every byte placed | `Ok`, one operation counted, copy notification |
/// | some bytes placed, then no buffer | `Ok` with the short count, one operation counted, copy notification |
/// | no bytes placed | `Err(ENOMEM)`, nothing counted, no notification |
/// # C: O(total / buf_len)
pub fn copy_run(total: usize, buf_len: usize, mut place: impl FnMut(usize, usize) -> bool)
    -> Result<CopyReport, Errno>
{
    let mut copied = 0usize;
    if buf_len != 0 {
        while copied < total {
            let take = core::cmp::min(buf_len, total - copied);
            if !place(copied, take) { break; }
            copied += take;
        }
    }
    if copied == 0 { return Err(Errno::Enomem); }
    Ok(CopyReport {
        copied,
        copy_count: 1,
        copy_bytes: copied as u64,
        notif: Some(ZCRX_NOTIF_COPY),
    })
}

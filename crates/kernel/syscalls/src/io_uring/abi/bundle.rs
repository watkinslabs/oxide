// Bundled send/receive: one operation spanning a RUN of provided buffers.
//
// An ordinary `IOSQE_BUFFER_SELECT` operation draws exactly one buffer. A
// bundle draws as many CONTIGUOUS buffers as the transfer needs, starting at
// the group's head, and reports the run as a single completion: `res` is the
// total byte count and `flags` carries the FIRST buffer's id, so the caller
// walks forward from it by its own buffer sizes. That is the whole of the
// `IORING_FEAT_RECVSEND_BUNDLE` contract.
//
// Ungated on purpose: every decision here — how many entries a transfer maps,
// which of them the transfer consumed, and what the completion says about
// them — is arithmetic over the ring's published entries, and the dispatch
// files that call it are kernel-gated (CLAUDE.md phantom-test rule).

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::ops::{IORING_OP_RECV, IORING_OP_RECVMSG, IORING_OP_SEND, IORING_OP_SENDMSG,
                 IOSQE_BUFFER_SELECT};

/// `IORING_RECVSEND_BUNDLE` — the `ioprio` bit asking for a bundle.
pub const IORING_RECVSEND_BUNDLE: u16 = 1 << 4;

/// Most entries one transfer maps, whatever the ring holds. One page of
/// segment descriptors even at the smallest buffer size.
pub const PEEK_MAX_IMPORT: usize = 256;
/// Most entries a single message may span, matching the vectored-I/O bound.
pub const UIO_MAXIOV: usize = 1024;
/// The mapped length a transfer is capped at when the entry names none.
pub const NO_LEN_CAP: u64 = i32::MAX as u64;

/// One entry as the caller published it in the provided-buffer ring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BufEntry {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
}

/// One mapped piece of a bundle: a whole published buffer, or the head of one
/// when the transfer's cap fell inside it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seg {
    pub addr: u64,
    pub len: u32,
}

/// What one transfer mapped out of the ring.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan {
    /// The id the completion reports; the run walks forward from it.
    pub first_bid: u16,
    /// Total bytes mapped.
    pub total: u64,
    /// A buffer was mapped short of its published length because the
    /// transfer's cap fell inside it, and the group does not consume
    /// incrementally — so the tail of that buffer is lost to this operation.
    pub partial_map: bool,
}

/// Whether the entry asks for a bundle at all. # C: O(1)
pub fn wants_bundle(ioprio: u16) -> bool { ioprio & IORING_RECVSEND_BUNDLE != 0 }

/// Whether a bundle actually governs this entry. The bit is meaningful only on
/// the two opcodes that read `ioprio` as their own flag word AND only when the
/// entry takes its buffer from a group: without a group there is no run to
/// draw, and the entry is an ordinary single-buffer transfer.
/// # C: O(1)
pub fn effective(opcode: u8, sqe_flags: u8, ioprio: u16) -> bool {
    wants_bundle(ioprio)
        && sqe_flags & IOSQE_BUFFER_SELECT != 0
        && matches!(opcode, IORING_OP_SEND | IORING_OP_RECV)
}

/// The refusal a bundle earns at admission. A message-carrying send or receive
/// describes its own scatter list, so a run of provided buffers has no
/// meaning there and the entry is malformed rather than merely inert.
/// # C: O(1)
pub fn admit(opcode: u8, ioprio: u16) -> Result<(), Errno> {
    if !wants_bundle(ioprio) { return Ok(()); }
    if matches!(opcode, IORING_OP_SENDMSG | IORING_OP_RECVMSG) { return Err(Errno::Einval); }
    Ok(())
}

/// How many published entries a transfer may look at: what the caller has
/// published, bounded by the per-message segment limit.
/// # C: O(1)
pub fn peek_window(available: u32) -> usize {
    core::cmp::min(available as usize, UIO_MAXIOV)
}

/// Map a run of published entries into transfer segments.
///
/// `max_len` is the entry's own length, or zero for "as much as the run
/// holds". The run is cut where the cap lands: on an incremental group the
/// last buffer is mapped short and keeps its remainder for the next operation,
/// and on an ordinary group a LATER buffer that would be cut is dropped
/// instead — cutting it would consume the whole buffer to deliver part of it.
/// The FIRST buffer is always mapped, cut or not, because a bundle that maps
/// nothing has no completion to report.
/// # C: O(entries)
pub fn plan(entries: &[BufEntry], max_len: u64, incremental: bool, out: &mut Vec<Seg>)
    -> Result<Plan, Errno>
{
    if entries.is_empty() { return Err(Errno::Enobufs); }
    let mut left = max_len;
    let mut window = entries.len();
    if left != 0 {
        let first = entries[0].len as u64;
        if first == 0 { return Err(Errno::Enobufs); }
        let needed = left.div_ceil(first);
        let needed = core::cmp::min(needed, PEEK_MAX_IMPORT as u64);
        if window as u64 > needed { window = needed as usize; }
    } else {
        left = NO_LEN_CAP;
    }

    let first_bid = entries[0].bid;
    let mut total = 0u64;
    let mut partial_map = false;
    if out.try_reserve(window).is_err() { return Err(Errno::Enomem); }
    for (i, e) in entries[..window].iter().enumerate() {
        let mut len = e.len as u64;
        if len > left {
            len = left;
            if !incremental {
                partial_map = true;
                if i != 0 { break; }
            }
        }
        out.push(Seg { addr: e.addr, len: len as u32 });
        total += len;
        left -= len;
        if left == 0 { break; }
    }
    Ok(Plan { first_bid, total, partial_map })
}

/// How many of the mapped segments a transfer of `transferred` bytes touched.
/// A segment the transfer only partly filled still counts: the operation wrote
/// into that buffer, so the caller must not see it handed out again.
/// # C: O(segments)
pub fn nbufs_for(segs: &[Seg], transferred: u64) -> usize {
    if transferred == 0 { return 0; }
    let mut left = transferred;
    let mut n = 0usize;
    for s in segs {
        n += 1;
        let this = core::cmp::min(s.len as u64, left);
        left -= this;
        if left == 0 { break; }
    }
    n
}

/// What an incremental group's head does after a transfer of `len` bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IncCommit {
    /// Entries the transfer used up whole; the head advances past them and
    /// their published length becomes zero.
    pub whole: usize,
    /// The entry the transfer stopped inside, rewritten to what is left of it:
    /// `(addr, len)`. The head does NOT move past it — the same buffer id
    /// serves the next operation, which is what the completion's
    /// "this id will be used again" flag tells the caller.
    pub partial: Option<(u64, u32)>,
}

impl IncCommit {
    /// Whether the transfer left a buffer part-used. # C: O(1)
    pub fn buf_more(&self) -> bool { self.partial.is_some() }
}

/// Walk an incremental group's head over `len` transferred bytes.
///
/// `min_left_sub_one` is one less than the smallest remainder worth keeping,
/// as the group was registered: a buffer whose remainder does not exceed it is
/// retired whole rather than handed back nearly empty.
/// # C: O(entries consumed)
pub fn inc_commit(entries: &[BufEntry], len: u64, min_left_sub_one: u32) -> IncCommit {
    // No bytes moved: the buffer is untouched and must stay available, so
    // nothing is consumed and nothing is rewritten.
    if len == 0 { return IncCommit { whole: 0, partial: None }; }
    let mut left = len;
    let mut whole = 0usize;
    for e in entries {
        if left == 0 { break; }
        let buf_len = e.len as u64;
        let this = core::cmp::min(left, buf_len);
        let rem = buf_len - this;
        if rem > min_left_sub_one as u64 || this == 0 {
            return IncCommit { whole, partial: Some((e.addr.wrapping_add(this), rem as u32)) };
        }
        whole += 1;
        left -= this;
    }
    IncCommit { whole, partial: None }
}

/// `IORING_CQE_F_BUFFER` plus the run's first id, and the "this id will be
/// used again" flag when an incremental buffer is only part-used.
/// # C: O(1)
pub fn cqe_flags(first_bid: u16, buf_more: bool) -> u32 {
    use super::ops::{IORING_CQE_BUFFER_SHIFT, IORING_CQE_F_BUFFER, IORING_CQE_F_BUF_MORE};
    let mut f = IORING_CQE_F_BUFFER | ((first_bid as u32) << IORING_CQE_BUFFER_SHIFT);
    if buf_more { f |= IORING_CQE_F_BUF_MORE; }
    f
}

#[cfg(test)]
#[path = "bundle/tests.rs"]
mod tests;

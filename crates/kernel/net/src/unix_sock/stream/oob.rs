// Out-of-band (`MSG_OOB`) data on an AF_UNIX `SOCK_STREAM` pair: the queue
// state, and the boundary rules a normal receive obeys around it.
//
// A stream carries at most ONE byte awaiting `recv(MSG_OOB)`. Sending one
// appends it to the queue and records its absolute stream offset; a second
// out-of-band send while the first is unread REPLACES the record, demoting the
// earlier byte to ordinary in-band data. The byte a `recv(MSG_OOB)` delivers
// stays queued as a spent record whose only remaining job is to bound a
// receive.
//
// A normal (not `MSG_OOB`) receive walking onto an out-of-band position:
//
// - having already copied bytes, it STOPS there — in-band data is never glued
//   across the mark;
// - having copied nothing, it steps over a spent record, and steps over the
//   pending byte too unless `SO_OOBINLINE`, under which the byte is delivered
//   as ordinary data and the record is retired;
// - a consuming step retires what it steps over — a non-inline pending byte is
//   DISCARDED, never delivered — while a `MSG_PEEK` step leaves the queue
//   alone, so the same byte is still there for the next receive.
//
// `recv(MSG_OOB)` itself reports EINVAL, never EAGAIN, when nothing is pending
// or when `SO_OOBINLINE` put the byte in the in-band stream instead; it never
// blocks. Only `SOCK_STREAM` has the channel at all — the datagram and
// seqpacket flavours report EOPNOTSUPP for both directions.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{UnixPair, UnixRing, UnixStreamSendError};
use super::super::{GcRights, UnixEnd};

/// The step a normal receive takes at one absolute stream offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OobStep {
    /// Copy ordinary bytes; the run may not pass `stop`.
    Copy { stop: u64 },
    /// End the receive: an out-of-band boundary with bytes already copied.
    Halt,
    /// Step over the byte at this offset without delivering it.
    Skip,
    /// Deliver the pending out-of-band byte as ordinary data (`SO_OOBINLINE`)
    /// and keep copying no further than `stop`.
    Inline { stop: u64 },
}

/// Absolute offset a run starting at `head` must stop at, and whether an
/// out-of-band record — rather than the end of the queue — is what stopped it.
/// # C: O(1)
pub fn limit(head: u64, pending: Option<u64>, mark: Option<u64>, produced: u64) -> (u64, bool) {
    let mut stop = produced;
    let mut from_oob = false;
    for candidate in [pending, mark] {
        match candidate {
            Some(at) if at > head && at < stop => { stop = at; from_oob = true; }
            _ => {}
        }
    }
    (stop, from_oob)
}

/// The step a normal (not `MSG_OOB`) stream receive takes at absolute offset
/// `head`. `pending` is the offset of the byte awaiting `recv(MSG_OOB)`, `mark`
/// the smallest spent out-of-band offset at or after `head`, `produced` the
/// ring's end, `copied` whether this receive already took bytes, `inline`
/// whether `SO_OOBINLINE` is set. # C: O(1)
pub fn step(head: u64, pending: Option<u64>, mark: Option<u64>, produced: u64,
    copied: bool, inline: bool) -> OobStep
{
    if mark == Some(head) { return if copied { OobStep::Halt } else { OobStep::Skip }; }
    if pending == Some(head) {
        if copied { return OobStep::Halt; }
        if !inline { return OobStep::Skip; }
        // The byte joins the in-band stream, so it bounds nothing.
        return OobStep::Inline { stop: limit(head, None, mark, produced).0 };
    }
    OobStep::Copy { stop: limit(head, pending, mark, produced).0 }
}

/// `SIOCATMARK` for a stream end: whether the next byte a receive would take
/// stands at the out-of-band mark. True at the pending byte itself, and at a
/// spent record that nothing but the next out-of-band byte follows. `queued` is
/// whether anything at all sits in the receive queue. # C: O(1)
pub fn at_mark(head: u64, pending: Option<u64>, mark: Option<u64>, queued: bool) -> bool {
    if !queued { return false; }
    if pending == Some(head) { return true; }
    mark == Some(head) && (pending.is_none() || pending == Some(head + 1))
}

/// Where a normal receive copies from, once it has stepped over the out-of-band
/// records that stand in front of it.
pub(super) struct OobWindow {
    /// Absolute offset the copy starts at.
    pub head: u64,
    /// Absolute offset the copy must stop at.
    pub stop: u64,
    /// `stop` is an out-of-band boundary, not the end of the queue: a receive
    /// gluing runs together must end here rather than wait for more bytes.
    pub oob_stop: bool,
}

impl UnixRing {
    /// Smallest spent out-of-band offset at or after `head`. # C: O(marks)
    pub(super) fn next_mark(&self, head: u64) -> Option<u64> {
        self.oob_marks.iter().copied().find(|at| *at >= head)
    }

    /// Step a receive positioned at `head` over the out-of-band records in
    /// front of it and report where its copy must stop. A consuming receive
    /// retires what it steps over — which is why a discarded out-of-band byte
    /// leaves no trace — while a peek only advances its own cursor. # C: O(marks)
    pub(super) fn oob_window(&mut self, head: u64, peek: bool, inline: bool) -> OobWindow {
        let mut head = head;
        loop {
            let mark = self.next_mark(head);
            match step(head, self.oob, mark, self.produced, false, inline) {
                OobStep::Copy { stop } => {
                    let oob_stop = limit(head, self.oob, mark, self.produced).1;
                    return OobWindow { head, stop, oob_stop };
                }
                OobStep::Inline { stop } => {
                    if !peek { self.oob = None; }
                    let oob_stop = limit(head, None, mark, self.produced).1;
                    return OobWindow { head, stop, oob_stop };
                }
                // Unreachable: `copied` is false for every step this walk takes.
                OobStep::Halt => return OobWindow { head, stop: head, oob_stop: true },
                OobStep::Skip => {
                    if !peek {
                        if self.oob == Some(head) { self.oob = None; }
                        if self.oob_marks.front() == Some(&head) { self.oob_marks.pop_front(); }
                        self.buf.pop_front();
                        self.consumed += 1;
                    }
                    head += 1;
                    if head >= self.produced {
                        return OobWindow { head, stop: head, oob_stop: false };
                    }
                }
            }
        }
    }
}

impl UnixPair {
    /// The ring `end` reads from. # C: O(1)
    fn recv_ring(&self, end: UnixEnd) -> &sync::Spinlock<UnixRing, sync::Socket> {
        match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b }
    }

    /// Enqueue one out-of-band byte from `end`, replacing any earlier byte the
    /// peer has not taken yet. Descriptors and sender credentials ride it
    /// exactly as they ride an in-band byte, and `cap` bounds it the same way.
    /// # C: O(rights)
    pub fn write_oob(&self, end: UnixEnd, byte: u8, rights: GcRights,
        creds: Option<(u32, u32, u32)>, cap: usize) -> Result<usize, UnixStreamSendError>
    { self.write_inner(end, &[byte], rights, creds, cap, true) }

    /// Whether a byte awaits `recv(MSG_OOB)` on the ring `end` reads. # C: O(1)
    pub fn has_oob(&self, end: UnixEnd) -> bool { self.recv_ring(end).lock().oob.is_some() }

    /// `SIOCATMARK` for the ring `end` reads. # C: O(marks)
    pub fn at_oob_mark(&self, end: UnixEnd) -> bool {
        let g = self.recv_ring(end).lock();
        let head = g.consumed;
        at_mark(head, g.oob, g.next_mark(head), !g.buf.is_empty())
    }

    /// Queued bytes a receive may still take on the ring `end` reads. # C: O(1)
    pub fn readable_len(&self, end: UnixEnd) -> usize { self.recv_ring(end).lock().readable_len() }

    /// `recv(MSG_OOB)` on the ring `end` reads: the one pending out-of-band
    /// byte, or `None` for the single EINVAL both "nothing pending" and
    /// "`SO_OOBINLINE` put it in-band" report. A consuming receive leaves the
    /// byte's position behind as a spent record; a peek changes nothing.
    /// # C: O(1)
    pub fn recv_oob(&self, end: UnixEnd, peek: bool, inline: bool) -> Option<u8> {
        if inline { return None; }
        let mut g = self.recv_ring(end).lock();
        let at = g.oob?;
        let index = at.checked_sub(g.consumed)? as usize;
        let byte = *g.buf.get(index)?;
        if !peek {
            g.oob = None;
            g.oob_marks.push_back(at);
        }
        Some(byte)
    }

    /// Out-of-band send with no ancillary data. # C: O(1)
    pub fn write_oob_byte(&self, end: UnixEnd, byte: u8) -> Result<usize, UnixStreamSendError> {
        self.write_oob(end, byte, GcRights::from_files(Vec::<Arc<vfs::File>>::new()), None,
            usize::MAX)
    }
}

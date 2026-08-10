// What a segment arriving for a connection that has answered a SYN but not
// yet seen the handshake finish is allowed to do.
//
// There are two populations in SYN-RECEIVED and they judge an acknowledgement
// differently, so both rules live here rather than being written twice at the
// places that act on them:
//
// - A REQUEST holds no send state at all. The only sequence it has ever put on
//   the wire is its SYN-ACK, so the only acknowledgement that can complete it
//   is the exact one past that: an off-path segment that guessed the 4-tuple
//   and landed inside the receive window still cannot finish the handshake
//   without also guessing the initial sequence number this side chose. The
//   test is EQUALITY, not a window.
// - A full socket in SYN-RECEIVED (a fast open, or a child already fed its
//   completing acknowledgement) has a real send sequence space, and judges an
//   acknowledgement by the ordinary rule: not older than what is already
//   acknowledged, not naming anything unsent.
//
// Both reject with one reset and no challenge acknowledgement.

/// Serial arithmetic: `a` precedes `b` in a 32-bit sequence space. # C: O(1)
#[inline]
pub fn before(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }

/// Serial arithmetic: `a` follows `b`. # C: O(1)
#[inline]
pub fn after(a: u32, b: u32) -> bool { before(b, a) }

/// A SYN-ACK announces its window unscaled, so a window a request is judged
/// against can never exceed what one header field holds. # C: O(1)
pub const SYNACK_WINDOW_MAX: u32 = 65_535;

/// The window a half-open request accepts a segment inside. # C: O(1)
#[inline]
pub fn synack_window(rcv_wnd: u32) -> u32 { core::cmp::min(rcv_wnd, SYNACK_WINDOW_MAX) }

/// Whether `[seq, end_seq)` overlaps the window `[s_win, e_win]`. # C: O(1)
pub fn in_window(seq: u32, end_seq: u32, s_win: u32, e_win: u32) -> bool {
    if seq == s_win { return true; }
    if after(end_seq, s_win) && before(seq, e_win) { return true; }
    seq == e_win && seq == end_seq
}

/// One past the last sequence a segment occupies: its payload plus the one
/// number each of SYN and FIN consume. # C: O(1)
pub fn end_seq(seq: u32, payload_len: usize, flag_bits: u8) -> u32 {
    let syn = ((flag_bits & crate::tcp_hdr::flags::SYN) != 0) as u32;
    let fin = ((flag_bits & crate::tcp_hdr::flags::FIN) != 0) as u32;
    seq.wrapping_add(payload_len as u32).wrapping_add(syn).wrapping_add(fin)
}

/// The acknowledgement that completes a half-open request: one past the
/// sequence its SYN-ACK carried, and nothing else. # C: O(1)
#[inline]
pub fn request_ack_completes(ack: u32, snt_isn: u32) -> bool {
    ack == snt_isn.wrapping_add(1)
}

/// Whether an acknowledgement is acceptable to a full socket in
/// SYN-RECEIVED: it may not be older than what is already acknowledged, and
/// may not name a sequence this side has not sent. # C: O(1)
#[inline]
pub fn socket_ack_acceptable(ack: u32, snd_una: u32, snd_nxt: u32) -> bool {
    !before(ack, snd_una) && !after(ack, snd_nxt)
}

/// What one segment arriving for a half-open request causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReqVerdict {
    /// A repeat of the opening SYN: the same SYN-ACK goes out again and the
    /// request is kept.
    ResendSynack,
    /// The segment acknowledges something this side never sent. One reset
    /// answers it; the request is untouched, because a segment that failed
    /// this test is not evidence about the connection it named.
    Reset,
    /// Outside the receive window: answered with an acknowledgement so the
    /// peer can resynchronise, unless it was itself a reset. Request kept.
    AckAndDrop,
    /// Dropped in silence, request kept.
    Drop,
    /// A reset, or a SYN that is not a plain repeat, inside the window: the
    /// request ends. A bad SYN is answered with a reset; a reset is not.
    EndRequest { reset: bool },
    /// The handshake is finished — build the child and feed it this segment.
    Complete,
}

/// The whole request check for one segment, in the reference's order: the
/// plain SYN repeat first, then the acknowledgement number, then the receive
/// window, then the reset and SYN bits, and only then the acknowledgement that
/// completes the handshake.
///
/// The acknowledgement number is tested BEFORE the window and before the reset
/// bit on purpose. A blind segment that guessed the window must not be able to
/// finish the handshake, and must not be able to tear the request down with a
/// reset either.
/// # C: O(1)
pub fn request_segment(flag_bits: u8, seq: u32, ack: u32, payload_len: usize,
                       snt_isn: u32, rcv_isn: u32, rcv_wnd: u32) -> ReqVerdict
{
    use crate::tcp_hdr::flags;
    // Only these three bits take part in the decision.
    let mut flg = flag_bits & (flags::SYN | flags::ACK | flags::RST);
    // A peer that lost the SYN-ACK repeats its SYN unchanged. Answering it
    // from the request costs one segment; treating it as a new connection
    // would cost a second backlog slot for the same handshake.
    if seq == rcv_isn && flg == flags::SYN { return ReqVerdict::ResendSynack; }
    if (flg & flags::ACK) != 0 && !request_ack_completes(ack, snt_isn) {
        return ReqVerdict::Reset;
    }
    let rcv_nxt = rcv_isn.wrapping_add(1);
    let end = end_seq(seq, payload_len, flag_bits);
    if !in_window(seq, end, rcv_nxt, rcv_nxt.wrapping_add(synack_window(rcv_wnd))) {
        return if (flg & flags::RST) != 0 { ReqVerdict::Drop } else { ReqVerdict::AckAndDrop };
    }
    // A SYN sitting at the peer's initial sequence is the SYN this request was
    // built from; it occupies no number inside the window, so it is read as
    // though it were absent and whatever else the segment carries decides.
    if seq == rcv_isn { flg &= !flags::SYN; }
    if (flg & (flags::RST | flags::SYN)) != 0 {
        return ReqVerdict::EndRequest { reset: (flg & flags::RST) == 0 };
    }
    if (flg & flags::ACK) == 0 { return ReqVerdict::Drop; }
    ReqVerdict::Complete
}

#[cfg(test)]
#[path = "synrecv_tests.rs"]
mod tests;

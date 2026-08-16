// Sequence-number arithmetic and the reorder window's placement decision.
//
// Everything here is modulo 4096 and everything here is pure. It is separated
// from the buffer that uses it because this is where a link silently stops
// working: a comparison that is off by one at the wrap point accepts a frame
// as new that is actually 2047 frames old, the window jumps forward, and
// every genuine frame after it is discarded as stale. Nothing logs, nothing
// panics, the link just stalls.

use wireless::ieee80211::fctl::SEQ_MODULO;

/// Highest sequence number before the wrap.
pub const SN_MAX: u16 = SEQ_MODULO - 1;
/// Mask that reduces any arithmetic back into the space.
pub const SN_MASK: u16 = SN_MAX;
/// The modulus itself, under a name a caller can import. Sequence numbers
/// are twelve bits and every comparison here is modulo this.
pub const SEQ_MODULO_TEST: u16 = SEQ_MODULO;
/// Half the space. A difference larger than this is read as the other
/// direction round the circle, which is what makes "less than" meaningful on
/// a wrapping counter at all.
pub const SN_HALF: u16 = SEQ_MODULO / 2;

/// Reduce a value into the sequence-number space. # C: O(1)
pub const fn sn(v: u16) -> u16 { v & SN_MASK }

/// Whether `a` is behind `b`. # C: O(1)
pub const fn sn_less(a: u16, b: u16) -> bool { sn(a.wrapping_sub(b)) > SN_HALF }
/// Whether `a` is behind `b` or equal to it. # C: O(1)
pub const fn sn_less_eq(a: u16, b: u16) -> bool { sn(b.wrapping_sub(a)) <= SN_HALF }
/// Whether `a` is ahead of `b`. # C: O(1)
pub const fn sn_greater(a: u16, b: u16) -> bool { sn_less(b, a) }
/// Sum of two sequence numbers. # C: O(1)
pub const fn sn_add(a: u16, b: u16) -> u16 { sn(a.wrapping_add(b)) }
/// Next sequence number. # C: O(1)
pub const fn sn_inc(a: u16) -> u16 { sn_add(a, 1) }
/// Difference between two sequence numbers, as a forward distance. # C: O(1)
pub const fn sn_sub(a: u16, b: u16) -> u16 { sn(a.wrapping_sub(b)) }

/// Where a received frame falls relative to a reorder window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    /// Behind the window: already released or given up on. Dropped.
    Old,
    /// Inside the window, at this offset from its head.
    InWindow(usize),
    /// Ahead of the window. The window must advance to `new_head` — which
    /// releases everything the advance passes over — and the frame then sits
    /// in the last slot.
    Ahead { new_head: u16 },
}

/// The receive window of one aggregation session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    /// Sequence number of the slot at the window's head — the next frame to
    /// be released in order.
    pub head_sn: u16,
    /// Slots the window covers.
    pub size: u16,
}

impl Window {
    /// A window of `size` slots starting at `ssn`. # C: O(1)
    pub const fn new(ssn: u16, size: u16) -> Self { Self { head_sn: sn(ssn), size } }

    /// Sequence number of the last slot the window currently covers.
    /// # C: O(1)
    pub const fn tail_sn(&self) -> u16 { sn_add(self.head_sn, self.size - 1) }

    /// Where a frame falls. A frame exactly at the tail is INSIDE the window;
    /// one past it moves the window by one. # C: O(1)
    pub fn place(&self, frame_sn: u16) -> Placement {
        let frame_sn = sn(frame_sn);
        if sn_less(frame_sn, self.head_sn) { return Placement::Old; }
        let offset = sn_sub(frame_sn, self.head_sn);
        if (offset as usize) < self.size as usize { return Placement::InWindow(offset as usize); }
        // The window advances by exactly enough to make room for this frame
        // in its last slot, never further: advancing further would give up on
        // frames that are still legitimately in flight.
        Placement::Ahead { new_head: sn_sub(frame_sn, self.size - 1) }
    }

    /// Slots the head must advance by to reach `new_head`. # C: O(1)
    pub fn advance_by(&self, new_head: u16) -> usize { sn_sub(new_head, self.head_sn) as usize }

    /// Move the head. # C: O(1)
    pub fn set_head(&mut self, new_head: u16) { self.head_sn = sn(new_head); }

    /// Move the head forward one slot. # C: O(1)
    pub fn advance_one(&mut self) { self.head_sn = sn_inc(self.head_sn); }
}

/// The transmit side's window: which frames have gone out under a session and
/// which the peer has acknowledged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxWindow {
    /// Oldest frame not yet acknowledged.
    pub start_sn: u16,
    /// Next sequence number to hand out.
    pub next_sn: u16,
    pub size: u16,
}

impl TxWindow {
    /// A window starting at `ssn`. # C: O(1)
    pub const fn new(ssn: u16, size: u16) -> Self {
        Self { start_sn: sn(ssn), next_sn: sn(ssn), size }
    }
    /// Frames outstanding. # C: O(1)
    pub fn outstanding(&self) -> u16 { sn_sub(self.next_sn, self.start_sn) }
    /// Whether another frame may go out without waiting. # C: O(1)
    pub fn can_send(&self) -> bool { self.outstanding() < self.size }
    /// Take the next sequence number. # C: O(1)
    pub fn take(&mut self) -> Option<u16> {
        if !self.can_send() { return None; }
        let s = self.next_sn;
        self.next_sn = sn_inc(s);
        Some(s)
    }
    /// The peer acknowledged everything before `sn`. An acknowledgement for a
    /// frame the window has already passed, or for one never sent, moves
    /// nothing. # C: O(1)
    pub fn ack_upto(&mut self, upto: u16) -> bool {
        let upto = sn(upto);
        if !sn_less(self.start_sn, upto) { return false; }
        if sn_greater(upto, self.next_sn) { return false; }
        self.start_sn = upto;
        true
    }
}

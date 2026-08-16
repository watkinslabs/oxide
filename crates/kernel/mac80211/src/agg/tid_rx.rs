// The receive side of one aggregation session: the reorder buffer, its
// release rules, and the session's own lifecycle.
//
// The buffer holds frames that arrived out of order until the gap before them
// is filled — or until the release timeout decides the missing frame is never
// coming. Without that timeout one lost frame stops the traffic identifier
// forever, which is the failure mode this buffer is most often blamed for and
// the reason the timeout is not optional.

extern crate alloc;

use alloc::vec::Vec;

use super::window::{sn_sub, Placement, Window};
use crate::limits;

/// One buffered frame.
#[derive(Clone, Debug)]
pub struct Held {
    pub frame: Vec<u8>,
    /// Monotonic nanoseconds it arrived at, for the release timeout.
    pub at_ns: u64,
}

/// What arrived at the buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RxAgg {
    /// The frame is a duplicate or arrived after its slot was given up on.
    Dropped,
    /// These frames are released, in order. An empty list means the frame was
    /// buffered and nothing came out yet.
    Released(Vec<Vec<u8>>),
}

/// One session's reorder buffer.
#[derive(Debug)]
pub struct ReorderBuf {
    pub win: Window,
    slots: Vec<Option<Held>>,
    /// Frames currently held.
    pub stored: usize,
    /// How long a frame waits behind a hole before the hole is abandoned.
    pub release_ns: u64,
    /// Monotonic nanoseconds of the last frame received on the session, for
    /// the idle teardown.
    pub last_rx_ns: u64,
    /// Token the peer's request carried, echoed in the response.
    pub dialog_token: u8,
    /// Session inactivity limit the peer asked for, in time units.
    pub timeout_tu: u16,
}

impl ReorderBuf {
    /// A buffer of `size` slots starting at `ssn`. # C: O(size)
    pub fn new(ssn: u16, size: u16, now_ns: u64) -> Self {
        let size = size.clamp(limits::MIN_AGG_BUF_SIZE, limits::MAX_AGG_BUF_SIZE);
        let mut slots = Vec::new();
        slots.resize_with(size as usize, || None);
        Self {
            win: Window::new(ssn, size), slots, stored: 0,
            release_ns: limits::REORDER_RELEASE_NS, last_rx_ns: now_ns,
            dialog_token: 0, timeout_tu: 0,
        }
    }

    /// Slots the buffer holds. # C: O(1)
    pub fn size(&self) -> u16 { self.win.size }

    fn index(&self, frame_sn: u16) -> usize { (frame_sn as usize) % self.slots.len() }

    /// Release the head slot if it is filled, repeatedly, and return what
    /// came out. # C: O(released)
    fn drain_head(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let i = self.index(self.win.head_sn);
            let Some(held) = self.slots[i].take() else { break; };
            self.stored -= 1;
            out.push(held.frame);
            self.win.advance_one();
        }
        out
    }

    /// Advance the head to `new_head`, releasing every filled slot it passes
    /// and abandoning every empty one. # C: O(distance)
    fn advance_to(&mut self, new_head: u16) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut steps = self.win.advance_by(new_head);
        // A jump longer than the buffer cannot release anything that is still
        // in it beyond one pass, so the walk is bounded by the buffer size.
        if steps > self.slots.len() {
            for slot in self.slots.iter_mut() {
                if let Some(h) = slot.take() { self.stored -= 1; out.push(h.frame); }
            }
            self.win.set_head(new_head);
            return out;
        }
        while steps > 0 {
            let i = self.index(self.win.head_sn);
            if let Some(h) = self.slots[i].take() { self.stored -= 1; out.push(h.frame); }
            self.win.advance_one();
            steps -= 1;
        }
        out
    }

    /// Take one frame. The frame is released immediately when it is the one
    /// the window is waiting for, buffered when it is ahead of that but
    /// inside the window, and dropped when it is behind the window or is a
    /// second copy of a frame already held. # C: O(released)
    pub fn receive(&mut self, frame_sn: u16, frame: Vec<u8>, now_ns: u64) -> RxAgg {
        self.last_rx_ns = now_ns;
        let mut released = match self.win.place(frame_sn) {
            Placement::Old => return RxAgg::Dropped,
            Placement::InWindow(_) => Vec::new(),
            Placement::Ahead { new_head } => self.advance_to(new_head),
        };
        let i = self.index(frame_sn);
        if self.slots[i].is_some() { return RxAgg::Dropped; }
        self.slots[i] = Some(Held { frame, at_ns: now_ns });
        self.stored += 1;
        released.extend(self.drain_head());
        RxAgg::Released(released)
    }

    /// Release whatever the timeout has given up waiting for. The head is
    /// advanced past the hole to the oldest frame still held, and everything
    /// from there that is contiguous comes out with it. # C: O(size)
    pub fn release_timed_out(&mut self, now_ns: u64) -> Vec<Vec<u8>> {
        if self.stored == 0 { return Vec::new(); }
        let head_i = self.index(self.win.head_sn);
        if self.slots[head_i].is_some() { return self.drain_head(); }
        let oldest = self.slots.iter().flatten().map(|h| h.at_ns).min();
        let Some(oldest) = oldest else { return Vec::new(); };
        if now_ns.saturating_sub(oldest) < self.release_ns { return Vec::new(); }
        // Skip forward to the first slot that actually holds something.
        let mut steps = 0usize;
        while steps < self.slots.len() {
            let i = self.index(super::window::sn_add(self.win.head_sn, steps as u16));
            if self.slots[i].is_some() { break; }
            steps += 1;
        }
        if steps >= self.slots.len() { return Vec::new(); }
        let new_head = super::window::sn_add(self.win.head_sn, steps as u16);
        let mut out = self.advance_to(new_head);
        out.extend(self.drain_head());
        out
    }

    /// Release everything, as tearing the session down does. # C: O(size)
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for step in 0..self.slots.len() {
            let i = self.index(super::window::sn_add(self.win.head_sn, step as u16));
            if let Some(h) = self.slots[i].take() { self.stored -= 1; out.push(h.frame); }
        }
        self.win.set_head(super::window::sn_add(self.win.head_sn, self.win.size));
        out
    }

    /// Move the head forward because the peer said everything before this
    /// number is gone — a block-ack request. # C: O(distance)
    pub fn bar(&mut self, start_sn: u16) -> Vec<Vec<u8>> {
        if sn_sub(start_sn, self.win.head_sn) == 0 { return Vec::new(); }
        if super::window::sn_less(start_sn, self.win.head_sn) { return Vec::new(); }
        let mut out = self.advance_to(start_sn);
        out.extend(self.drain_head());
        out
    }

    /// Whether the session has been idle long enough to tear down. # C: O(1)
    pub fn is_idle(&self, now_ns: u64) -> bool {
        let limit = if self.timeout_tu == 0 { limits::AGG_SESSION_TIMEOUT_NS }
                    else { limits::tu_to_ns(self.timeout_tu as u64) };
        now_ns.saturating_sub(self.last_rx_ns) >= limit
    }
}

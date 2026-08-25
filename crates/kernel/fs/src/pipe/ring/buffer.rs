use alloc::vec::Vec;

use super::super::limits::PIPE_GROW_STEP;

pub(in crate::pipe) struct PipeBuf {
    /// Backing store, grown on demand up to `cap`. Its length is what the ring
    /// indices wrap on; `cap` is only the ceiling it may grow to.
    pub(in crate::pipe) data: Vec<u8>,
    pub(in crate::pipe) packet: Vec<bool>,
    pub(in crate::pipe) packet_end: Vec<bool>,
    pub(in crate::pipe) head: usize,
    pub(in crate::pipe) tail: usize,
    pub(in crate::pipe) len:  usize,
    /// `F_GETPIPE_SZ`: how many bytes this pipe may hold.
    pub(in crate::pipe) cap:  usize,
}

impl PipeBuf {
    pub(in crate::pipe) fn new(cap: usize) -> Self {
        Self { data: Vec::new(), packet: Vec::new(), packet_end: Vec::new(),
            head: 0, tail: 0, len: 0, cap }
    }

    /// Next ring index after `i`. Wraps on the ALLOCATED length, not on the
    /// capacity — an unfilled pipe holds fewer bytes than it may grow to.
    /// # C: O(1)
    pub(in crate::pipe) fn next_idx(&self, i: usize) -> usize {
        if i + 1 >= self.data.len() { 0 } else { i + 1 }
    }

    /// Rotate the queued bytes to the front so the backing store can be
    /// extended without the new slots landing inside the queue.
    fn normalize(&mut self) {
        if self.head == 0 { return; }
        self.data.rotate_left(self.head);
        self.packet.rotate_left(self.head);
        self.packet_end.rotate_left(self.head);
        self.head = 0;
        self.tail = if self.len >= self.data.len() { 0 } else { self.len };
    }

    /// Extend the backing store by one allocation unit. False when the pipe is
    /// already at its capacity or the memory is not there — either way the
    /// caller treats it as a full ring and waits.
    fn grow(&mut self) -> bool {
        let cur = self.data.len();
        if cur >= self.cap { return false; }
        let want = (cur + PIPE_GROW_STEP).min(self.cap);
        let add = want - cur;
        if self.data.try_reserve_exact(add).is_err() { return false; }
        if self.packet.try_reserve_exact(add).is_err() { return false; }
        if self.packet_end.try_reserve_exact(add).is_err() { return false; }
        self.normalize();
        self.data.resize(want, 0);
        self.packet.resize(want, false);
        self.packet_end.resize(want, false);
        self.tail = self.len;
        true
    }

    pub(in crate::pipe) fn push(&mut self, b: u8, packet: bool, packet_end: bool) -> bool {
        if self.len >= self.cap { return false; }
        if self.len >= self.data.len() && !self.grow() { return false; }
        self.data[self.tail] = b;
        self.packet[self.tail] = packet;
        self.packet_end[self.tail] = packet_end;
        self.tail = self.next_idx(self.tail);
        self.len += 1;
        true
    }

    pub(in crate::pipe) fn pop(&mut self) -> Option<(u8, bool, bool)> {
        if self.len == 0 { return None; }
        let b = self.data[self.head];
        let packet = self.packet[self.head];
        let packet_end = self.packet_end[self.head];
        self.packet[self.head] = false;
        self.packet_end[self.head] = false;
        self.head = self.next_idx(self.head);
        self.len -= 1;
        Some((b, packet, packet_end))
    }
}

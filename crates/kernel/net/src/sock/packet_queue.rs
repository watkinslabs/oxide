use alloc::collections::VecDeque;

use super::PacketFrame;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketStatistics {
    pub packets: u32,
    pub drops: u32,
    pub freeze_queue_count: u32,
}

#[derive(Default)]
pub struct PacketRxQueue {
    frames: VecDeque<PacketFrame>,
    bytes: usize,
    packets: u32,
    drops: u32,
    pressure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketRoom { Normal, Low, None }

impl PacketRxQueue {
    /// Classify prospective receive room for Linux fanout rollover. # C: O(1)
    pub(crate) fn room(&self, charge: usize, limit: usize) -> PacketRoom {
        let next = self.bytes.saturating_add(charge);
        if next >= limit { return PacketRoom::None; }
        if limit.saturating_sub(next) <= limit / 4 { PacketRoom::Low } else { PacketRoom::Normal }
    }

    /// Report Linux packet-socket pressure for rollover peer selection. # C: O(1)
    pub(crate) fn pressured(&self) -> bool { self.pressure }

    /// Admit one frame against Linux receive-buffer byte pressure. # C: O(1)
    pub(crate) fn admit(&mut self, frame: PacketFrame, limit: usize) -> bool {
        let next = self.bytes.saturating_add(frame.charge);
        if next >= limit {
            self.drops = self.drops.wrapping_add(1);
            self.pressure = true;
            return false;
        }
        self.bytes = next;
        self.packets = self.packets.wrapping_add(1);
        self.pressure = limit.saturating_sub(self.bytes) <= limit / 4;
        self.frames.push_back(frame);
        true
    }

    /// Read or consume one queued frame and update byte pressure. # C: O(payload clone)
    pub(crate) fn receive(&mut self, peek: bool, limit: usize) -> Option<PacketFrame> {
        if peek { return self.frames.front().cloned(); }
        let frame = self.frames.pop_front()?;
        self.bytes = self.bytes.saturating_sub(frame.charge);
        if limit.saturating_sub(self.bytes) > limit / 4 { self.pressure = false; }
        Some(frame)
    }

    /// Return the first queued payload length. # C: O(1)
    pub(crate) fn first_len(&self) -> Option<usize> {
        self.frames.front().map(|frame| frame.payload.len())
    }

    /// Return queued frame count. # C: O(1)
    pub(crate) fn len(&self) -> usize { self.frames.len() }

    /// Report whether no frame is queued. # C: O(1)
    pub(crate) fn is_empty(&self) -> bool { self.frames.is_empty() }

    /// Read and clear Linux packet counters atomically under the queue lock. # C: O(1)
    pub(crate) fn take_statistics(&mut self) -> PacketStatistics {
        let drops = core::mem::take(&mut self.drops);
        let packets = core::mem::take(&mut self.packets).wrapping_add(drops);
        PacketStatistics { packets, drops, freeze_queue_count: 0 }
    }

    #[cfg(any(test, feature = "hosted"))]
    /// Drain test frames while preserving receive-side byte accounting. # C: O(N)
    pub(crate) fn take_all(&mut self, limit: usize) -> alloc::vec::Vec<PacketFrame> {
        let mut out = alloc::vec::Vec::with_capacity(self.frames.len());
        while let Some(frame) = self.receive(false, limit) { out.push(frame); }
        out
    }

    #[cfg(test)]
    /// Expose exact queue accounting to deterministic tests. # C: O(1)
    pub(crate) fn accounting(&self) -> (usize, bool) { (self.bytes, self.pressure) }
}

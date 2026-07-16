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
    freeze_queue_count: u32,
    pressure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketRoom { Normal, Low, None }

const LINUX_CACHE_LINE: usize = 64;
const LINUX_PAGE_SIZE: usize = 4096;
const LINUX_SKB_SIZE: usize = 256;
const LINUX_SKB_SHARED_INFO_SIZE: usize = 320;
const LINUX_SKB_SMALL_HEAD_SIZE: usize = 704;
const LINUX_PACKET_HEADROOM: usize = 16;
const LINUX_ETHERNET_HEADER: usize = 14;

fn align_up(value: usize, alignment: usize) -> usize {
    value.saturating_add(alignment - 1) / alignment * alignment
}

fn linear_skb_truesize(bytes: usize) -> usize {
    let requested = align_up(bytes, LINUX_CACHE_LINE)
        .saturating_add(LINUX_SKB_SHARED_INFO_SIZE);
    let allocation = if requested <= LINUX_SKB_SMALL_HEAD_SIZE {
        LINUX_SKB_SMALL_HEAD_SIZE
    } else {
        requested.checked_next_power_of_two().unwrap_or(usize::MAX)
    };
    allocation.saturating_add(LINUX_SKB_SIZE)
}

/// Linux 6.19 64-bit `packet_alloc_skb` receive charge for one raw frame. # C: O(1)
pub(crate) fn linux_packet_skb_truesize(frame_len: usize) -> usize {
    if LINUX_PACKET_HEADROOM.saturating_add(frame_len) < LINUX_PAGE_SIZE {
        return linear_skb_truesize(LINUX_PACKET_HEADROOM.saturating_add(frame_len));
    }
    let linear = frame_len.min(LINUX_ETHERNET_HEADER);
    linear_skb_truesize(LINUX_PACKET_HEADROOM.saturating_add(linear))
        .saturating_add(align_up(frame_len.saturating_sub(linear), LINUX_PAGE_SIZE))
}

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
        if self.bytes >= limit {
            self.drops = self.drops.wrapping_add(1);
            self.pressure = true;
            return false;
        }
        self.bytes = self.bytes.saturating_add(frame.charge);
        self.packets = self.packets.wrapping_add(1);
        self.pressure = limit.saturating_sub(self.bytes) <= limit / 4;
        self.frames.push_back(frame);
        true
    }

    /// Admit an optional ring-copy fallback without counting a delivered ring as dropped. # C: O(1)
    pub(crate) fn admit_copy(&mut self, frame: PacketFrame, limit: usize) -> bool {
        if self.bytes >= limit { return false; }
        self.bytes = self.bytes.saturating_add(frame.charge);
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

    /// Report whether Linux's clear-on-read drop counter is nonzero. # C: O(1)
    pub(crate) fn has_drops(&self) -> bool { self.drops != 0 }

    /// Account one receive-ring publication attempt. # C: O(1)
    pub(crate) fn account_ring(&mut self, published: bool) {
        if published { self.packets = self.packets.wrapping_add(1); }
        else { self.drops = self.drops.wrapping_add(1); }
    }

    /// Account one V3 queue-freeze transition. # C: O(1)
    pub(crate) fn account_freeze(&mut self) {
        self.freeze_queue_count = self.freeze_queue_count.wrapping_add(1);
    }

    /// Read and clear Linux packet counters atomically under the queue lock. # C: O(1)
    pub(crate) fn take_statistics(&mut self) -> PacketStatistics {
        let drops = core::mem::take(&mut self.drops);
        let packets = core::mem::take(&mut self.packets).wrapping_add(drops);
        let freeze_queue_count = core::mem::take(&mut self.freeze_queue_count);
        PacketStatistics { packets, drops, freeze_queue_count }
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

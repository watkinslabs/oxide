// Per-CPU `softnet_data`: the input backlog itself, its admission rule, and
// the counters `/proc/net/softnet_stat` publishes.
//
// No target gate on this file, deliberately: every decision here (admission
// against the length cap, the two-queue splice, what counts as a drop) is
// logic the hosted tests must be able to execute. The kernel-only glue lives
// in `action.rs`.

extern crate alloc;
use alloc::collections::VecDeque;

use crate::addr::NetIfaceId;
use crate::pkt::Pkt;

use super::limits::NETDEV_MAX_BACKLOG;

/// One frame waiting for receive processing, tagged with the interface it
/// arrived on. The ingress lease is re-acquired at delivery time rather than
/// carried here: a device that went down between enqueue and drain must have
/// its queued frames dropped, which is exactly what a failed re-acquire gives.
pub struct BacklogItem {
    pub iface: NetIfaceId,
    /// The generation accepted at ingress. `None` is the synthetic loopback
    /// path, which re-acquires the current generation at delivery.
    pub generation: Option<u64>,
    pub packet: BacklogPacket,
}

/// The one canonical backlog can carry both loopback L3 packets and a module
/// driver's complete Ethernet frame. The latter keeps packet-socket fanout,
/// bridge admission and L3 delivery on the NET_RX stack rather than running
/// them under the driver's caller.
pub enum BacklogPacket {
    L3(Pkt),
    Ethernet { pkt: Pkt, metadata: crate::PacketRxMetadata },
}

/// Outcome of an enqueue — the reference `NET_RX_SUCCESS` / `NET_RX_DROP`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RxVerdict {
    /// Frame is queued; the caller must ensure NET_RX is raised.
    Success,
    /// Backlog full. The frame is gone and the drop is accounted.
    Drop,
}

/// A `/proc/net/softnet_stat` row's live values for one CPU.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SoftnetRow {
    pub processed: u64,
    pub dropped: u64,
    pub time_squeeze: u64,
    pub input_qlen: u64,
    pub process_qlen: u64,
}

/// One CPU's receive backlog. Two queues, as in the reference: producers append
/// to `input` under the backlog lock; the drain splices `input` into `process`
/// once and then consumes `process` without blocking producers behind it.
pub struct SoftnetData {
    input: VecDeque<BacklogItem>,
    process: VecDeque<BacklogItem>,
    processed: u64,
    dropped: u64,
    time_squeeze: u64,
}

impl SoftnetData {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            input: VecDeque::new(), process: VecDeque::new(),
            processed: 0, dropped: 0, time_squeeze: 0,
        }
    }

    /// Admit one frame to the input queue, or drop it and account the drop.
    ///
    /// Admission tests the queue length BEFORE the push against the cap, so a
    /// cap of N admits N+1 entries — the reference's `qlen <= max_backlog`
    /// test, reproduced rather than tidied, because a tidied version silently
    /// changes the queue depth every `netdev_max_backlog` tuning assumes.
    /// # C: O(1)
    pub fn enqueue(&mut self, item: BacklogItem) -> RxVerdict {
        if self.input.len() > NETDEV_MAX_BACKLOG {
            self.dropped += 1;
            return RxVerdict::Drop;
        }
        self.input.push_back(item);
        RxVerdict::Success
    }

    /// Take the next frame for delivery, splicing the input queue in when the
    /// process queue runs dry. Bumps `processed` for every frame handed out.
    /// # C: O(1) amortized
    pub fn dequeue(&mut self) -> Option<BacklogItem> {
        if self.process.is_empty() {
            if self.input.is_empty() { return None; }
            core::mem::swap(&mut self.process, &mut self.input);
        }
        let item = self.process.pop_front()?;
        self.processed += 1;
        Some(item)
    }

    /// Nothing queued on either side. # C: O(1)
    pub fn is_empty(&self) -> bool { self.input.is_empty() && self.process.is_empty() }

    /// Total frames queued across both halves. # C: O(1)
    pub fn len(&self) -> usize { self.input.len() + self.process.len() }

    /// Account a drain that hit its budget or time limit with work still
    /// queued (`softnet_stat` column 3). # C: O(1)
    pub fn note_time_squeeze(&mut self) { self.time_squeeze += 1; }

    /// Account frames discarded outside the admission path — a device whose
    /// ingress generation no longer admits, or a namespace retired under the
    /// queued frame. # C: O(1)
    pub fn note_dropped(&mut self, n: u64) { self.dropped += n; }

    /// Live counters for this CPU's `/proc/net/softnet_stat` row. # C: O(1)
    pub fn row(&self) -> SoftnetRow {
        SoftnetRow {
            processed: self.processed, dropped: self.dropped,
            time_squeeze: self.time_squeeze,
            input_qlen: self.input.len() as u64,
            process_qlen: self.process.len() as u64,
        }
    }

    /// Discard everything queued, accounting each frame as a drop. Used when a
    /// stack is torn down under queued work. # C: O(N queued)
    pub fn purge(&mut self) {
        self.dropped += self.len() as u64;
        self.input.clear();
        self.process.clear();
    }
}

impl Default for SoftnetData { fn default() -> Self { Self::new() } }

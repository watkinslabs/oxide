// One station: what is known about a peer this interface talks to.
//
// The per-traffic-identifier state is per station and not per interface,
// because a reorder window, a duplicate history and an aggregation session
// all belong to ONE pair of endpoints. Sharing any of them across peers
// produces the same silent stall as a wrong window comparison.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use wireless::ieee80211::fctl::NUM_BA_TIDS;
use wireless::ieee80211::MacAddr;

use crate::agg::{ReorderBuf, TidTx};
use crate::limits;
use crate::ops::StaState;
use crate::rate::RateCtl;

/// One buffered frame held for a sleeping station.
#[derive(Clone, Debug)]
pub struct PsFrame {
    pub frame: Vec<u8>,
    pub at_ns: u64,
    /// Whether the frame is addressed to the group rather than the station,
    /// so it goes out after the beacon rather than on a poll.
    pub multicast: bool,
}

/// Everything one peer's state amounts to.
pub struct Sta {
    pub addr: MacAddr,
    pub state: StaState,
    /// Association identifier this interface handed out, or was given.
    pub aid: u16,
    /// Beacon intervals the peer sleeps for.
    pub listen_interval: u16,
    /// Whether the peer runs quality of service, so its frames carry a
    /// traffic identifier and its transmit queue is per category.
    pub qos: bool,
    /// Whether management frames to and from this peer are protected.
    pub mfp: bool,
    /// Whether the peer uses four-address frames.
    pub use_4addr: bool,
    /// Rates the peer said it supports, in 100 kbit/s units.
    pub supported_rates: Vec<u32>,
    /// Elements the peer's association request carried, reported upward.
    pub assoc_ie: Vec<u8>,

    /// Monotonic nanoseconds the association completed at.
    pub assoc_at_ns: u64,
    /// Monotonic nanoseconds of the last frame heard from the peer.
    pub last_rx_ns: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_retries: u64,
    pub tx_failed: u64,
    /// Last signal heard from the peer, in dBm.
    pub signal: i8,

    /// Transmit sequence counters, one per traffic identifier plus one for
    /// frames that carry none. Sharing one counter across identifiers makes
    /// the peer's duplicate detection reject perfectly good frames.
    pub seq: [u16; limits::NUM_DUP_SLOTS],
    /// Last sequence-control field seen per identifier, for duplicate
    /// detection.
    pub last_seq_ctrl: [Option<u16>; limits::NUM_DUP_SLOTS],

    /// Receiving half of each aggregation session.
    pub tid_rx: [Option<ReorderBuf>; NUM_BA_TIDS],
    /// Originating half of each aggregation session.
    pub tid_tx: [TidTx; NUM_BA_TIDS],

    /// Whether the peer is asleep, so frames for it are buffered.
    pub asleep: bool,
    /// Frames held for a sleeping peer.
    pub ps_buf: VecDeque<PsFrame>,
    /// Frames dropped because the buffer was full.
    pub ps_dropped: u64,

    /// Rate selection state for this peer.
    pub rate: RateCtl,
}

impl Sta {
    /// A station in the table but nothing more. # C: O(1)
    pub fn new(addr: MacAddr, now_ns: u64) -> Self {
        Self {
            addr, state: StaState::None, aid: 0,
            listen_interval: limits::DEFAULT_LISTEN_INTERVAL,
            qos: false, mfp: false, use_4addr: false,
            supported_rates: Vec::new(), assoc_ie: Vec::new(),
            assoc_at_ns: 0, last_rx_ns: now_ns,
            rx_packets: 0, rx_bytes: 0, rx_dropped: 0,
            tx_packets: 0, tx_bytes: 0, tx_retries: 0, tx_failed: 0,
            signal: 0,
            seq: [0; limits::NUM_DUP_SLOTS],
            last_seq_ctrl: [None; limits::NUM_DUP_SLOTS],
            tid_rx: [const { None }; NUM_BA_TIDS],
            tid_tx: [TidTx::new(0); NUM_BA_TIDS],
            asleep: false, ps_buf: VecDeque::new(), ps_dropped: 0,
            rate: RateCtl::default(),
        }
    }

    /// Slot a traffic identifier uses in the per-identifier arrays. A frame
    /// with no quality-of-service control field gets its own slot rather than
    /// sharing slot zero with best-effort traffic. # C: O(1)
    pub fn slot(tid: Option<u8>) -> usize {
        match tid {
            Some(t) if (t as usize) < limits::NUM_DUP_SLOTS - 1 => t as usize,
            _ => limits::NUM_DUP_SLOTS - 1,
        }
    }

    /// Take the next transmit sequence number for a traffic identifier.
    /// # C: O(1)
    pub fn next_seq(&mut self, tid: Option<u8>) -> u16 {
        let i = Self::slot(tid);
        let s = self.seq[i];
        self.seq[i] = crate::agg::window::sn_inc(s);
        s
    }

    /// Whether a frame is a retransmission of one already taken. The check is
    /// on the WHOLE sequence-control field, fragment number included: two
    /// fragments of one frame share a sequence number and differ only in the
    /// fragment number, and comparing only the sequence number would discard
    /// every fragment after the first. # C: O(1)
    pub fn is_duplicate(&mut self, tid: Option<u8>, seq_ctrl: u16, retry: bool) -> bool {
        let i = Self::slot(tid);
        // A frame that is not marked as a retry cannot be a duplicate however
        // its numbering compares: the peer has moved on and reused the value.
        if !retry { self.last_seq_ctrl[i] = Some(seq_ctrl); return false; }
        if self.last_seq_ctrl[i] == Some(seq_ctrl) { return true; }
        self.last_seq_ctrl[i] = Some(seq_ctrl);
        false
    }

    /// Buffer a frame for a sleeping peer, dropping the oldest when the
    /// buffer is full. A buffer that grew without bound would let one sleeping
    /// station consume the radio's memory. # C: O(1)
    pub fn buffer_ps(&mut self, frame: Vec<u8>, multicast: bool, now_ns: u64) {
        if self.ps_buf.len() >= limits::MAX_PS_BUFFERED {
            self.ps_buf.pop_front();
            self.ps_dropped += 1;
        }
        self.ps_buf.push_back(PsFrame { frame, at_ns: now_ns, multicast });
    }

    /// Release everything buffered, dropping whatever has waited too long.
    /// # C: O(buffered)
    pub fn release_ps(&mut self, now_ns: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(f) = self.ps_buf.pop_front() {
            if now_ns.saturating_sub(f.at_ns) >= limits::PS_BUFFER_TIMEOUT_NS {
                self.ps_dropped += 1;
                continue;
            }
            out.push(f.frame);
        }
        out
    }

    /// Whether the peer has traffic waiting, which the traffic-indication map
    /// in every beacon reports. # C: O(1)
    pub fn has_buffered(&self) -> bool { !self.ps_buf.is_empty() }

    /// Whether the peer has been silent long enough to evict. # C: O(1)
    pub fn is_inactive(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_rx_ns) >= limits::STA_INACTIVITY_NS
    }

    /// Report this station upward. # C: O(1)
    pub fn to_info(&self, now_ns: u64, generation: u32) -> wireless::sta::StationInfo {
        let mut info = wireless::sta::StationInfo::new(self.addr);
        info.generation = generation;
        info.inactive_time =
            Some((now_ns.saturating_sub(self.last_rx_ns) / 1_000_000) as u32);
        info.assoc_at_ns = if self.assoc_at_ns != 0 { Some(self.assoc_at_ns) } else { None };
        info.connected_time = info.connected_secs(now_ns);
        info.rx_bytes = Some(self.rx_bytes);
        info.tx_bytes = Some(self.tx_bytes);
        info.rx_packets = Some(self.rx_packets as u32);
        info.tx_packets = Some(self.tx_packets as u32);
        info.tx_retries = Some(self.tx_retries as u32);
        info.tx_failed = Some(self.tx_failed as u32);
        info.rx_dropped_misc = Some(self.rx_dropped);
        if self.signal != 0 { info.signal = Some(self.signal); }
        if self.aid != 0 { info.aid = Some(self.aid); }
        info.tx_bitrate = Some(self.rate.current_info());
        let mut sta_flags = wireless::sta::StaFlags::default();
        use wireless::uapi::nested::sta_flag;
        sta_flags.put(sta_flag::AUTHENTICATED, self.state >= StaState::Auth);
        sta_flags.put(sta_flag::ASSOCIATED, self.state >= StaState::Assoc);
        sta_flags.put(sta_flag::AUTHORIZED, self.state == StaState::Authorized);
        sta_flags.put(sta_flag::WME, self.qos);
        sta_flags.put(sta_flag::MFP, self.mfp);
        info.sta_flags = Some(sta_flags);
        info
    }
}

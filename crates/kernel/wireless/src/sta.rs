// Station reporting: the per-peer counters and link quality `iw dev link` and
// `iw dev station dump` read.
//
// Every field is optional and reported only when it is real. A driver that
// keeps no retry counter must not report zero retries — zero is a
// measurement, and userspace treats it as one.

extern crate alloc;

use alloc::vec::Vec;

use crate::ieee80211::MacAddr;

/// A negotiated rate in one direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateInfo {
    /// Rate in units of 100 kbit/s.
    pub bitrate: u32,
    /// Modulation-and-coding index, for a high-throughput rate.
    pub mcs: Option<u8>,
    /// Spatial streams, for a very-high-throughput or later rate.
    pub nss: Option<u8>,
    /// Channel width the rate was measured at.
    pub width: crate::uapi::enums::ChanWidth,
    /// Whether the short guard interval was in use.
    pub short_gi: bool,
    /// Generation of the rate: 0 legacy, 1 high throughput, 2 very high,
    /// 3 high efficiency, 4 extremely high throughput.
    pub generation: u8,
}

/// Rate generations, named so a reader does not have to know the numbering.
pub mod rate_gen {
    pub const LEGACY: u8 = 0;
    pub const HT: u8 = 1;
    pub const VHT: u8 = 2;
    pub const HE: u8 = 3;
    pub const EHT: u8 = 4;
}

/// Per-traffic-identifier counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TidStats {
    pub rx_msdu: u64,
    pub tx_msdu: u64,
    pub tx_msdu_retries: u64,
    pub tx_msdu_failed: u64,
}

/// Flags a station has, and which of them the reporter actually knows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaFlags {
    /// Bit `n` set means flag `n` is known.
    pub mask: u32,
    /// Bit `n` set means flag `n` is on.
    pub set: u32,
}

impl StaFlags {
    /// Record one flag as known, with a value. # C: O(1)
    pub fn put(&mut self, flag: u32, on: bool) {
        self.mask |= 1 << flag;
        if on { self.set |= 1 << flag; } else { self.set &= !(1 << flag); }
    }
    /// Whether a flag is known and on. # C: O(1)
    pub fn get(&self, flag: u32) -> bool {
        self.mask & (1 << flag) != 0 && self.set & (1 << flag) != 0
    }
}

/// Everything reported about one station.
#[derive(Clone, Debug, Default)]
pub struct StationInfo {
    pub mac: MacAddr,
    /// Bumped whenever the station list changes, so a dump reader can tell a
    /// consistent snapshot from a torn one.
    pub generation: u32,
    /// Milliseconds since the last frame from this station.
    pub inactive_time: Option<u32>,
    /// Seconds since the association completed.
    pub connected_time: Option<u32>,
    /// Monotonic nanoseconds at which the association completed.
    pub assoc_at_ns: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_packets: Option<u32>,
    pub tx_packets: Option<u32>,
    pub tx_retries: Option<u32>,
    pub tx_failed: Option<u32>,
    pub rx_dropped_misc: Option<u64>,
    pub beacon_loss_count: Option<u32>,
    pub beacon_rx: Option<u64>,
    /// Last signal in dBm.
    pub signal: Option<i8>,
    /// Running average signal in dBm.
    pub signal_avg: Option<i8>,
    pub beacon_signal_avg: Option<i8>,
    /// Per-antenna signal in dBm.
    pub chain_signal: Vec<i8>,
    pub chain_signal_avg: Vec<i8>,
    pub tx_bitrate: Option<RateInfo>,
    pub rx_bitrate: Option<RateInfo>,
    pub sta_flags: Option<StaFlags>,
    /// Association identifier the AP gave this station.
    pub aid: Option<u16>,
    /// Time spent receiving from this station, in microseconds.
    pub rx_duration: Option<u64>,
    pub tx_duration: Option<u64>,
    pub tid_stats: Vec<(u8, TidStats)>,
    /// Estimated throughput in kbit/s.
    pub expected_throughput: Option<u32>,
    pub ack_signal: Option<i8>,
    pub ack_signal_avg: Option<i8>,
    /// Whether the station is a mesh peer, and its peer-link state.
    pub plink_state: Option<u8>,
    /// Parameters of the BSS this station belongs to.
    pub bss_param: Option<BssParam>,
}

/// The BSS-level parameters reported alongside a station.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BssParam {
    pub cts_protection: bool,
    pub short_preamble: bool,
    pub short_slot_time: bool,
    pub dtim_period: u8,
    pub beacon_interval: u16,
}

impl StationInfo {
    /// A report for one station with nothing yet known about it. # C: O(1)
    pub fn new(mac: MacAddr) -> Self { Self { mac, ..Default::default() } }

    /// Seconds a station has been associated, derived from the association
    /// time so the two can never disagree. # C: O(1)
    pub fn connected_secs(&self, now_ns: u64) -> Option<u32> {
        let at = self.assoc_at_ns?;
        Some((now_ns.saturating_sub(at) / 1_000_000_000) as u32)
    }
}

/// A station modification request from userspace.
#[derive(Clone, Debug, Default)]
pub struct StationParams {
    pub aid: Option<u16>,
    pub listen_interval: Option<u16>,
    pub supported_rates: Option<Vec<u8>>,
    pub ht_capa: Option<Vec<u8>>,
    pub vht_capa: Option<Vec<u8>>,
    pub sta_flags: Option<StaFlags>,
    pub plink_action: Option<u8>,
    pub plink_state: Option<u8>,
    pub vlan_id: Option<u16>,
    pub airtime_weight: Option<u16>,
    pub capability: Option<u16>,
    pub ext_capa: Option<Vec<u8>>,
    pub opmode_notif: Option<u8>,
    /// Whether the station uses four-address frames.
    pub use_4addr: Option<bool>,
}

/// `NL80211_PLINK_*` mesh peer-link states.
pub mod plink_state {
    pub const LISTEN: u8 = 0;
    pub const OPN_SNT: u8 = 1;
    pub const OPN_RCVD: u8 = 2;
    pub const CNF_RCVD: u8 = 3;
    pub const ESTAB: u8 = 4;
    pub const HOLDING: u8 = 5;
    pub const BLOCKED: u8 = 6;
    pub const MAX: u8 = BLOCKED;
}

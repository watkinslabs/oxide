// What a radio can do. Every field here is advertised to userspace verbatim
// in a `GET_WIPHY` reply, and `wpa_supplicant` plans a whole connection from
// it: the bands and channels decide what it will scan, the cipher list
// decides what it will offer in its RSN element, and the interface-mode mask
// decides whether it will even try.

extern crate alloc;

use alloc::vec::Vec;

use crate::chan::Channel;
use crate::uapi::enums::Band;

/// One legacy rate a band supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bitrate {
    /// Rate in units of 100 kbit/s, the unit nl80211 reports.
    pub bitrate: u32,
    /// Flags from `bitrate_flags`.
    pub flags: u32,
}

/// Per-rate flags.
pub mod bitrate_flags {
    /// The rate has a short-preamble variant on 2 GHz.
    pub const SHORT_PREAMBLE: u32 = 1 << 0;
    /// The rate is a mandatory member of the basic rate set.
    pub const MANDATORY: u32 = 1 << 1;
}

/// One band a radio operates in.
#[derive(Clone, Debug)]
pub struct WiphyBand {
    pub band: Band,
    pub channels: Vec<Channel>,
    pub bitrates: Vec<Bitrate>,
    /// HT capability element body, when the band supports it.
    pub ht_cap: Option<[u8; 26]>,
    /// VHT capability element body, when the band supports it.
    pub vht_cap: Option<[u8; 12]>,
}

impl WiphyBand {
    /// A band with the channels and rates given and no high-throughput
    /// capability. # C: O(1)
    pub fn new(band: Band, channels: Vec<Channel>, bitrates: Vec<Bitrate>) -> Self {
        Self { band, channels, bitrates, ht_cap: None, vht_cap: None }
    }
    /// Channel at a centre frequency in MHz. # C: O(N channels)
    pub fn channel(&self, freq_mhz: u32) -> Option<&Channel> {
        self.channels.iter().find(|c| c.center_freq == freq_mhz)
    }
    /// Mutable channel at a centre frequency in MHz. # C: O(N channels)
    pub fn channel_mut(&mut self, freq_mhz: u32) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|c| c.center_freq == freq_mhz)
    }
}

/// The 2.4 GHz rate set every station supports, in 100 kbit/s units.
pub const RATES_2GHZ: [u32; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];
/// The 5 GHz rate set — no direct-sequence rates exist above 2.4 GHz.
pub const RATES_5GHZ: [u32; 8] = [60, 90, 120, 180, 240, 360, 480, 540];
/// Rates below this are direct-sequence and carry the short-preamble flag.
pub const CCK_RATE_MAX: u32 = 110;

/// Build the standard rate table for a band. # C: O(rates)
pub fn standard_bitrates(band: Band) -> Vec<Bitrate> {
    let (rates, cck): (&[u32], bool) = match band {
        Band::Band2Ghz | Band::BandLc => (&RATES_2GHZ, true),
        _ => (&RATES_5GHZ, false),
    };
    rates.iter().map(|&bitrate| {
        let mut flags = 0;
        if cck && bitrate <= CCK_RATE_MAX { flags |= bitrate_flags::SHORT_PREAMBLE; }
        Bitrate { bitrate, flags }
    }).collect()
}

/// Everything a radio advertises about itself.
#[derive(Clone, Debug)]
pub struct WiphyCaps {
    pub bands: Vec<WiphyBand>,
    /// Cipher suites the radio can install keys for, in advertisement order.
    pub cipher_suites: Vec<u32>,
    /// Bit `n` set means interface type `n` is supported.
    pub interface_modes: u32,
    /// Interface types the radio implements in software rather than hardware.
    pub software_iftypes: u32,
    pub max_scan_ssids: u8,
    pub max_sched_scan_ssids: u8,
    pub max_match_sets: u8,
    pub max_scan_ie_len: u16,
    pub max_sched_scan_ie_len: u16,
    pub max_num_pmkids: u8,
    /// Longest remain-on-channel request, in milliseconds.
    pub max_remain_on_channel_duration: u32,
    /// Largest number of stations an AP interface may hold.
    pub max_ap_assoc_sta: u16,
    /// Antennas available, as bit masks.
    pub available_antennas_tx: u32,
    pub available_antennas_rx: u32,
    /// `feature_flags` bits.
    pub features: u32,
    /// Immutable radio capability bits from `wiphy::flags`.
    pub flags: u32,
    /// `ext_feature` bit positions the radio sets.
    pub ext_features: Vec<u32>,
    /// Whether the radio manages its own regulatory domain and ignores the
    /// core's.
    pub self_managed_reg: bool,
    /// Whether the radio's own firmware runs the AP-side management state
    /// machine.
    pub ap_sme: bool,
    /// Whether the radio signals in dBm rather than an unspecified unit.
    pub signal_dbm: bool,
    /// Management frame subtypes the radio can transmit, per interface type.
    pub mgmt_stypes: Vec<MgmtStypes>,
}

/// Which management frames one interface type may send and receive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MgmtStypes {
    pub iftype: u32,
    /// Bit `n` set means subtype `n` (the subtype field shifted down four)
    /// may be transmitted.
    pub tx: u16,
    /// Bit `n` set means subtype `n` may be registered for on receive.
    pub rx: u16,
}

impl Default for WiphyCaps {
    fn default() -> Self {
        Self {
            bands: Vec::new(), cipher_suites: Vec::new(),
            interface_modes: 0, software_iftypes: 0,
            max_scan_ssids: 4, max_sched_scan_ssids: 0, max_match_sets: 0,
            max_scan_ie_len: 2048, max_sched_scan_ie_len: 0, max_num_pmkids: 0,
            max_remain_on_channel_duration: 5000, max_ap_assoc_sta: 0,
            available_antennas_tx: 0, available_antennas_rx: 0,
            features: 0, flags: 0, ext_features: Vec::new(),
            self_managed_reg: false, ap_sme: false, signal_dbm: true,
            mgmt_stypes: Vec::new(),
        }
    }
}

impl WiphyCaps {
    /// Mark an interface type supported. # C: O(1)
    pub fn add_iftype(&mut self, ty: crate::uapi::enums::IfType) {
        self.interface_modes |= 1u32 << ty.as_u32();
    }
    /// Mark an extended feature bit set. # C: O(N features)
    pub fn add_ext_feature(&mut self, bit: u32) {
        if !self.ext_features.contains(&bit) { self.ext_features.push(bit); }
    }
    /// Whether an extended feature bit is set. # C: O(N features)
    pub fn has_ext_feature(&self, bit: u32) -> bool { self.ext_features.contains(&bit) }
    /// Whether an immutable radio capability bit is set. # C: O(1)
    pub fn has_flag(&self, bit: u32) -> bool { self.flags & bit != 0 }
    /// Band record for a band. # C: O(N bands)
    pub fn band(&self, band: Band) -> Option<&WiphyBand> {
        self.bands.iter().find(|b| b.band == band)
    }
    /// The extended-feature bitmap as nl80211 carries it: one byte per eight
    /// bits, least significant bit first. # C: O(N features)
    pub fn ext_features_bytes(&self) -> Vec<u8> {
        let Some(&highest) = self.ext_features.iter().max() else { return Vec::new(); };
        let mut out = alloc::vec![0u8; (highest / 8 + 1) as usize];
        for &bit in &self.ext_features { out[(bit / 8) as usize] |= 1 << (bit % 8); }
        out
    }
}

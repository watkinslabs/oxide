// Channels: the number/frequency mapping, one channel's regulatory state,
// and the channel definition an operating interface commits to.
//
// The number/frequency mapping is not one formula. Bands overlap in channel
// number, one 2 GHz channel sits off the arithmetic grid, and the 6 GHz band
// has a channel whose frequency is below its own base, so a single "base plus
// five times number" rule is wrong on four separate counts.

extern crate alloc;

use alloc::vec::Vec;

use crate::uapi::enums::{Band, ChanWidth};

/// One megahertz in kilohertz — every frequency here is held in kHz because
/// the 6 GHz and S1G bands place channels off the megahertz grid.
pub const KHZ_PER_MHZ: u32 = 1000;

/// Convert MHz to kHz. # C: O(1)
pub const fn mhz_to_khz(mhz: u32) -> u32 { mhz * KHZ_PER_MHZ }
/// Convert kHz to MHz, truncating. # C: O(1)
pub const fn khz_to_mhz(khz: u32) -> u32 { khz / KHZ_PER_MHZ }

/// Centre frequency in kHz of a channel number within a band. Zero means the
/// number is not a channel in that band. # C: O(1)
pub fn channel_to_freq_khz(chan: i32, band: Band) -> u32 {
    if chan <= 0 { return 0; }
    let chan = chan as u32;
    match band {
        Band::Band2Ghz | Band::BandLc => {
            if chan == 14 { mhz_to_khz(2484) }
            else if chan < 14 { mhz_to_khz(2407 + chan * 5) }
            else { 0 }
        }
        Band::Band5Ghz => {
            if (182..=196).contains(&chan) { mhz_to_khz(4000 + chan * 5) }
            else { mhz_to_khz(5000 + chan * 5) }
        }
        Band::Band6Ghz => {
            if chan == 2 { mhz_to_khz(5935) }
            else if chan <= 253 { mhz_to_khz(5950 + chan * 5) }
            else { 0 }
        }
        Band::Band60Ghz => if chan < 7 { mhz_to_khz(56160 + chan * 2160) } else { 0 },
        Band::BandS1Ghz => 902_000 + chan * 500,
    }
}

/// Centre frequency in MHz of a channel number within a band. # C: O(1)
pub fn channel_to_freq(chan: i32, band: Band) -> u32 { khz_to_mhz(channel_to_freq_khz(chan, band)) }

/// Channel number a frequency in kHz names. Zero means no channel. # C: O(1)
pub fn freq_khz_to_channel(freq_khz: u32) -> u32 {
    let freq = khz_to_mhz(freq_khz);
    if freq == 2484 { 14 }
    else if freq < 2484 { freq.saturating_sub(2407) / 5 }
    else if (4910..=4980).contains(&freq) { (freq - 4000) / 5 }
    else if freq < 5925 { (freq - 5000) / 5 }
    else if freq == 5935 { 2 }
    else if freq <= 45000 { (freq - 5950) / 5 }
    else if (58320..=70200).contains(&freq) { (freq - 56160) / 2160 }
    else { 0 }
}

/// Band a frequency in kHz falls in. # C: O(1)
pub fn freq_khz_to_band(freq_khz: u32) -> Option<Band> {
    let freq = khz_to_mhz(freq_khz);
    Some(match freq {
        0..=901 => return None,
        902..=928 => Band::BandS1Ghz,
        2400..=2500 => Band::Band2Ghz,
        4900..=5895 => Band::Band5Ghz,
        5925..=7125 => Band::Band6Ghz,
        58320..=70200 => Band::Band60Ghz,
        _ => return None,
    })
}

/// One channel a radio can operate on, with the restrictions the current
/// regulatory domain places on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel {
    /// Centre frequency in MHz.
    pub center_freq: u32,
    /// Offset from `center_freq` in kHz, for the channels off the MHz grid.
    pub freq_offset: u32,
    pub band: Band,
    /// Channel number in its band.
    pub hw_value: u16,
    /// Highest transmit power the regulatory domain allows, in dBm.
    pub max_power: i32,
    /// Highest antenna gain the regulatory domain allows, in dBi.
    pub max_antenna_gain: i32,
    /// Regulatory restrictions in force, from `reg_rule_flags`.
    pub flags: u32,
    /// Radar-clearance state when this channel is under DFS.
    pub dfs_state: u32,
    /// Monotonic nanoseconds at which `dfs_state` last changed.
    pub dfs_state_entered_ns: u64,
    /// Channel-availability-check duration in milliseconds.
    pub dfs_cac_ms: u32,
}

/// Channel-level restriction flags, mirroring the regulatory rule flags a
/// rule contributes to each channel it covers.
pub mod chan_flags {
    /// The channel may not be used at all.
    pub const DISABLED: u32 = 1 << 0;
    /// No initiating radiation: no beaconing and no probe requests, so the
    /// channel is passive-scan only until a beacon is heard on it.
    pub const NO_IR: u32 = 1 << 1;
    pub const RADAR: u32 = 1 << 2;
    pub const NO_HT40PLUS: u32 = 1 << 3;
    pub const NO_HT40MINUS: u32 = 1 << 4;
    pub const NO_OFDM: u32 = 1 << 5;
    pub const NO_80MHZ: u32 = 1 << 6;
    pub const NO_160MHZ: u32 = 1 << 7;
    pub const INDOOR_ONLY: u32 = 1 << 8;
    pub const IR_CONCURRENT: u32 = 1 << 9;
    pub const NO_20MHZ: u32 = 1 << 10;
    pub const NO_10MHZ: u32 = 1 << 11;
    pub const NO_HE: u32 = 1 << 12;
    pub const NO_320MHZ: u32 = 1 << 13;
    pub const NO_EHT: u32 = 1 << 14;
    pub const PSD: u32 = 1 << 15;
    pub const DFS_CONCURRENT: u32 = 1 << 16;
    /// Both HT40 directions barred.
    pub const NO_HT40: u32 = NO_HT40PLUS | NO_HT40MINUS;
}

impl Channel {
    /// A channel with no restrictions, at the default power ceiling. # C: O(1)
    pub fn new(center_freq: u32, band: Band, max_power: i32) -> Self {
        Self {
            center_freq, freq_offset: 0, band,
            hw_value: freq_khz_to_channel(mhz_to_khz(center_freq)) as u16,
            max_power, max_antenna_gain: 0, flags: 0,
            dfs_state: crate::uapi::enums::dfs_state::USABLE,
            dfs_state_entered_ns: 0, dfs_cac_ms: 0,
        }
    }
    /// Full centre frequency in kHz, offset included. # C: O(1)
    pub fn center_freq_khz(&self) -> u32 { mhz_to_khz(self.center_freq) + self.freq_offset }
    /// Whether the channel is usable at all right now. # C: O(1)
    pub fn is_usable(&self) -> bool { self.flags & chan_flags::DISABLED == 0 }
    /// Whether a scan on this channel must be passive: the regulatory domain
    /// forbids initiating radiation, so no probe request may go out until a
    /// beacon has been heard. # C: O(1)
    pub fn scan_is_passive(&self) -> bool {
        self.flags & (chan_flags::DISABLED | chan_flags::NO_IR) != 0
    }
    /// Whether beaconing on this channel is allowed. A radar channel is only
    /// available once its availability check has completed. # C: O(1)
    pub fn can_beacon(&self) -> bool {
        if !self.is_usable() { return false; }
        if self.flags & chan_flags::RADAR != 0 {
            return self.dfs_state == crate::uapi::enums::dfs_state::AVAILABLE;
        }
        self.flags & chan_flags::NO_IR == 0
    }
}

/// The channel an interface operates on: a primary channel, a width, and the
/// segment centres that width implies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChanDef {
    pub chan: Channel,
    pub width: ChanWidth,
    /// Centre of the first (or only) frequency segment, in MHz.
    pub center_freq1: u32,
    /// Offset of `center_freq1` in kHz.
    pub freq1_offset: u32,
    /// Centre of the second segment, only meaningful for the split width.
    pub center_freq2: u32,
}

impl ChanDef {
    /// A 20 MHz definition on one channel. # C: O(1)
    pub fn new_20(chan: Channel) -> Self {
        Self { chan, width: ChanWidth::Width20, center_freq1: chan.center_freq,
               freq1_offset: chan.freq_offset, center_freq2: 0 }
    }
    /// A definition of a given width whose segment centre is stated. # C: O(1)
    pub fn new(chan: Channel, width: ChanWidth, center_freq1: u32, center_freq2: u32) -> Self {
        Self { chan, width, center_freq1, freq1_offset: 0, center_freq2 }
    }

    /// Whether the definition is internally consistent: the width takes the
    /// segment centres it needs and no others, the primary channel lies
    /// inside the first segment, and the segment centre sits on the grid the
    /// width requires. An inconsistent definition is refused here rather than
    /// programmed into a radio. # C: O(1)
    pub fn is_valid(&self) -> bool {
        let needs_freq2 = self.width == ChanWidth::Width80P80;
        if needs_freq2 != (self.center_freq2 != 0) { return false; }
        if self.center_freq1 == 0 { return false; }
        let bw_mhz = khz_to_mhz(self.width.khz());
        match self.width {
            // A single-channel width places the centre on the channel itself.
            ChanWidth::Width20NoHt | ChanWidth::Width20 | ChanWidth::Width5
                | ChanWidth::Width10 | ChanWidth::Width1 | ChanWidth::Width2
                | ChanWidth::Width4 | ChanWidth::Width8 | ChanWidth::Width16 => {
                self.center_freq1 == self.chan.center_freq
            }
            // A wide channel's centre is offset from the primary by half the
            // width minus half a channel, and the primary must fall inside.
            // A split channel is two eighty-megahertz segments that do not
            // touch. Their centres sit on the same ten-megahertz offset grid
            // the wide widths use, NOT on a twenty-megahertz boundary.
            ChanWidth::Width80P80 => {
                self.contains_primary(80) && self.center_freq2 % 10 == 0
                    && self.center_freq1.abs_diff(self.center_freq2) > 80
            }
            _ => self.contains_primary(bw_mhz),
        }
    }

    /// Whether the primary channel lies within `bw_mhz` centred on the first
    /// segment centre, on the 20 MHz grid that width uses. # C: O(1)
    fn contains_primary(&self, bw_mhz: u32) -> bool {
        let half = bw_mhz / 2;
        let low = self.center_freq1.saturating_sub(half);
        let high = self.center_freq1 + half;
        let primary = self.chan.center_freq;
        primary > low && primary < high && (primary.abs_diff(self.center_freq1)) % 10 == 0
    }

    /// Every 20 MHz channel centre the definition occupies. A caller checking
    /// the definition against a regulatory domain must check all of them, not
    /// only the primary. # C: O(width)
    pub fn covered_freqs(&self) -> Vec<u32> {
        let mut out = Vec::new();
        let mut push_segment = |center: u32, bw: u32| {
            if center == 0 || bw == 0 { return; }
            let n = bw / 20;
            if n == 0 { out.push(center); return; }
            let first = center - bw / 2 + 10;
            for i in 0..n { out.push(first + i * 20); }
        };
        match self.width {
            ChanWidth::Width80P80 => {
                push_segment(self.center_freq1, 80);
                push_segment(self.center_freq2, 80);
            }
            ChanWidth::Width20NoHt | ChanWidth::Width20 | ChanWidth::Width5
                | ChanWidth::Width10 | ChanWidth::Width1 | ChanWidth::Width2
                | ChanWidth::Width4 | ChanWidth::Width8 | ChanWidth::Width16 =>
                out.push(self.chan.center_freq),
            _ => push_segment(self.center_freq1, khz_to_mhz(self.width.khz())),
        }
        out
    }

    /// Whether two definitions describe the same operating channel. # C: O(1)
    pub fn is_identical(&self, other: &Self) -> bool {
        self.chan.center_freq == other.chan.center_freq
            && self.chan.freq_offset == other.chan.freq_offset
            && self.width == other.width
            && self.center_freq1 == other.center_freq1
            && self.freq1_offset == other.freq1_offset
            && self.center_freq2 == other.center_freq2
    }
}

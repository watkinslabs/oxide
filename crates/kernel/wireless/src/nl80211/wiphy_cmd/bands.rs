// The band description inside a radio's advertisement: every channel with the
// restrictions in force on it, every legacy rate, and the high-throughput
// capability blobs.
//
// `wpa_supplicant` plans a scan from exactly this and nothing else. A channel
// omitted here is a channel it will never tune to, and a restriction flag
// omitted here is a channel it will transmit on where it may not.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::chan::{chan_flags, Channel};
use crate::uapi::nested::{band_attr, bitrate_attr, freq_attr};
use crate::wiphy::caps::{bitrate_flags, WiphyBand};

use super::super::msg;

/// Millibel-milliwatts per decibel-milliwatt: the unit the frequency list
/// reports transmit power in.
const MBM_PER_DBM: i32 = 100;

/// Offset of the capability-information field inside a high-throughput
/// capability element body.
const HT_CAP_INFO: usize = 0;
/// Offset of the aggregation-parameters byte.
const HT_AMPDU_PARAMS: usize = 2;
/// Offset and width of the modulation-and-coding set.
const HT_MCS_SET: usize = 3;
const HT_MCS_SET_LEN: usize = 16;
/// Aggregation exponent field of the aggregation-parameters byte.
const HT_AMPDU_FACTOR_MASK: u8 = 0x03;
/// Aggregation spacing field, and how far it is shifted up.
const HT_AMPDU_DENSITY_MASK: u8 = 0x07;
const HT_AMPDU_DENSITY_SHIFT: u32 = 2;

/// Offset of the capability field inside a very-high-throughput capability
/// element body, and the offset and width of its coding set.
const VHT_CAP_INFO: usize = 0;
const VHT_MCS_SET: usize = 4;
const VHT_MCS_SET_LEN: usize = 8;

/// Append every band of a radio, each nested under its own band number.
///
/// The nest index is the band's own number and not a running counter: a
/// reader indexes it directly, so a radio with only a 5 GHz band must still
/// report that band under the 5 GHz number. # C: O(N channels)
pub fn put_all(out: &mut Vec<u8>, bands: &[WiphyBand]) {
    let all = attr::nest_start(out, crate::uapi::attr::WIPHY_BANDS);
    for band in bands.iter() {
        let one = attr::nest_start(out, band.band.as_u32() as u16);
        put_capabilities(out, band);
        put_rates(out, band);
        put_freqs(out, band);
        attr::nest_end(out, one);
    }
    attr::nest_end(out, all);
}

/// The high-throughput capability blobs a band supports, split into the four
/// attributes nl80211 carries them in. # C: O(1)
fn put_capabilities(out: &mut Vec<u8>, band: &WiphyBand) {
    if let Some(ht) = &band.ht_cap {
        attr::put(out, band_attr::HT_MCS_SET, &ht[HT_MCS_SET..HT_MCS_SET + HT_MCS_SET_LEN]);
        attr::put_u16(out, band_attr::HT_CAPA,
                      u16::from_le_bytes([ht[HT_CAP_INFO], ht[HT_CAP_INFO + 1]]));
        let params = ht[HT_AMPDU_PARAMS];
        msg::put_u8(out, band_attr::HT_AMPDU_FACTOR, params & HT_AMPDU_FACTOR_MASK);
        msg::put_u8(out, band_attr::HT_AMPDU_DENSITY,
                    (params >> HT_AMPDU_DENSITY_SHIFT) & HT_AMPDU_DENSITY_MASK);
    }
    if let Some(vht) = &band.vht_cap {
        attr::put(out, band_attr::VHT_MCS_SET,
                  &vht[VHT_MCS_SET..VHT_MCS_SET + VHT_MCS_SET_LEN]);
        attr::put_u32(out, band_attr::VHT_CAPA, u32::from_le_bytes([
            vht[VHT_CAP_INFO], vht[VHT_CAP_INFO + 1],
            vht[VHT_CAP_INFO + 2], vht[VHT_CAP_INFO + 3]]));
    }
}

/// The legacy rate list, each rate nested under its position. # C: O(N rates)
fn put_rates(out: &mut Vec<u8>, band: &WiphyBand) {
    let rates = attr::nest_start(out, band_attr::RATES);
    for (i, rate) in band.bitrates.iter().enumerate() {
        let one = attr::nest_start(out, i as u16);
        attr::put_u32(out, bitrate_attr::RATE, rate.bitrate);
        if rate.flags & bitrate_flags::SHORT_PREAMBLE != 0 {
            msg::put_flag(out, bitrate_attr::SHORTPREAMBLE_2GHZ);
        }
        attr::nest_end(out, one);
    }
    attr::nest_end(out, rates);
}

/// The channel list, each channel nested under its position. # C: O(N channels)
fn put_freqs(out: &mut Vec<u8>, band: &WiphyBand) {
    let freqs = attr::nest_start(out, band_attr::FREQS);
    for (i, chan) in band.channels.iter().enumerate() {
        let one = attr::nest_start(out, i as u16);
        put_channel(out, chan);
        attr::nest_end(out, one);
    }
    attr::nest_end(out, freqs);
}

/// One channel. Every restriction is a flag attribute written only when the
/// restriction is in force: a flag carries no payload, so writing one for a
/// cleared restriction still reads as TRUE. # C: O(1)
pub fn put_channel(out: &mut Vec<u8>, chan: &Channel) {
    attr::put_u32(out, freq_attr::FREQ, chan.center_freq);
    if chan.freq_offset != 0 { attr::put_u32(out, freq_attr::OFFSET, chan.freq_offset); }
    put_flag_if(out, chan.flags, chan_flags::DISABLED, freq_attr::DISABLED);
    put_flag_if(out, chan.flags, chan_flags::NO_IR, freq_attr::NO_IR);
    if chan.flags & chan_flags::RADAR != 0 {
        msg::put_flag(out, freq_attr::RADAR);
        attr::put_u32(out, freq_attr::DFS_STATE, chan.dfs_state);
        attr::put_u32(out, freq_attr::DFS_CAC_TIME, chan.dfs_cac_ms);
    }
    put_flag_if(out, chan.flags, chan_flags::NO_HT40MINUS, freq_attr::NO_HT40_MINUS);
    put_flag_if(out, chan.flags, chan_flags::NO_HT40PLUS, freq_attr::NO_HT40_PLUS);
    put_flag_if(out, chan.flags, chan_flags::NO_80MHZ, freq_attr::NO_80MHZ);
    put_flag_if(out, chan.flags, chan_flags::NO_160MHZ, freq_attr::NO_160MHZ);
    put_flag_if(out, chan.flags, chan_flags::INDOOR_ONLY, freq_attr::INDOOR_ONLY);
    put_flag_if(out, chan.flags, chan_flags::IR_CONCURRENT, freq_attr::IR_CONCURRENT);
    put_flag_if(out, chan.flags, chan_flags::NO_20MHZ, freq_attr::NO_20MHZ);
    put_flag_if(out, chan.flags, chan_flags::NO_10MHZ, freq_attr::NO_10MHZ);
    put_flag_if(out, chan.flags, chan_flags::NO_HE, freq_attr::NO_HE);
    put_flag_if(out, chan.flags, chan_flags::NO_320MHZ, freq_attr::NO_320MHZ);
    put_flag_if(out, chan.flags, chan_flags::NO_EHT, freq_attr::NO_EHT);
    attr::put_u32(out, freq_attr::MAX_TX_POWER, (chan.max_power * MBM_PER_DBM) as u32);
}

/// Write a flag attribute only when its restriction is set. # C: O(1)
fn put_flag_if(out: &mut Vec<u8>, flags: u32, bit: u32, ty: u16) {
    if flags & bit != 0 { msg::put_flag(out, ty); }
}


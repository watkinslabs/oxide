// The per-station report and the per-channel survey.
//
// Every counter is written only when the driver actually has it. A driver
// that keeps no retry count must not report zero retries: zero is a
// measurement and `iw dev link` prints it as one.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::ops::SurveyInfo;
use crate::sta::{rate_gen, RateInfo, StationInfo};
use crate::uapi::attr as a;
use crate::uapi::enums::ChanWidth;
use crate::uapi::nested::{rate_info, sta_info, survey_info};
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::super::msg;

/// `NL80211_STA_BSS_PARAM_*` — the network parameters inside a station report.
mod bss_param {
    pub const CTS_PROT: u16 = 1;
    pub const SHORT_PREAMBLE: u16 = 2;
    pub const SHORT_SLOT_TIME: u16 = 3;
    pub const DTIM_PERIOD: u16 = 4;
    pub const BEACON_INTERVAL: u16 = 5;
}

/// `NL80211_TID_STATS_*` — per-traffic-identifier counters.
mod tid_stats {
    pub const RX_MSDU: u16 = 1;
    pub const TX_MSDU: u16 = 2;
    pub const TX_MSDU_RETRIES: u16 = 3;
    pub const TX_MSDU_FAILED: u16 = 4;
    pub const PAD: u16 = 5;
}

/// Widest bitrate a 16-bit attribute can carry, in 100 kbit/s units.
const BITRATE16_LIMIT: u32 = 1 << 16;

/// Append one station's report, nested, with the identity attributes outside
/// the nest. # C: O(N fields)
pub fn put(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, info: &StationInfo) {
    if let Some(ifindex) = wdev.ifindex() { attr::put_u32(out, a::IFINDEX, ifindex); }
    msg::put_u64(out, a::WDEV, wdev.identifier, a::PAD);
    msg::put_mac(out, a::MAC, info.mac);
    attr::put_u32(out, a::GENERATION, info.generation);

    let at = attr::nest_start(out, a::STA_INFO);
    put_counters(out, info);
    put_signal(out, wiphy, info);
    if let Some(r) = &info.tx_bitrate { put_rate(out, sta_info::TX_BITRATE, r); }
    if let Some(r) = &info.rx_bitrate { put_rate(out, sta_info::RX_BITRATE, r); }
    if let Some(p) = &info.bss_param { put_bss_param(out, p); }
    if let Some(f) = &info.sta_flags {
        let mut payload = [0u8; 8];
        payload[..4].copy_from_slice(&f.mask.to_ne_bytes());
        payload[4..].copy_from_slice(&f.set.to_ne_bytes());
        attr::put(out, sta_info::STA_FLAGS, &payload);
    }
    put_tid_stats(out, info);
    attr::nest_end(out, at);
}

/// The plain counters. # C: O(1)
fn put_counters(out: &mut Vec<u8>, info: &StationInfo) {
    if let Some(v) = info.connected_time { attr::put_u32(out, sta_info::CONNECTED_TIME, v); }
    if let Some(v) = info.inactive_time { attr::put_u32(out, sta_info::INACTIVE_TIME, v); }
    if let Some(v) = info.assoc_at_ns {
        msg::put_u64(out, sta_info::ASSOC_AT_BOOTTIME, v, sta_info::PAD);
    }
    // The 32-bit byte counters predate the 64-bit ones and both go out: old
    // tools read only the narrow pair and would otherwise see no traffic.
    if let Some(v) = info.rx_bytes {
        attr::put_u32(out, sta_info::RX_BYTES, v as u32);
        msg::put_u64(out, sta_info::RX_BYTES64, v, sta_info::PAD);
    }
    if let Some(v) = info.tx_bytes {
        attr::put_u32(out, sta_info::TX_BYTES, v as u32);
        msg::put_u64(out, sta_info::TX_BYTES64, v, sta_info::PAD);
    }
    if let Some(v) = info.rx_duration { msg::put_u64(out, sta_info::RX_DURATION, v, sta_info::PAD); }
    if let Some(v) = info.tx_duration { msg::put_u64(out, sta_info::TX_DURATION, v, sta_info::PAD); }
    if let Some(v) = info.rx_packets { attr::put_u32(out, sta_info::RX_PACKETS, v); }
    if let Some(v) = info.tx_packets { attr::put_u32(out, sta_info::TX_PACKETS, v); }
    if let Some(v) = info.tx_retries { attr::put_u32(out, sta_info::TX_RETRIES, v); }
    if let Some(v) = info.tx_failed { attr::put_u32(out, sta_info::TX_FAILED, v); }
    if let Some(v) = info.expected_throughput {
        attr::put_u32(out, sta_info::EXPECTED_THROUGHPUT, v);
    }
    if let Some(v) = info.beacon_loss_count { attr::put_u32(out, sta_info::BEACON_LOSS, v); }
    if let Some(v) = info.plink_state { msg::put_u8(out, sta_info::PLINK_STATE, v); }
    if let Some(v) = info.rx_dropped_misc { msg::put_u64(out, sta_info::RX_DROP_MISC, v, sta_info::PAD); }
    if let Some(v) = info.beacon_rx { msg::put_u64(out, sta_info::BEACON_RX, v, sta_info::PAD); }
}

/// The signal levels, which are only meaningful when the radio reports in a
/// defined unit. # C: O(N chains)
fn put_signal(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>, info: &StationInfo) {
    if !wiphy.caps.signal_dbm { return; }
    if let Some(v) = info.signal { msg::put_u8(out, sta_info::SIGNAL, v as u8); }
    if let Some(v) = info.signal_avg { msg::put_u8(out, sta_info::SIGNAL_AVG, v as u8); }
    if let Some(v) = info.beacon_signal_avg {
        msg::put_u8(out, sta_info::BEACON_SIGNAL_AVG, v as u8);
    }
    put_chain(out, sta_info::CHAIN_SIGNAL, &info.chain_signal);
    put_chain(out, sta_info::CHAIN_SIGNAL_AVG, &info.chain_signal_avg);
    if let Some(v) = info.ack_signal { msg::put_u8(out, sta_info::ACK_SIGNAL, v as u8); }
    if let Some(v) = info.ack_signal_avg {
        msg::put_u8(out, sta_info::ACK_SIGNAL_AVG, v as u8);
    }
}

/// One per-antenna signal list, nested and numbered by antenna. # C: O(N chains)
fn put_chain(out: &mut Vec<u8>, ty: u16, values: &[i8]) {
    if values.is_empty() { return; }
    let at = attr::nest_start(out, ty);
    for (i, &v) in values.iter().enumerate() { msg::put_u8(out, i as u16, v as u8); }
    attr::nest_end(out, at);
}

/// One direction's negotiated rate. The wide form is always written and the
/// narrow one only when the rate fits it, because a rate above the narrow
/// form's ceiling reported as zero reads as no link at all. # C: O(1)
pub fn put_rate(out: &mut Vec<u8>, ty: u16, rate: &RateInfo) {
    let at = attr::nest_start(out, ty);
    if rate.bitrate > 0 { attr::put_u32(out, rate_info::BITRATE32, rate.bitrate); }
    if rate.bitrate > 0 && rate.bitrate < BITRATE16_LIMIT {
        attr::put_u16(out, rate_info::BITRATE, rate.bitrate as u16);
    }
    if let Some(flag) = width_flag(rate.width) { msg::put_flag(out, flag); }
    match rate.generation {
        rate_gen::HT => {
            if let Some(mcs) = rate.mcs { msg::put_u8(out, rate_info::MCS, mcs); }
            if rate.short_gi { msg::put_flag(out, rate_info::SHORT_GI); }
        }
        rate_gen::VHT => {
            if let Some(mcs) = rate.mcs { msg::put_u8(out, rate_info::VHT_MCS, mcs); }
            if let Some(nss) = rate.nss { msg::put_u8(out, rate_info::VHT_NSS, nss); }
            if rate.short_gi { msg::put_flag(out, rate_info::SHORT_GI); }
        }
        rate_gen::HE => {
            if let Some(mcs) = rate.mcs { msg::put_u8(out, rate_info::HE_MCS, mcs); }
            if let Some(nss) = rate.nss { msg::put_u8(out, rate_info::HE_NSS, nss); }
        }
        rate_gen::EHT => {
            if let Some(mcs) = rate.mcs { msg::put_u8(out, rate_info::EHT_MCS, mcs); }
            if let Some(nss) = rate.nss { msg::put_u8(out, rate_info::EHT_NSS, nss); }
        }
        _ => {}
    }
    attr::nest_end(out, at);
}

/// The flag that names a rate's width. The 20 MHz width has none: it is what
/// a rate with no width flag means. # C: O(1)
fn width_flag(width: ChanWidth) -> Option<u16> {
    Some(match width {
        ChanWidth::Width20 | ChanWidth::Width20NoHt => return None,
        ChanWidth::Width40 => rate_info::WIDTH_40,
        ChanWidth::Width80 => rate_info::WIDTH_80,
        ChanWidth::Width80P80 => rate_info::WIDTH_80P80,
        ChanWidth::Width160 => rate_info::WIDTH_160,
        ChanWidth::Width320 => rate_info::WIDTH_320,
        ChanWidth::Width10 => rate_info::WIDTH_10,
        ChanWidth::Width5 => rate_info::WIDTH_5,
        _ => return None,
    })
}

/// The parameters of the network the station belongs to. # C: O(1)
fn put_bss_param(out: &mut Vec<u8>, p: &crate::sta::BssParam) {
    let at = attr::nest_start(out, sta_info::BSS_PARAM);
    if p.cts_protection { msg::put_flag(out, bss_param::CTS_PROT); }
    if p.short_preamble { msg::put_flag(out, bss_param::SHORT_PREAMBLE); }
    if p.short_slot_time { msg::put_flag(out, bss_param::SHORT_SLOT_TIME); }
    msg::put_u8(out, bss_param::DTIM_PERIOD, p.dtim_period);
    attr::put_u16(out, bss_param::BEACON_INTERVAL, p.beacon_interval);
    attr::nest_end(out, at);
}

/// Per-traffic-identifier counters, each nested under its identifier plus
/// one — the nest is numbered from one, not from zero. # C: O(N tids)
fn put_tid_stats(out: &mut Vec<u8>, info: &StationInfo) {
    if info.tid_stats.is_empty() { return; }
    let all = attr::nest_start(out, sta_info::TID_STATS);
    for (tid, stats) in info.tid_stats.iter() {
        let one = attr::nest_start(out, *tid as u16 + 1);
        msg::put_u64(out, tid_stats::RX_MSDU, stats.rx_msdu, tid_stats::PAD);
        msg::put_u64(out, tid_stats::TX_MSDU, stats.tx_msdu, tid_stats::PAD);
        msg::put_u64(out, tid_stats::TX_MSDU_RETRIES, stats.tx_msdu_retries, tid_stats::PAD);
        msg::put_u64(out, tid_stats::TX_MSDU_FAILED, stats.tx_msdu_failed, tid_stats::PAD);
        attr::nest_end(out, one);
    }
    attr::nest_end(out, all);
}

/// One channel's occupancy report. # C: O(1)
pub fn put_survey(out: &mut Vec<u8>, wdev: &Arc<Wdev>, s: &SurveyInfo) {
    if let Some(ifindex) = wdev.ifindex() { attr::put_u32(out, a::IFINDEX, ifindex); }
    msg::put_u64(out, a::WDEV, wdev.identifier, a::PAD);
    let at = attr::nest_start(out, a::SURVEY_INFO);
    if s.freq != 0 { attr::put_u32(out, survey_info::FREQUENCY, s.freq); }
    if let Some(v) = s.noise { msg::put_u8(out, survey_info::NOISE, v as u8); }
    if s.in_use { msg::put_flag(out, survey_info::IN_USE); }
    if let Some(v) = s.time_ms { msg::put_u64(out, survey_info::TIME, v, survey_info::PAD); }
    if let Some(v) = s.time_busy_ms { msg::put_u64(out, survey_info::TIME_BUSY, v, survey_info::PAD); }
    if let Some(v) = s.time_ext_busy_ms { msg::put_u64(out, survey_info::TIME_EXT_BUSY, v, survey_info::PAD); }
    if let Some(v) = s.time_rx_ms { msg::put_u64(out, survey_info::TIME_RX, v, survey_info::PAD); }
    if let Some(v) = s.time_tx_ms { msg::put_u64(out, survey_info::TIME_TX, v, survey_info::PAD); }
    if let Some(v) = s.time_scan_ms {
        msg::put_u64(out, survey_info::TIME_SCAN, v, survey_info::PAD);
    }
    attr::nest_end(out, at);
}

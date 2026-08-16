// The body of a radio's advertisement — everything a `GET_WIPHY` reply
// carries beyond the identity attributes.
//
// This is the single largest thing nl80211 emits and userspace plans from all
// of it: the interface-mode mask decides whether NetworkManager will create an
// access point, the command list decides whether `iw` offers a subcommand at
// all, and the cipher list decides what `wpa_supplicant` puts in its robust
// security element.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::uapi::attr as a;
use crate::wiphy::caps::MgmtStypes;
use crate::wiphy::Wiphy;

use super::super::msg;
use super::bands;

/// Number of interface types the mode mask can hold.
const NUM_IFTYPES: u32 = 32;
/// Management frame type field of a frame-control word, and the shift that
/// turns a subtype bit position into a subtype field.
const FTYPE_MGMT: u16 = crate::ieee80211::fctl::FTYPE_MGMT;
const STYPE_SHIFT: u32 = 4;
/// Subtypes a frame-control word can name.
const NUM_MGMT_STYPES: u32 = 16;

/// Append the identity attributes every wiphy message starts with. # C: O(1)
pub fn put_identity(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>) {
    attr::put_u32(out, a::WIPHY, wiphy.index);
    attr::put_str(out, a::WIPHY_NAME, &wiphy.name);
    attr::put_u32(out, a::GENERATION, wiphy.generation());
}

/// Append everything a radio advertises about itself. # C: O(N channels)
pub fn put(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>) {
    let caps = &wiphy.caps;
    let cfg = wiphy.config();

    msg::put_u8(out, a::WIPHY_RETRY_SHORT, cfg.retry_short);
    msg::put_u8(out, a::WIPHY_RETRY_LONG, cfg.retry_long);
    attr::put_u32(out, a::WIPHY_FRAG_THRESHOLD, cfg.frag_threshold);
    attr::put_u32(out, a::WIPHY_RTS_THRESHOLD, cfg.rts_threshold);
    msg::put_u8(out, a::WIPHY_COVERAGE_CLASS, cfg.coverage_class as u8);
    msg::put_u8(out, a::MAX_NUM_SCAN_SSIDS, caps.max_scan_ssids);
    msg::put_u8(out, a::MAX_NUM_SCHED_SCAN_SSIDS, caps.max_sched_scan_ssids);
    attr::put_u16(out, a::MAX_SCAN_IE_LEN, caps.max_scan_ie_len);
    attr::put_u16(out, a::MAX_SCHED_SCAN_IE_LEN, caps.max_sched_scan_ie_len);
    msg::put_u8(out, a::MAX_MATCH_SETS, caps.max_match_sets);

    msg::put_u32_array(out, a::CIPHER_SUITES, &caps.cipher_suites);
    msg::put_u8(out, a::MAX_NUM_PMKIDS, caps.max_num_pmkids);
    attr::put_u32(out, a::WIPHY_ANTENNA_AVAIL_TX, caps.available_antennas_tx);
    attr::put_u32(out, a::WIPHY_ANTENNA_AVAIL_RX, caps.available_antennas_rx);
    if caps.available_antennas_tx != 0 || caps.available_antennas_rx != 0 {
        attr::put_u32(out, a::WIPHY_ANTENNA_TX, cfg.antenna_tx);
        attr::put_u32(out, a::WIPHY_ANTENNA_RX, cfg.antenna_rx);
    }

    put_iftypes(out, a::SUPPORTED_IFTYPES, caps.interface_modes);
    bands::put_all(out, &caps.bands);
    put_commands(out);
    attr::put_u32(out, a::MAX_REMAIN_ON_CHANNEL_DURATION,
                  caps.max_remain_on_channel_duration);
    put_iftypes(out, a::SOFTWARE_IFTYPES, caps.software_iftypes);
    if caps.ap_sme { attr::put_u32(out, a::DEVICE_AP_SME, 1); }
    attr::put_u32(out, a::FEATURE_FLAGS, caps.features);
    put_mgmt_stypes(out, &caps.mgmt_stypes);
    msg::put_mac(out, a::MAC, wiphy.perm_addr);
    if !wiphy.addr_mask.is_zero() { msg::put_mac(out, a::MAC_MASK, wiphy.addr_mask); }
    if caps.max_ap_assoc_sta != 0 {
        attr::put_u32(out, a::MAX_AP_ASSOC_STA, caps.max_ap_assoc_sta as u32);
    }
    if caps.self_managed_reg { msg::put_flag(out, a::WIPHY_SELF_MANAGED_REG); }
    attr::put(out, a::EXT_FEATURES, &caps.ext_features_bytes());
}

/// A mode mask as a nest of flags, one per set bit, numbered by the interface
/// type itself. # C: O(1)
pub fn put_iftypes(out: &mut Vec<u8>, ty: u16, modes: u32) {
    let nest = attr::nest_start(out, ty);
    for i in 0..NUM_IFTYPES {
        if modes & (1u32 << i) != 0 { msg::put_flag(out, i as u16); }
    }
    attr::nest_end(out, nest);
}

/// The command list, as a nest of command numbers. The nest index is the
/// position and the payload is the command, which is why this is not a flat
/// array. # C: O(N commands)
fn put_commands(out: &mut Vec<u8>) {
    let nest = attr::nest_start(out, a::SUPPORTED_COMMANDS);
    for (i, &c) in msg::SUPPORTED_COMMANDS.iter().enumerate() {
        attr::put_u32(out, i as u16, c as u32);
    }
    attr::nest_end(out, nest);
}

/// Which management subtypes each interface type may transmit and register
/// for. A radio that advertises none of this cannot serve a frame
/// registration at all. # C: O(N iftypes)
fn put_mgmt_stypes(out: &mut Vec<u8>, stypes: &[MgmtStypes]) {
    if stypes.is_empty() { return; }
    put_stype_direction(out, a::TX_FRAME_TYPES, stypes, true);
    put_stype_direction(out, a::RX_FRAME_TYPES, stypes, false);
}

/// One direction of the subtype advertisement. # C: O(N iftypes)
fn put_stype_direction(out: &mut Vec<u8>, ty: u16, stypes: &[MgmtStypes], tx: bool) {
    let outer = attr::nest_start(out, ty);
    for entry in stypes.iter() {
        let inner = attr::nest_start(out, entry.iftype as u16);
        let mask = if tx { entry.tx } else { entry.rx };
        for i in 0..NUM_MGMT_STYPES {
            if mask & (1u16 << i) != 0 {
                attr::put_u16(out, a::FRAME_TYPE, ((i as u16) << STYPE_SHIFT) | FTYPE_MGMT);
            }
        }
        attr::nest_end(out, inner);
    }
    attr::nest_end(out, outer);
}



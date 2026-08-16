// Frame construction. Every frame this stack transmits is built here, so the
// header layout has exactly one writer and the parsers in `hdr`/`mgmt` are
// its exact inverse.

extern crate alloc;

use alloc::vec::Vec;

use super::fctl::{self, mgmt_stype};
use super::hdr::{MacAddr, ADDR_LEN};
use super::mgmt::{self, ba_params, SSC_SSN_SHIFT};

/// Append a three-address management header. `duration` is left zero: the
/// value a real radio needs depends on the rate it finally picks, which is
/// the driver's decision, not this layer's. # C: O(1)
pub fn mgmt_header(out: &mut Vec<u8>, subtype: u16, da: MacAddr, sa: MacAddr, bssid: MacAddr) {
    let fc = fctl::FTYPE_MGMT | subtype;
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&da.0);
    out.extend_from_slice(&sa.0);
    out.extend_from_slice(&bssid.0);
    // Sequence control is assigned by whoever owns the transmit counter.
    out.extend_from_slice(&0u16.to_le_bytes());
}

/// Overwrite the sequence-control field of a built frame. # C: O(1)
pub fn set_seq_ctrl(frame: &mut [u8], seq_ctrl: u16) -> bool {
    let Some(slot) = frame.get_mut(22..24) else { return false; };
    slot.copy_from_slice(&seq_ctrl.to_le_bytes());
    true
}

/// Append one information element. A body longer than an element can carry
/// is refused rather than silently truncated to its low byte, which is how a
/// length field becomes a parser desynchronisation. # C: O(len)
pub fn element(out: &mut Vec<u8>, id: u8, body: &[u8]) -> bool {
    if body.len() > super::elem::MAX_BODY_LEN { return false; }
    out.push(id);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    true
}

/// Build an authentication frame. # C: O(len)
pub fn auth(da: MacAddr, sa: MacAddr, bssid: MacAddr, alg: u16, transaction: u16,
            status: u16, extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + mgmt::AuthBody::FIXED_LEN + extra.len());
    mgmt_header(&mut out, mgmt_stype::AUTH, da, sa, bssid);
    out.extend_from_slice(&alg.to_le_bytes());
    out.extend_from_slice(&transaction.to_le_bytes());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(extra);
    out
}

/// Build a deauthenticate frame. # C: O(1)
pub fn deauth(da: MacAddr, sa: MacAddr, bssid: MacAddr, reason: u16) -> Vec<u8> {
    reason_frame(mgmt_stype::DEAUTH, da, sa, bssid, reason)
}

/// Build a disassociate frame. # C: O(1)
pub fn disassoc(da: MacAddr, sa: MacAddr, bssid: MacAddr, reason: u16) -> Vec<u8> {
    reason_frame(mgmt_stype::DISASSOC, da, sa, bssid, reason)
}

fn reason_frame(subtype: u16, da: MacAddr, sa: MacAddr, bssid: MacAddr, reason: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + mgmt::ReasonBody::FIXED_LEN);
    mgmt_header(&mut out, subtype, da, sa, bssid);
    out.extend_from_slice(&reason.to_le_bytes());
    out
}

/// Build an association request. # C: O(len)
pub fn assoc_req(bssid: MacAddr, sa: MacAddr, capability: u16, listen_interval: u16,
                 prev_bssid: Option<MacAddr>, elements: &[u8]) -> Vec<u8> {
    let reassoc = prev_bssid.is_some();
    let subtype = if reassoc { mgmt_stype::REASSOC_REQ } else { mgmt_stype::ASSOC_REQ };
    let mut out = Vec::with_capacity(24 + mgmt::AssocReqBody::REASSOC_FIXED_LEN + elements.len());
    mgmt_header(&mut out, subtype, bssid, sa, bssid);
    out.extend_from_slice(&capability.to_le_bytes());
    out.extend_from_slice(&listen_interval.to_le_bytes());
    if let Some(prev) = prev_bssid { out.extend_from_slice(&prev.0); }
    out.extend_from_slice(elements);
    out
}

/// Build an association response. # C: O(len)
pub fn assoc_resp(da: MacAddr, sa: MacAddr, bssid: MacAddr, capability: u16, status: u16,
                  aid: u16, reassoc: bool, elements: &[u8]) -> Vec<u8> {
    let subtype = if reassoc { mgmt_stype::REASSOC_RESP } else { mgmt_stype::ASSOC_RESP };
    let mut out = Vec::with_capacity(24 + mgmt::AssocRespBody::FIXED_LEN + elements.len());
    mgmt_header(&mut out, subtype, da, sa, bssid);
    out.extend_from_slice(&capability.to_le_bytes());
    out.extend_from_slice(&status.to_le_bytes());
    // The two top bits are reserved and always set on the air.
    out.extend_from_slice(&((aid & mgmt::AID_MASK) | !mgmt::AID_MASK).to_le_bytes());
    out.extend_from_slice(elements);
    out
}

/// Build a probe request. A wildcard scan sends a zero-length SSID element,
/// which is a present element with no body — not an absent element. # C: O(len)
pub fn probe_req(sa: MacAddr, bssid: MacAddr, ssid: &[u8], extra_ies: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 2 + ssid.len() + extra_ies.len());
    mgmt_header(&mut out, mgmt_stype::PROBE_REQ, MacAddr::BROADCAST, sa, bssid);
    element(&mut out, super::elem::id::SSID, ssid);
    out.extend_from_slice(extra_ies);
    out
}

/// Build a beacon. # C: O(len)
pub fn beacon(sa: MacAddr, bssid: MacAddr, timestamp: u64, beacon_int: u16, capability: u16,
              elements: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + mgmt::BeaconBody::FIXED_LEN + elements.len());
    mgmt_header(&mut out, mgmt_stype::BEACON, MacAddr::BROADCAST, sa, bssid);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&beacon_int.to_le_bytes());
    out.extend_from_slice(&capability.to_le_bytes());
    out.extend_from_slice(elements);
    out
}

/// Build a probe response. # C: O(len)
pub fn probe_resp(da: MacAddr, sa: MacAddr, bssid: MacAddr, timestamp: u64, beacon_int: u16,
                  capability: u16, elements: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + mgmt::BeaconBody::FIXED_LEN + elements.len());
    mgmt_header(&mut out, mgmt_stype::PROBE_RESP, da, sa, bssid);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&beacon_int.to_le_bytes());
    out.extend_from_slice(&capability.to_le_bytes());
    out.extend_from_slice(elements);
    out
}

/// Build an ADDBA request action frame. # C: O(1)
pub fn addba_req(da: MacAddr, sa: MacAddr, bssid: MacAddr, dialog_token: u8, params: u16,
                 timeout: u16, start_seq_num: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 9);
    mgmt_header(&mut out, mgmt_stype::ACTION, da, sa, bssid);
    out.push(mgmt::action_category::BLOCK_ACK);
    out.push(mgmt::block_ack_action::ADDBA_REQ);
    out.push(dialog_token);
    out.extend_from_slice(&params.to_le_bytes());
    out.extend_from_slice(&timeout.to_le_bytes());
    out.extend_from_slice(&(start_seq_num << SSC_SSN_SHIFT).to_le_bytes());
    out
}

/// Build an ADDBA response action frame. # C: O(1)
pub fn addba_resp(da: MacAddr, sa: MacAddr, bssid: MacAddr, dialog_token: u8, status: u16,
                  params: u16, timeout: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 9);
    mgmt_header(&mut out, mgmt_stype::ACTION, da, sa, bssid);
    out.push(mgmt::action_category::BLOCK_ACK);
    out.push(mgmt::block_ack_action::ADDBA_RESP);
    out.push(dialog_token);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&params.to_le_bytes());
    out.extend_from_slice(&timeout.to_le_bytes());
    out
}

/// Build a DELBA action frame. # C: O(1)
pub fn delba(da: MacAddr, sa: MacAddr, bssid: MacAddr, tid: u8, initiator: bool,
             reason: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 6);
    mgmt_header(&mut out, mgmt_stype::ACTION, da, sa, bssid);
    out.push(mgmt::action_category::BLOCK_ACK);
    out.push(mgmt::block_ack_action::DELBA);
    let mut params = ((tid as u16) << ba_params::DELBA_TID_SHIFT) & ba_params::DELBA_TID_MASK;
    if initiator { params |= ba_params::DELBA_INITIATOR; }
    out.extend_from_slice(&params.to_le_bytes());
    out.extend_from_slice(&reason.to_le_bytes());
    out
}

/// Append a data-frame header for a station sending toward its AP. The QoS
/// variant carries its traffic identifier in the QoS-control field, so a
/// caller that wants a specific access category must pass a TID and not rely
/// on the frame type alone. # C: O(1)
pub fn data_header_to_ds(out: &mut Vec<u8>, bssid: MacAddr, sa: MacAddr, da: MacAddr,
                         tid: Option<u8>, protected: bool) {
    let mut fc = fctl::FTYPE_DATA | fctl::FCTL_TODS;
    if tid.is_some() { fc |= fctl::data_stype::QOS; }
    if protected { fc |= fctl::FCTL_PROTECTED; }
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&bssid.0);
    out.extend_from_slice(&sa.0);
    out.extend_from_slice(&da.0);
    out.extend_from_slice(&0u16.to_le_bytes());
    if let Some(tid) = tid {
        out.extend_from_slice(&((tid as u16) & fctl::QOS_CTL_TID_MASK).to_le_bytes());
    }
}

/// Append a data-frame header for an AP sending toward a station. # C: O(1)
pub fn data_header_from_ds(out: &mut Vec<u8>, da: MacAddr, bssid: MacAddr, sa: MacAddr,
                           tid: Option<u8>, protected: bool) {
    let mut fc = fctl::FTYPE_DATA | fctl::FCTL_FROMDS;
    if tid.is_some() { fc |= fctl::data_stype::QOS; }
    if protected { fc |= fctl::FCTL_PROTECTED; }
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&da.0);
    out.extend_from_slice(&bssid.0);
    out.extend_from_slice(&sa.0);
    out.extend_from_slice(&0u16.to_le_bytes());
    if let Some(tid) = tid {
        out.extend_from_slice(&((tid as u16) & fctl::QOS_CTL_TID_MASK).to_le_bytes());
    }
}

/// The RFC 1042 SNAP header an 802.11 data frame carries before an Ethernet
/// protocol payload.
pub const RFC1042_HEADER: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
/// The bridge-tunnel header used for the two protocols RFC 1042 cannot carry.
pub const BRIDGE_TUNNEL_HEADER: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8];

/// Whether an EtherType must use the bridge-tunnel encapsulation instead of
/// RFC 1042. # C: O(1)
pub fn needs_bridge_tunnel(ethertype: u16) -> bool {
    // AppleTalk AARP and IPX are the two the standard carves out.
    ethertype == 0x80f3 || ethertype == 0x8137
}

/// Append the link-layer encapsulation for one EtherType. # C: O(1)
pub fn snap_header(out: &mut Vec<u8>, ethertype: u16) {
    if needs_bridge_tunnel(ethertype) { out.extend_from_slice(&BRIDGE_TUNNEL_HEADER); }
    else { out.extend_from_slice(&RFC1042_HEADER); }
    out.extend_from_slice(&ethertype.to_be_bytes());
}

/// Width of an Ethernet header, for conversions between the two formats.
pub const ETH_HDR_LEN: usize = ADDR_LEN * 2 + 2;

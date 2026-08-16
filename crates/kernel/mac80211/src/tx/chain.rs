// The transmit handler chain, in order: the controlled port, conversion,
// sequence numbering, the integrity code, fragmentation, encryption, rate and
// queue selection, and the driver hand-off.
//
// Fragmentation sits between the integrity code and encryption on purpose.
// The code covers the whole frame and is computed once; each fragment is then
// encrypted separately with its own packet number, because a packet number
// reused across two fragments is a reused nonce.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{build, fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::enums::IfType;

use super::{encrypt, frag, port};
use crate::flags;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::netdev::convert::{self, EthFrame};
use crate::ops::TxInfo;
use crate::uapi;

/// Transmit an Ethernet frame through an interface. # C: O(len)
pub fn xmit_eth(local: &Arc<Local>, sdata: &Arc<Sdata>, eth: &EthFrame) -> bool {
    let controlled = crate::rx::data::uses_controlled_port(sdata);
    let authorized = sdata.port_authorized();
    if !port::allowed(controlled, authorized, eth.proto) {
        sdata.with(|s| { s.stats.tx_port_blocked += 1; s.stats.tx_dropped += 1; });
        return false;
    }

    let iftype = sdata.iftype();
    let Some(bssid) = target_bssid(sdata, eth) else {
        sdata.with(|s| s.stats.tx_dropped += 1);
        return false;
    };
    // Everything below is keyed on the OVER-THE-AIR receiver, not on the
    // Ethernet destination. A station sends every frame — broadcast ones
    // included — to its access point, so the key, the sequence counter, the
    // rate and the quality-of-service agreement all belong to that peer and
    // not to whoever is behind it.
    let ra = receiver_addr(sdata, eth, bssid);
    // Quality of service is used only when the peer negotiated it: a frame
    // with a QoS control field sent to a peer that did not is discarded by
    // that peer.
    let tid = if peer_qos(sdata, ra) { Some(priority_for(eth)) } else { None };

    let Some(frame) = convert::from_8023(eth, iftype, sdata.addr, bssid, tid, false) else {
        sdata.with(|s| s.stats.tx_dropped += 1);
        return false;
    };
    let Some(header) = MacHeader::parse(&frame) else { return false; };
    let hdr_len = header.len;

    // A sleeping peer's frames are buffered rather than sent.
    if iftype.is_ap() && crate::ps::buffer_if_asleep(sdata, eth.dst, &frame, local.now_ns()) {
        return true;
    }

    let seq_ctrl_base = next_seq(sdata, ra, tid);
    tx_payload(local, sdata, &frame[..hdr_len], &frame[hdr_len..], seq_ctrl_base, ra, tid)
}

/// Build, number, protect and hand off one payload under a prepared header.
/// `ra` is the address the frame is addressed to ON THE AIR, which is what
/// selects the key and the rate. # C: O(len)
pub fn tx_payload(local: &Arc<Local>, sdata: &Arc<Sdata>, header_bytes: &[u8],
                  payload: &[u8], sn: u16, ra: MacAddr, tid: Option<u8>) -> bool {
    let key_choice = sdata.with(|s| s.keys.tx_key(ra).map(|(k, i)| (k.cipher, i, k.overhead())));
    let overhead = key_choice.as_ref().map_or(0, |(_, _, o)| *o);
    let threshold = local.with(|s| s.frag_threshold);

    // The integrity code the temporal-key cipher needs covers the whole
    // payload, so it is added before the payload is cut up.
    let mut body = payload.to_vec();
    if let Some((_, idx, _)) = key_choice {
        let Some(parsed) = MacHeader::parse(header_bytes) else { return false; };
        let ok = sdata.with(|s| {
            let pairwise = ra.is_unicast() && s.keys.has_pairwise(ra);
            let peer = if pairwise { Some(ra) } else { None };
            let Some(key) = s.keys.get_mut(idx, pairwise, peer) else { return true; };
            encrypt::add_michael_mic(key, &parsed, &mut body).is_ok()
        });
        if !ok { return false; }
    }

    let pieces = frag::split(threshold, header_bytes.len(), overhead, body.len());
    let mut all_ok = true;
    for piece in pieces.iter() {
        let mut hdr = header_bytes.to_vec();
        let mut fc = u16::from_le_bytes([hdr[0], hdr[1]]);
        if piece.more { fc |= fctl::FCTL_MOREFRAGS; } else { fc &= !fctl::FCTL_MOREFRAGS; }
        hdr[0..2].copy_from_slice(&fc.to_le_bytes());
        build::set_seq_ctrl(&mut hdr, fctl::sn_to_seq(sn, piece.number));

        let slice = &body[piece.start..piece.end];
        let frame = match protect(sdata, &hdr, slice, ra) {
            Some(f) => f,
            None => { all_ok = false; continue; }
        };
        hand_off(local, sdata, &frame, ra, tid);
    }
    all_ok
}

/// Encrypt if a key applies, otherwise pass through. # C: O(len)
fn protect(sdata: &Arc<Sdata>, header_bytes: &[u8], payload: &[u8], dst: MacAddr)
    -> Option<Vec<u8>>
{
    let sa = sdata.addr;
    let has_key = sdata.with(|s| s.keys.tx_key(dst).map(|(_, i)| i));
    let Some(idx) = has_key else {
        let mut out = Vec::with_capacity(header_bytes.len() + payload.len());
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(payload);
        return Some(out);
    };
    sdata.with(|s| {
        let pairwise = dst.is_unicast() && s.keys.has_pairwise(dst);
        let peer = if pairwise { Some(dst) } else { None };
        let key = s.keys.get_mut(idx, pairwise, peer)?;
        // The integrity code was already added to the whole payload before
        // fragmentation; this step encrypts only, and must not add it again.
        let mut hdr = header_bytes.to_vec();
        encrypt::mark_protected(&mut hdr);
        let parsed = MacHeader::parse(&hdr)?;
        let sealed = encrypt::encrypt_payload(key, idx, &parsed, sa, payload).ok()?;
        let mut out = Vec::with_capacity(hdr.len() + sealed.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&sealed);
        Some(out)
    })
}

/// Pick the queue and rate and give the frame to the driver. # C: O(len)
fn hand_off(local: &Arc<Local>, sdata: &Arc<Sdata>, frame: &[u8], dst: MacAddr,
            tid: Option<u8>) {
    let tid_val = tid.unwrap_or(0);
    let rate_idx = sdata.stas.with(dst, |sta| sta.rate.current());
    let info = TxInfo {
        flags: 0,
        queue: uapi::tid_to_ac(tid_val),
        tid: tid_val,
        rate_idx,
        max_tries: local.with(|s| s.conf.long_frame_max_tx_count).max(1),
        cookie: 0,
    };
    sdata.with(|s| { s.stats.tx_packets += 1; s.stats.tx_bytes += frame.len() as u64; });
    sdata.stas.with(dst, |sta| { sta.tx_packets += 1; sta.tx_bytes += frame.len() as u64; });
    local.ops.tx(&local.hw, Some(&sdata.vif()), &info, frame);
}

/// Transmit a management frame this layer built: number it and hand it
/// straight over. Management frames are never fragmented by this layer and
/// only the robust ones are ever protected. # C: O(len)
pub fn tx_mgmt(local: &Arc<Local>, sdata: &Arc<Sdata>, frame: &mut Vec<u8>) {
    let Some(header) = MacHeader::parse(frame) else { return; };
    let dst = header.addr1;
    let sn = next_seq(sdata, dst, None);
    build::set_seq_ctrl(frame, fctl::sn_to_seq(sn, 0));

    let out = if fctl::is_robust_mgmt(header.frame_control) && sdata.mfp() {
        protect(sdata, &frame[..header.len], &frame[header.len..], dst)
            .unwrap_or_else(|| frame.clone())
    } else { frame.clone() };

    let info = TxInfo {
        flags: flags::tx::REQ_TX_STATUS | flags::tx::CTL_PORT,
        queue: uapi::ac::VO, tid: 0, rate_idx: None,
        max_tries: local.with(|s| s.conf.long_frame_max_tx_count).max(1),
        cookie: 0,
    };
    sdata.with(|s| { s.stats.tx_packets += 1; s.stats.tx_bytes += out.len() as u64; });
    local.ops.tx(&local.hw, Some(&sdata.vif()), &info, &out);
}

/// The next sequence number for a destination and traffic identifier. A peer
/// in the table keeps its own counter; anything else uses the interface's.
/// # C: O(N stations)
fn next_seq(sdata: &Arc<Sdata>, dst: MacAddr, tid: Option<u8>) -> u16 {
    sdata.stas.with(dst, |sta| sta.next_seq(tid)).unwrap_or_else(|| sdata.next_seq())
}

/// The address a frame is addressed to on the air. # C: O(1)
fn receiver_addr(sdata: &Arc<Sdata>, eth: &EthFrame, bssid: MacAddr) -> MacAddr {
    match sdata.iftype() {
        IfType::Station | IfType::P2pClient => bssid,
        _ => eth.dst,
    }
}

/// Which network address a frame goes out under. # C: O(1)
fn target_bssid(sdata: &Arc<Sdata>, _eth: &EthFrame) -> Option<MacAddr> {
    match sdata.iftype() {
        IfType::Ap | IfType::ApVlan | IfType::P2pGo => Some(sdata.addr),
        _ => sdata.bssid(),
    }
}

/// Whether the peer negotiated quality of service. # C: O(N stations)
fn peer_qos(sdata: &Arc<Sdata>, dst: MacAddr) -> bool {
    if dst.is_multicast() { return false; }
    sdata.stas.with(dst, |sta| sta.qos).unwrap_or(false)
}

/// Traffic identifier for a frame. Without a priority from the stack above,
/// everything is best effort — which is the identifier the standard numbers
/// zero, not the lowest-priority one. # C: O(1)
fn priority_for(_eth: &EthFrame) -> u8 { uapi::ac_to_tid(uapi::ac::BE) }

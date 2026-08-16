// Data frames: reordering, conversion, and the receive side of the
// controlled port.
//
// The port rule on receive mirrors the one on transmit and exists for the
// same reason. Before the port is authorized the only frame that may cross it
// is the one that authorizes it; delivering anything else hands traffic to
// the stack from a peer whose key exchange has not finished, which is
// precisely the traffic the port exists to hold back.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};

use crate::hw::Local;
use crate::iface::Sdata;
use crate::netdev::convert::{self, EthFrame};
use crate::ops::{RxStatus, StaState};
use crate::sta_info::state as sta_state;
use crate::uapi::ETH_P_PAE;

/// The group address the port-access protocol may also be addressed to.
pub const PAE_GROUP_ADDR: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);

/// Take one complete, decrypted data frame. # C: O(len)
pub fn rx_data(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader,
               status: &RxStatus, payload: Vec<u8>) {
    let fc = header.frame_control;
    let Some(sender) = header.transmitter() else { return; };

    // Reordering: only a frame on a traffic identifier with a live session
    // goes through the buffer, and only when the radio has not already done
    // it. Everything else is in order by definition.
    let tid = header.tid();
    let use_reorder = fctl::is_data_qos(fc)
        && status.flags & crate::flags::rx::NO_REORDER == 0
        && (tid as usize) < wireless::ieee80211::fctl::NUM_BA_TIDS;
    if use_reorder {
        let sn = header.seq_num().unwrap_or(0);
        let mut whole = Vec::with_capacity(header.len + payload.len());
        whole.extend_from_slice(&header_bytes(header));
        whole.extend_from_slice(&payload);
        let released = sdata.stas.with(sender, |sta| {
            let Some(buf) = sta.tid_rx[tid as usize].as_mut() else { return None; };
            Some(match buf.receive(sn, whole, status.now_ns) {
                crate::agg::RxAgg::Dropped => Vec::new(),
                crate::agg::RxAgg::Released(v) => v,
            })
        });
        if let Some(Some(frames)) = released {
            for f in frames { deliver_released(local, sdata, status, &f); }
            return;
        }
    }
    deliver(local, sdata, header, status, &payload);
}

/// Re-parse a frame released from the reorder buffer and deliver it. The
/// buffer holds whole frames rather than payloads so that the address map and
/// the traffic identifier still travel with the payload after the delay.
/// # C: O(len)
pub fn deliver_released(local: &Arc<Local>, sdata: &Arc<Sdata>, status: &RxStatus,
                        frame: &[u8]) {
    let Some(header) = MacHeader::parse(frame) else { return; };
    if frame.len() < header.len { return; }
    deliver(local, sdata, &header, status, &frame[header.len..]);
}

/// Rebuild the header bytes of a parsed header. Only the fields the address
/// map and the traffic identifier need are reproduced; the duration is not
/// one of them and the receiver never reads it. # C: O(1)
fn header_bytes(header: &MacHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len);
    out.extend_from_slice(&header.frame_control.to_le_bytes());
    out.extend_from_slice(&header.duration_id.to_le_bytes());
    out.extend_from_slice(&header.addr1.0);
    out.extend_from_slice(&header.addr2.unwrap_or(MacAddr::ZERO).0);
    out.extend_from_slice(&header.addr3.unwrap_or(MacAddr::ZERO).0);
    out.extend_from_slice(&header.seq_ctrl.unwrap_or(0).to_le_bytes());
    if let Some(a4) = header.addr4 { out.extend_from_slice(&a4.0); }
    if let Some(q) = header.qos_ctrl { out.extend_from_slice(&q.to_le_bytes()); }
    out.resize(header.len, 0);
    out
}

fn deliver(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, _status: &RxStatus,
           payload: &[u8]) {
    let iftype = sdata.iftype();
    let frames: Vec<EthFrame> = if header.is_amsdu() {
        match convert::parse_amsdu(payload) { Some(v) => v, None => return }
    } else {
        match convert::to_8023(header, payload, iftype, sdata.addr) {
            Some(f) => alloc::vec![f],
            None => { sdata.with(|s| s.stats.rx_dropped += 1); return; }
        }
    };
    let sender = header.transmitter().unwrap_or(MacAddr::ZERO);
    for eth in frames {
        if !frame_allowed(sdata, sender, &eth) {
            sdata.with(|s| s.stats.rx_dropped += 1);
            continue;
        }
        sdata.with(|s| { s.stats.rx_packets += 1; s.stats.rx_bytes += eth.payload.len() as u64; });
        let sink = sdata.deliver.lock().clone();
        match sink {
            Some(sink) => sink.deliver_eth(&eth),
            None => { sdata.with(|s| s.stats.rx_dropped += 1); }
        }
        // An access point forwards a frame between two of its own stations
        // rather than handing it up: the destination is on this network and
        // the stack above has nothing to do with it.
        if iftype.is_ap() && eth.dst.is_unicast() && eth.dst != sdata.addr
            && sdata.stas.contains(eth.dst) {
            crate::tx::xmit_eth(local, sdata, &eth);
        }
    }
    let _ = local;
}

/// Whether a converted frame may cross into the stack. # C: O(N stations)
pub fn frame_allowed(sdata: &Arc<Sdata>, sender: MacAddr, eth: &EthFrame) -> bool {
    // The authentication protocol crosses whatever the port state is — it is
    // what opens the port — but only when it is addressed to this interface
    // or to the protocol's own group address. Accepting it for any other
    // destination would let a peer relay somebody else's exchange.
    if eth.proto == ETH_P_PAE {
        return eth.dst == sdata.addr || eth.dst == PAE_GROUP_ADDR;
    }
    if !uses_controlled_port(sdata) { return true; }
    let state = sdata.stas.state(sender);
    if state == StaState::NotExist { return true; }
    sta_state::data_allowed(state)
}

/// Whether this interface runs a controlled port at all. An open network has
/// none: every frame is allowed the moment the association completes.
/// # C: O(1)
pub fn uses_controlled_port(sdata: &Arc<Sdata>) -> bool {
    sdata.with(|s| s.keys.any() || s.bss.protected_mgmt)
}

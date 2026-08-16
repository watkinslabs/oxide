// The receive handler chain, in order.
//
// The order is the contract. Duplicate detection must run before
// decryption or a retransmission burns a replay-counter slot; decryption must
// run before defragmentation or fragments of one frame are checked under
// different keys; reordering must run after both or the buffer holds frames
// that will never be delivered. Each handler either passes the frame on,
// drops it, or consumes it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::enums::IfType;

use super::defrag::Defrag;
use super::decrypt::{decrypt, Decrypted};
use crate::flags;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::RxStatus;

/// Hand one received frame to the layer. Every interface the frame is
/// addressed to sees it; a frame addressed to none is dropped after the
/// monitor interfaces have had it. # C: O(N interfaces × len)
pub fn rx(local: &Arc<Local>, status: &RxStatus, frame: &[u8]) {
    local.set_now_ns(status.now_ns);
    let Some(header) = MacHeader::parse(frame) else { return; };
    // A frame claiming a protocol version this standard does not define is
    // dropped before any field past the frame-control word is read.
    if header.frame_control & fctl::FCTL_VERS != 0 { return; }

    let ifaces = local.ifaces();
    for sdata in ifaces.iter().filter(|s| s.is_up() && s.iftype() == IfType::Monitor) {
        deliver_monitor(sdata, frame);
    }
    if status.flags & flags::rx::FAILED_FCS_CRC != 0 { return; }

    for sdata in ifaces.iter() {
        if !sdata.is_up() || sdata.iftype() == IfType::Monitor { continue; }
        if !addressed_to(sdata, &header) { continue; }
        rx_iface(local, sdata, &header, status, frame);
    }
}

/// Whether a frame belongs to this interface: addressed to its own address,
/// or a group frame from the network it belongs to. # C: O(1)
pub fn addressed_to(sdata: &Arc<Sdata>, header: &MacHeader) -> bool {
    if header.addr1 == sdata.addr { return true; }
    if !header.addr1.is_multicast() { return false; }
    // A group frame belongs to us only when it came from our own network. A
    // client that accepted group traffic from every network in range would
    // deliver its neighbours' broadcast traffic to the stack.
    match (sdata.bssid(), header.bssid()) {
        (Some(ours), Some(theirs)) => ours == theirs,
        // Before a network is joined, only beacons and probe responses are
        // interesting, and those are handled by the scan path.
        _ => fctl::is_mgmt(header.frame_control),
    }
}

fn deliver_monitor(sdata: &Arc<Sdata>, frame: &[u8]) {
    sdata.with(|s| { s.stats.rx_packets += 1; s.stats.rx_bytes += frame.len() as u64; });
    let sink = sdata.deliver.lock().clone();
    if let Some(sink) = sink { sink.deliver_raw(frame); }
}

fn rx_iface(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, status: &RxStatus,
            frame: &[u8]) {
    let fc = header.frame_control;
    let sender = header.transmitter();
    if let Some(sender) = sender { note_sta(sdata, sender, status, frame.len()); }

    // Duplicate detection: a retransmission the peer sent because our
    // acknowledgement was lost must not be delivered twice.
    if let Some(sender) = sender {
        if !header.addr1.is_multicast() && header.seq_ctrl.is_some() {
            let tid = if fctl::is_data_qos(fc) { Some(header.tid()) } else { None };
            let retry = fc & fctl::FCTL_RETRY != 0;
            let dup = sdata.stas.with(sender, |sta|
                sta.is_duplicate(tid, header.seq_ctrl.unwrap_or(0), retry));
            if dup == Some(true) {
                sdata.with(|s| s.stats.rx_duplicate += 1);
                return;
            }
        }
    }

    let body = &frame[header.len..];
    let mfp = sdata.mfp();
    let (plain, key_idx) = if status.flags & flags::rx::DECRYPTED != 0 {
        (body.to_vec(), 0u8)
    } else {
        match sdata.with(|s| decrypt(&mut s.keys, header, body, mfp)) {
            Decrypted::Plain => (body.to_vec(), 0u8),
            Decrypted::Ok { body, key_idx } => (body, key_idx),
            Decrypted::MicFailure { key_idx } => {
                report_mic_failure(local, sdata, header, key_idx, body);
                return;
            }
            Decrypted::Drop(_) => {
                sdata.with(|s| s.stats.rx_crypto_failed += 1);
                return;
            }
        }
    };

    if fctl::is_mgmt(fc) {
        super::mgmt::rx_mgmt(local, sdata, header, status, &plain, frame);
        return;
    }
    if fctl::is_ctl(fc) {
        super::ctl::rx_ctl(local, sdata, header, &plain);
        return;
    }
    if !fctl::is_data(fc) { return; }
    if fctl::is_nodata(fc) {
        // A null frame carries no payload; its only content is the
        // power-management bit, which the power-save path reads.
        crate::ps::note_pm_bit(sdata, header);
        return;
    }

    // Defragmentation, once the fragment is in the clear.
    let Some(sender) = sender else { return; };
    let seq = header.seq_num().unwrap_or(0);
    let frag = header.frag_num().unwrap_or(0);
    let more = fc & fctl::FCTL_MOREFRAGS != 0;
    let protected = fctl::is_protected(fc);
    let now = status.now_ns;
    let assembled = sdata.with(|s|
        s.frags.accept(sender, seq, frag, more, protected, key_idx, &plain, now));
    let payload = match assembled {
        Defrag::Complete(p) => p,
        Defrag::Held => return,
        Defrag::Dropped => { sdata.with(|s| s.stats.rx_dropped += 1); return; }
    };

    super::data::rx_data(local, sdata, header, status, payload);
}

fn note_sta(sdata: &Arc<Sdata>, sender: MacAddr, status: &RxStatus, len: usize) {
    sdata.stas.with(sender, |sta| {
        sta.last_rx_ns = status.now_ns;
        sta.rx_packets += 1;
        sta.rx_bytes += len as u64;
        if status.signal != 0 { sta.signal = status.signal; }
    });
}

fn report_mic_failure(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader,
                      key_idx: u8, body: &[u8]) {
    sdata.with(|s| s.stats.rx_crypto_failed += 1);
    let Some(wiphy) = local.wiphy() else { return; };
    let addr = header.transmitter().unwrap_or(MacAddr::ZERO);
    let tsc = super::decrypt::tkip_tsc_bytes(body);
    let key_type = if header.addr1.is_multicast() { 1 } else { 0 };
    wireless::events::michael_mic_failure(&wiphy, &sdata.wdev, addr, key_type,
                                          Some(key_idx), tsc.as_ref().map(|t| &t[..]));
}

/// Frames a caller wants delivered after a reorder release, in order.
pub type Released = Vec<Vec<u8>>;

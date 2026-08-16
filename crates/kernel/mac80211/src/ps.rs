// Power save, on both sides of the link.
//
// A station announces that it is asleep with one bit in the frame-control
// word of any frame, usually a null data frame sent for exactly that purpose.
// An access point must then BUFFER everything for that station and announce
// the fact in every beacon, because the station is not listening and a frame
// sent to it is simply lost. Missing either half — the buffer or the
// announcement — produces a link that works until the station sleeps.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};

use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::TxInfo;
use crate::uapi;

/// Build a null data frame carrying the power-management bit. It is a data
/// frame with no payload: the bit is the whole message. # C: O(1)
pub fn null_frame(sdata: &Arc<Sdata>, bssid: MacAddr, powersave: bool, qos: bool) -> Vec<u8> {
    let mut fc = fctl::FTYPE_DATA | fctl::FCTL_TODS
        | if qos { fctl::data_stype::QOS_NULLFUNC } else { fctl::data_stype::NULLFUNC };
    if powersave { fc |= fctl::FCTL_PM; }
    let mut out = Vec::with_capacity(26);
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&bssid.0);
    out.extend_from_slice(&sdata.addr.0);
    out.extend_from_slice(&bssid.0);
    out.extend_from_slice(&0u16.to_le_bytes());
    if qos { out.extend_from_slice(&0u16.to_le_bytes()); }
    out
}

/// Announce this station's sleep state to its access point. # C: O(1)
pub fn send_nullfunc(local: &Arc<Local>, sdata: &Arc<Sdata>, powersave: bool) {
    let Some(bssid) = sdata.bssid() else { return; };
    let qos = sdata.stas.with(bssid, |sta| sta.qos).unwrap_or(false);
    let frame = null_frame(sdata, bssid, powersave, qos);
    let info = TxInfo { queue: uapi::ac::VO, max_tries: 1, ..Default::default() };
    local.ops.tx(&local.hw, Some(&sdata.vif()), &info, &frame);
}

/// Record the power-management bit a peer's frame carried. A peer that just
/// woke gets everything buffered for it, immediately: it is awake now and the
/// next thing it does may be to go back to sleep. # C: O(buffered)
pub fn note_pm_bit(sdata: &Arc<Sdata>, header: &MacHeader) -> bool {
    let Some(peer) = header.transmitter() else { return false; };
    let asleep = header.frame_control & fctl::FCTL_PM != 0;
    sdata.stas.with(peer, |sta| {
        let woke = sta.asleep && !asleep;
        sta.asleep = asleep;
        woke
    }).unwrap_or(false)
}

/// Take a peer's power-management bit and release its buffer if it woke.
/// # C: O(buffered)
pub fn update_ps(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader) {
    if !note_pm_bit(sdata, header) { return; }
    let Some(peer) = header.transmitter() else { return; };
    release_all(local, sdata, peer);
}

/// Hold a frame for a peer that is asleep. Reports whether it was held; a
/// caller that gets `true` must not also transmit it. # C: O(1)
pub fn buffer_if_asleep(sdata: &Arc<Sdata>, dst: MacAddr, frame: &[u8], now_ns: u64) -> bool {
    if dst.is_multicast() {
        // Group traffic waits for the delivery period after a beacon, but
        // only while at least one station is asleep to wait for.
        let any_asleep = !sdata.stas.for_each(|s| if s.asleep { Some(()) } else { None })
            .is_empty();
        if !any_asleep { return false; }
        return sdata.stas.for_each(|sta| {
            if !sta.asleep { return None; }
            sta.buffer_ps(frame.to_vec(), true, now_ns);
            Some(())
        }).first().is_some();
    }
    sdata.stas.with(dst, |sta| {
        if !sta.asleep { return false; }
        sta.buffer_ps(frame.to_vec(), false, now_ns);
        true
    }).unwrap_or(false)
}

/// Send everything held for a peer. # C: O(buffered)
pub fn release_all(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr) {
    let now = local.now_ns();
    let frames = sdata.stas.with(peer, |sta| sta.release_ps(now)).unwrap_or_default();
    let info = TxInfo { queue: uapi::ac::BE, max_tries: 1, ..Default::default() };
    for f in frames { local.ops.tx(&local.hw, Some(&sdata.vif()), &info, &f); }
}

/// A poll asks for exactly ONE buffered frame, and the frame's more-data bit
/// tells the peer whether to poll again. Sending the whole buffer on a poll
/// is what makes a polling station miss frames: it goes back to sleep after
/// the one it asked for. # C: O(1)
pub fn rx_pspoll(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader) {
    let Some(peer) = header.transmitter() else { return; };
    let Some((frame, more)) = sdata.stas.with(peer, |sta| {
        let f = sta.ps_buf.pop_front()?;
        Some((f.frame, sta.has_buffered()))
    }).flatten() else { return; };

    let mut frame = frame;
    if more && frame.len() >= 2 {
        let fc = u16::from_le_bytes([frame[0], frame[1]]) | fctl::FCTL_MOREDATA;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());
    }
    let info = TxInfo { queue: uapi::ac::BE, max_tries: 1,
                        flags: crate::flags::tx::CLEAR_PS_FILT, ..Default::default() };
    local.ops.tx(&local.hw, Some(&sdata.vif()), &info, &frame);
}

/// The network says this station has traffic waiting. A station in power save
/// must wake and ask for it; one not in power save has nothing to do, because
/// the traffic was never buffered in the first place. # C: O(1)
pub fn traffic_pending(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    if !sdata.with(|s| s.ps) { return; }
    send_nullfunc(local, sdata, false);
}

/// Enter or leave power save on a client interface. # C: O(1)
pub fn set_ps(local: &Arc<Local>, sdata: &Arc<Sdata>, enabled: bool) {
    if sdata.with(|s| core::mem::replace(&mut s.ps, enabled)) == enabled { return; }
    sdata.wdev.with(|w| w.ps = enabled);
    if sdata.is_assoc() { send_nullfunc(local, sdata, enabled); }
    crate::iface::apply_conf(local);
}

/// Release the group traffic held for the delivery period after a beacon.
/// # C: O(N stations)
pub fn release_multicast(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    let now = local.now_ns();
    let batches = sdata.stas.for_each(|sta| {
        let mut out = Vec::new();
        while let Some(front) = sta.ps_buf.front() {
            if !front.multicast { break; }
            let f = sta.ps_buf.pop_front().expect("front was present");
            if now.saturating_sub(f.at_ns) < crate::limits::PS_BUFFER_TIMEOUT_NS {
                out.push(f.frame);
            }
        }
        if out.is_empty() { None } else { Some(out) }
    });
    let info = TxInfo { queue: uapi::ac::BE, max_tries: 1, ..Default::default() };
    for batch in batches {
        for f in batch { local.ops.tx(&local.hw, Some(&sdata.vif()), &info, &f); }
    }
}

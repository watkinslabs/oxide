// Beacon monitoring and the beacon an access-point interface transmits.
//
// Missing beacons is how a station finds out its access point is gone: no
// frame announces it. The count before the link is declared lost is a
// trade — too few and a microwave oven disconnects the user, too many and a
// station sits on a dead link for a minute — and it is named in `limits`
// rather than written here.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{build, elem, hdr::MacHeader, mgmt};

use crate::hw::Local;
use crate::iface::Sdata;
use crate::limits;
use crate::ops::RxStatus;
use crate::uapi::elem_id;

/// A beacon arrived. Only a beacon from the network this interface joined
/// resets the monitor: one from a neighbour proves nothing about our own
/// link. # C: O(len)
pub fn rx_beacon(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader,
                 status: &RxStatus, body: &[u8]) {
    let Some(bssid) = header.bssid() else { return; };
    if sdata.bssid() != Some(bssid) { return; }
    let Some(parsed) = mgmt::BeaconBody::parse(body) else { return; };
    sdata.with(|s| {
        s.mlme.note_beacon(status.now_ns);
        s.tsf = parsed.timestamp;
        if parsed.beacon_int != 0 { s.bss.beacon_int = parsed.beacon_int; }
    });
    if let Some(tim) = elem::find(parsed.elements, elem_id::TIM) {
        let aid = sdata.with(|s| s.bss.aid);
        if tim_has_traffic(tim.body, aid) { crate::ps::traffic_pending(local, sdata); }
    }
    let signal = status.signal as i32;
    if let Some(wiphy) = local.wiphy() {
        wireless::events::cqm_rssi_notify(&wiphy, &sdata.wdev, signal);
    }
}

/// Whether the traffic-indication map says this station has traffic waiting.
/// The map's first byte is the count until the next delivery period, the
/// second the period, the third the control byte carrying the bitmap offset,
/// and the rest the bitmap itself — reading the bitmap without the offset
/// reports another station's traffic as ours. # C: O(1)
pub fn tim_has_traffic(tim: &[u8], aid: u16) -> bool {
    if aid == 0 || tim.len() < 4 { return false; }
    let control = tim[2];
    // The low bit is the group-traffic indication, not part of the offset.
    let offset = (control & 0xfe) as usize;
    let bitmap = &tim[3..];
    let index = (aid / 8) as usize;
    if index < offset { return false; }
    let Some(byte) = bitmap.get(index - offset) else { return false; };
    byte & (1 << (aid % 8)) != 0
}

/// Whether the map announces group traffic, which every associated station
/// must stay awake for. # C: O(1)
pub fn tim_has_multicast(tim: &[u8]) -> bool {
    tim.len() >= 3 && tim[2] & 0x01 != 0
}

/// Check the monitor and act. Returns whether the link was declared lost.
/// # C: O(1)
pub fn check_connection(local: &Arc<Local>, sdata: &Arc<Sdata>) -> bool {
    let now = local.now_ns();
    let beacon_int = sdata.with(|s| s.bss.beacon_int);
    let (lost, probe) = sdata.with(|s|
        (s.mlme.beacon_lost(beacon_int, now), s.mlme.should_probe(beacon_int, now)));
    if lost {
        if let Some(wiphy) = local.wiphy() {
            wireless::events::cqm_beacon_loss_notify(&wiphy, &sdata.wdev);
        }
        let bssid = sdata.bssid();
        if let Some(bssid) = bssid {
            super::deauth::deauth_peer(local, sdata, bssid,
                wireless::ieee80211::status::reason::DISASSOC_DUE_TO_INACTIVITY, false);
        }
        return true;
    }
    if probe { send_probe(local, sdata); }
    false
}

/// Probe the network directly, which is cheaper than giving up on it.
/// # C: O(len)
pub fn send_probe(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    let Some(bssid) = sdata.bssid() else { return; };
    let ssid = sdata.with(|s| s.mlme.ssid.clone());
    let mut frame = build::probe_req(sdata.addr, bssid, &ssid, &[]);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// Build the beacon an access-point interface transmits. # C: O(len)
pub fn build_beacon(local: &Arc<Local>, sdata: &Arc<Sdata>) -> Option<Vec<u8>> {
    let (ssid, beacon_int, dtim, tsf) = sdata.with(|s|
        (s.bss.ssid.clone(), s.bss.beacon_int, s.bss.dtim_period, s.tsf));
    let def = sdata.chandef()?;
    let band = local.hw.bands.iter().find(|b| b.band == def.chan.band)?;

    let mut elements = Vec::new();
    build::element(&mut elements, elem_id::SSID, &ssid);
    let rates = crate::rate::rates_element(&band.bitrates, BASIC_RATE_MASK);
    let (supp, ext) = crate::rate::split_rates(&rates);
    build::element(&mut elements, elem_id::SUPP_RATES, supp);
    build::element(&mut elements, elem_id::DS_PARAMS, &[def.chan.hw_value as u8]);
    build::element(&mut elements, elem_id::TIM, &tim_element(sdata, dtim));
    if !ext.is_empty() { build::element(&mut elements, elem_id::EXT_SUPP_RATES, ext); }

    let capability = mgmt::capability::ESS
        | if sdata.with(|s| s.keys.any()) { mgmt::capability::PRIVACY } else { 0 };
    let interval = if beacon_int == 0 { limits::DEFAULT_BEACON_INT_TU } else { beacon_int };
    Some(build::beacon(sdata.addr, sdata.addr, tsf, interval, capability, &elements))
}

/// The lowest four rates of a band are the ones every station must support.
const BASIC_RATE_MASK: u32 = 0b1111;

/// The traffic-indication map: which associated stations have buffered
/// traffic waiting. # C: O(N stations)
pub fn tim_element(sdata: &Arc<Sdata>, dtim_period: u8) -> Vec<u8> {
    let mut bitmap = alloc::vec![0u8; 251];
    let mut multicast = false;
    let mut highest = 0usize;
    sdata.stas.for_each(|sta| {
        if !sta.has_buffered() { return None::<()>; }
        if sta.aid == 0 { multicast = true; return None; }
        let i = (sta.aid / 8) as usize;
        if i < bitmap.len() {
            bitmap[i] |= 1 << (sta.aid % 8);
            highest = highest.max(i);
        }
        None
    });
    let mut out = Vec::with_capacity(4 + highest);
    out.push(0);
    out.push(dtim_period.max(1));
    out.push(if multicast { 0x01 } else { 0x00 });
    out.extend_from_slice(&bitmap[..=highest]);
    out
}

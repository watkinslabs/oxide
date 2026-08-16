// What a driver reports upward. Each call updates the core state and raises
// the matching notification, in that order, so a listener woken by the event
// reads state that already agrees with it.
//
// The ordering is the whole point of routing driver reports through one
// module. A driver that raised the event first and updated the cache second
// would let a supplicant read the old scan results in response to a
// scan-finished event — a race that reproduces about as often as the machine
// is busy.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ieee80211::{elem, fctl, mgmt, MacAddr, MacHeader};
use crate::nl80211::event;
use crate::scan::{Bss, BssUpdate};
use crate::sme::ConnectResult;
use crate::uapi::enums::ChanWidth;
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

/// A received beacon or probe response, as the driver saw it.
pub struct RxBeacon<'a> {
    /// Centre frequency in MHz the frame was heard on.
    pub freq: u32,
    /// Signal strength in millibel-milliwatts.
    pub signal_mbm: i32,
    /// Monotonic nanoseconds the frame arrived at.
    pub now_ns: u64,
    /// The whole frame, header included.
    pub frame: &'a [u8],
}

/// Record a beacon or probe response in the radio's scan cache.
///
/// The frame is parsed here and not by the driver: every driver would
/// otherwise need its own element walk, and one of them would get the
/// truncation rule wrong. # C: O(N entries + N elements)
pub fn inform_bss_frame(wiphy: &Arc<Wiphy>, rx: &RxBeacon<'_>) -> Option<BssUpdate> {
    let hdr = MacHeader::parse(rx.frame)?;
    let fc = hdr.frame_control;
    if !fctl::is_beacon(fc) && !fctl::is_probe_resp(fc) { return None; }
    let body = rx.frame.get(hdr.len..)?;
    let parsed = mgmt::BeaconBody::parse(body)?;
    if !elem::is_well_formed(parsed.elements) { return None; }
    let bssid = hdr.bssid()?;
    let bss = Bss {
        bssid,
        freq: rx.freq,
        freq_offset: 0,
        tsf: parsed.timestamp,
        beacon_interval: parsed.beacon_int,
        capability: parsed.capability,
        ies: parsed.elements.to_vec(),
        beacon_ies: Vec::new(),
        presp_data: false,
        signal_mbm: rx.signal_mbm,
        last_seen_ns: rx.now_ns,
        first_seen_ns: rx.now_ns,
        chan_width: ChanWidth::Width20,
        status: None,
        hold: 0,
    };
    let from_probe_resp = fctl::is_probe_resp(fc);
    Some(wiphy.with_state(|s| s.bss.insert(bss, from_probe_resp, rx.now_ns)))
}

/// A scan finished. The cache is expired against the scan's own start time
/// first when the request asked for a flush, so a caller that reads results
/// on the event sees exactly what this scan found. # C: O(N entries)
pub fn scan_done(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, aborted: bool) {
    wiphy.with_state(|s| {
        if let Some(scan) = s.scan.take() {
            if !aborted && scan.request.flushes() { s.bss.expire(scan.request.start_ns); }
        }
    });
    event::scan_done(wiphy, wdev, aborted);
}

/// A connect attempt reached its terminal outcome. # C: O(len)
pub fn connect_result(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, result: ConnectResult,
                      req_ie: Vec<u8>, resp_ie: Vec<u8>, port_authorized: bool) {
    wdev.with(|w| match &result {
        ConnectResult::Success { bssid, aid } =>
            w.conn.associated(*bssid, *aid, req_ie.clone(), resp_ie.clone(), port_authorized),
        _ => w.conn.disconnected(),
    });
    if let ConnectResult::Success { bssid, .. } = &result {
        let freq = wdev.chandef().map_or(0, |d| d.chan.center_freq);
        wiphy.with_state(|s| s.bss.set_status(*bssid, freq,
            Some(crate::uapi::nested::bss_status::ASSOCIATED)));
    }
    event::connect_result(wiphy, wdev, &result, &req_ie, &resp_ie);
}

/// The controlled port opened. # C: O(1)
pub fn port_authorized(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, bssid: MacAddr) {
    wdev.with(|w| w.conn.port_authorized = true);
    event::port_authorized(wiphy, wdev, bssid);
}

/// A connection ended. Keys for the peer go with it: a key left installed for
/// a peer this interface is no longer associated to would encrypt the first
/// frames of the NEXT association with the old key. # C: O(N peers)
pub fn disconnected(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, reason: u16, by_ap: bool,
                    ie: &[u8]) {
    let previous = wdev.with(|w| {
        let previous = w.conn.current_bssid;
        w.conn.disconnected();
        if let Some(peer) = previous { w.keys.forget_peer(peer); }
        previous
    });
    if let Some(bssid) = previous {
        let freq = wdev.chandef().map_or(0, |d| d.chan.center_freq);
        wiphy.with_state(|s| s.bss.set_status(bssid, freq, None));
    }
    event::disconnected(wiphy, wdev, reason, by_ap, ie);
}

/// An authentication exchange completed, reported as the frame. # C: O(len)
pub fn rx_auth(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, frame: &[u8]) {
    if let Some(hdr) = MacHeader::parse(frame) {
        if let Some(peer) = hdr.transmitter() {
            wdev.with(|w| w.conn.note_authenticated(peer));
        }
    }
    event::mlme_frame(wiphy, wdev, crate::uapi::cmd::AUTHENTICATE, frame);
}

/// An association exchange completed, reported as the frame. # C: O(len)
pub fn rx_assoc(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, frame: &[u8]) {
    event::mlme_frame(wiphy, wdev, crate::uapi::cmd::ASSOCIATE, frame);
}

/// A deauthenticate arrived. # C: O(len)
pub fn rx_deauth(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, frame: &[u8]) {
    event::mlme_frame(wiphy, wdev, crate::uapi::cmd::DEAUTHENTICATE, frame);
}

/// A disassociate arrived. # C: O(len)
pub fn rx_disassoc(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, frame: &[u8]) {
    event::mlme_frame(wiphy, wdev, crate::uapi::cmd::DISASSOCIATE, frame);
}

/// An UNPROTECTED deauthenticate or disassociate arrived on a link with
/// management frame protection in force. It is reported under its own command
/// and MUST NOT tear the link down: acting on it is exactly the attack
/// protection exists to stop. # C: O(len)
pub fn rx_unprot_mlme(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, frame: &[u8]) {
    let Some(hdr) = MacHeader::parse(frame) else { return; };
    let cmd = match fctl::stype(hdr.frame_control) {
        fctl::mgmt_stype::DEAUTH => crate::uapi::cmd::UNPROT_DEAUTHENTICATE,
        fctl::mgmt_stype::DISASSOC => crate::uapi::cmd::UNPROT_DISASSOCIATE,
        _ => return,
    };
    event::mlme_frame(wiphy, wdev, cmd, frame);
}

/// A management frame arrived that userspace may have registered for.
/// Reports whether anyone took it. # C: O(N regs)
pub fn rx_mgmt(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, freq: u32, signal_dbm: i32,
               frame: &[u8]) -> bool {
    event::rx_mgmt(wiphy, wdev, freq, signal_dbm, frame)
}

/// The status of a transmitted management frame. # C: O(len)
pub fn mgmt_tx_status(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, cookie: u64, frame: &[u8],
                      acked: bool) {
    event::mgmt_tx_status(wiphy, wdev, cookie, frame, acked);
}

/// A station associated to an access-point interface. # C: O(len)
pub fn new_station(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, mac: MacAddr, assoc_ie: &[u8]) {
    wiphy.bump_generation();
    event::new_station(wiphy, wdev, mac, assoc_ie);
}

/// A station left. # C: O(N peers)
pub fn del_station(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, mac: MacAddr) {
    wdev.with(|w| w.keys.forget_peer(mac));
    wiphy.bump_generation();
    event::del_station(wiphy, wdev, mac);
}

/// A frame failed its integrity check. # C: O(1)
pub fn michael_mic_failure(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, addr: MacAddr,
                           key_type: u32, key_id: Option<u8>, tsc: Option<&[u8]>) {
    event::michael_mic_failure(wiphy, wdev, addr, key_type, key_id, tsc);
}

/// A signal measurement crossed a configured threshold. The event is raised
/// only on a CROSSING, and the direction is remembered, so a signal hovering
/// at the threshold does not produce one event per beacon. # C: O(1)
pub fn cqm_rssi_notify(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, signal_dbm: i32) {
    use crate::uapi::nested::cqm;
    let Some(event_kind) = wdev.with(|w| {
        if w.cqm.rssi_thold == 0 { return None; }
        let hyst = w.cqm.rssi_hyst as i32;
        let low = signal_dbm < w.cqm.rssi_thold - hyst;
        let high = signal_dbm > w.cqm.rssi_thold + hyst;
        let kind = if low { cqm::RSSI_EVENT_LOW }
                   else if high { cqm::RSSI_EVENT_HIGH }
                   else { return None; };
        if w.cqm.last_rssi_event == Some(kind) { return None; }
        w.cqm.last_rssi_event = Some(kind);
        Some(kind)
    }) else { return; };
    event::cqm_notify(wiphy, wdev, cqm::RSSI_THRESHOLD_EVENT, event_kind);
}

/// Beacons stopped arriving. # C: O(1)
pub fn cqm_beacon_loss_notify(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) {
    use crate::uapi::nested::cqm;
    event::cqm_notify(wiphy, wdev, cqm::BEACON_LOSS_EVENT, 1);
}

/// The interface moved to a different channel. # C: O(1)
pub fn ch_switch_notify(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, def: crate::chan::ChanDef) {
    wdev.with(|w| w.chandef = Some(def));
    event::ch_switch_notify(wiphy, wdev, &def);
}

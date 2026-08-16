// Executing what the state machine decided.
//
// The state machine itself touches no radio and no interface: it takes an
// event and returns an action. This is the only place that turns an action
// into a frame, a station-state change and an upward report — so the ordering
// of those three is written once. State first, then the report, so anything
// woken by the report reads state that already agrees with it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::{build, mgmt, MacAddr};
use wireless::sme::ConnectResult;

use super::state::{MlmeAction, MlmeState};
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::StaState;

/// Carry out one action. Returns whether the attempt is over. # C: O(len)
pub fn run(local: &Arc<Local>, sdata: &Arc<Sdata>, action: MlmeAction) -> bool {
    match action {
        MlmeAction::None => false,
        MlmeAction::SendAuth => { send_auth(local, sdata); false }
        MlmeAction::SendAssoc => { send_assoc(local, sdata); false }
        MlmeAction::SendDeauth { reason } => {
            send_deauth(local, sdata, reason);
            report(local, sdata, ConnectResult::TimedOut {
                reason: wireless::uapi::enums::timeout_reason::UNSPECIFIED });
            true
        }
        MlmeAction::Success { bssid, aid } => { on_success(local, sdata, bssid, aid); true }
        MlmeAction::Refused { status } => {
            let bssid = sdata.with(|s| s.mlme.bssid);
            teardown(local, sdata);
            report(local, sdata, ConnectResult::Refused { bssid, status });
            true
        }
        MlmeAction::TimedOut { reason } => {
            teardown(local, sdata);
            report(local, sdata, ConnectResult::TimedOut { reason });
            true
        }
    }
}

/// Send the authenticate the state machine asked for. # C: O(len)
pub fn send_auth(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    let (bssid, alg) = sdata.with(|s| (s.mlme.bssid, s.mlme.auth_alg));
    let Some(bssid) = bssid else { return; };
    let mut frame = build::auth(bssid, sdata.addr, bssid, alg, 1,
                                wireless::ieee80211::status::status::SUCCESS, &[]);
    // The step is recorded BEFORE the frame goes out. A response can arrive
    // before the transmit call returns — on another processor, or on a
    // medium that delivers synchronously — and a machine still in the
    // previous step discards it as belonging to nothing.
    let now = local.now_ns();
    sdata.with(|s| s.mlme.auth_sent(now));
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// Send the associate the state machine asked for. # C: O(len)
pub fn send_assoc(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    let (bssid, ssid, ie) = sdata.with(|s|
        (s.mlme.bssid, s.mlme.ssid.clone(), s.mlme.assoc_ie.clone()));
    let Some(bssid) = bssid else { return; };
    let mut elements = Vec::new();
    build::element(&mut elements, crate::uapi::elem_id::SSID, &ssid);
    let rates = band_rates(local, sdata);
    let (supp, ext) = crate::rate::split_rates(&rates);
    build::element(&mut elements, crate::uapi::elem_id::SUPP_RATES, supp);
    if !ext.is_empty() {
        build::element(&mut elements, crate::uapi::elem_id::EXT_SUPP_RATES, ext);
    }
    elements.extend_from_slice(&ie);

    let capability = mgmt::capability::ESS | mgmt::capability::SHORT_PREAMBLE;
    let mut frame = build::assoc_req(bssid, sdata.addr, capability,
                                     crate::limits::DEFAULT_LISTEN_INTERVAL, None,
                                     &elements);
    let now = local.now_ns();
    sdata.with(|s| s.mlme.assoc_sent(now));
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// Send a deauthenticate to the network being left. # C: O(len)
pub fn send_deauth(local: &Arc<Local>, sdata: &Arc<Sdata>, reason: u16) {
    let bssid = sdata.with(|s| s.mlme.bssid).or_else(|| sdata.bssid());
    let Some(bssid) = bssid else { return; };
    let mut frame = build::deauth(bssid, sdata.addr, bssid, reason);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// The rates this radio offers on the interface's current band, as element
/// bytes. # C: O(N rates)
pub fn band_rates(local: &Arc<Local>, sdata: &Arc<Sdata>) -> Vec<u8> {
    let Some(def) = sdata.chandef() else { return Vec::new(); };
    let Some(band) = local.hw.bands.iter().find(|b| b.band == def.chan.band) else {
        return Vec::new();
    };
    // Every rate is offered; which of them are mandatory is the network's
    // decision, not a joining station's.
    crate::rate::rates_element(&band.bitrates, 0)
}

fn on_success(local: &Arc<Local>, sdata: &Arc<Sdata>, bssid: MacAddr, aid: u16) {
    let now = local.now_ns();
    // The peer must exist and be associated before the interface is marked
    // associated: a frame arriving in between would otherwise find no station.
    if !sdata.stas.contains(bssid) {
        let mut sta = crate::sta_info::Sta::new(bssid, now);
        sta.aid = aid;
        sta.assoc_at_ns = now;
        sdata.stas.insert(sta);
    }
    let target = if sdata.with(|s| s.keys.any()) { StaState::Assoc } else { StaState::Authorized };
    sdata.stas.set_state(bssid, target, |from, to| {
        let _ = local.ops.sta_state(&local.hw, &sdata.vif(), bssid, from, to);
        true
    });
    let authorized = target == StaState::Authorized;
    crate::iface::update_bss(local, sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(bssid);
        bss.aid = aid;
        bss.port_authorized = authorized;
    });
    report(local, sdata, ConnectResult::Success { bssid, aid });
}

/// Undo everything an attempt set up. # C: O(N stations)
pub fn teardown(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    let bssid = sdata.with(|s| s.mlme.bssid).or_else(|| sdata.bssid());
    if let Some(bssid) = bssid {
        sdata.stas.set_state(bssid, StaState::NotExist, |from, to| {
            let _ = local.ops.sta_state(&local.hw, &sdata.vif(), bssid, from, to);
            true
        });
        sdata.stas.remove(bssid);
        sdata.with(|s| s.keys.forget_peer(bssid));
    }
    crate::iface::update_bss(local, sdata, |bss| {
        bss.assoc = false;
        bss.bssid = None;
        bss.aid = 0;
        bss.port_authorized = false;
    });
}

fn report(local: &Arc<Local>, sdata: &Arc<Sdata>, result: ConnectResult) {
    let Some(wiphy) = local.wiphy() else { return; };
    let resp_ie = sdata.with(|s| s.mlme.resp_ie.clone());
    let authorized = sdata.port_authorized();
    wireless::events::connect_result(&wiphy, &sdata.wdev, result, Vec::new(), resp_ie,
                                     authorized);
}

/// Feed an event through the state machine and carry out what it decided.
/// # C: O(len)
pub fn event(local: &Arc<Local>, sdata: &Arc<Sdata>, ev: super::state::MlmeEvent) -> bool {
    let now = local.now_ns();
    let action = sdata.with(|s| s.mlme.on_event(ev, now));
    run(local, sdata, action)
}

/// Begin an attempt. # C: O(len)
pub fn start(local: &Arc<Local>, sdata: &Arc<Sdata>, bssid: MacAddr, ssid: Vec<u8>,
             auth_alg: u16, assoc_ie: Vec<u8>, mfp: bool) {
    let now = local.now_ns();
    let action = sdata.with(|s| {
        let a = s.mlme.start(bssid, ssid, auth_alg, now);
        s.mlme.assoc_ie = assoc_ie;
        s.mlme.mfp = mfp;
        a
    });
    if !sdata.stas.contains(bssid) {
        sdata.stas.insert(crate::sta_info::Sta::new(bssid, now));
    }
    run(local, sdata, action);
}

/// The state machine as a snapshot, for anything that only needs to read it.
/// # C: O(len)
pub fn snapshot(sdata: &Arc<Sdata>) -> MlmeState { sdata.with(|s| s.mlme.clone()) }

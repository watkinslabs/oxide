// Deauthenticate and disassociate, in both directions.
//
// Whether an incoming frame may be acted on at all was already decided by the
// receive dispatch — an unprotected one on a protected link never reaches
// here. What is decided here is what acting on it means, and the difference
// between the two frames: a disassociate ends the association and leaves the
// authentication standing, a deauthenticate ends both.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::{build, hdr::MacHeader, mgmt::ReasonBody, MacAddr};

use super::run;
use super::state::MlmeEvent;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::StaState;

/// Handle an incoming deauthenticate or disassociate. # C: O(N stations)
pub fn rx_deauth(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8],
                 raw: &[u8], full: bool) {
    let Some(peer) = header.transmitter() else { return; };
    let Some(parsed) = ReasonBody::parse(body) else { return; };
    let reason = parsed.reason;

    if let Some(wiphy) = local.wiphy() {
        if full { wireless::events::rx_deauth(&wiphy, &sdata.wdev, raw); }
        else { wireless::events::rx_disassoc(&wiphy, &sdata.wdev, raw); }
    }

    if sdata.iftype().is_ap() {
        // A station leaving takes its own state with it and nothing else.
        let target = if full { StaState::NotExist } else { StaState::Auth };
        sdata.stas.set_state(peer, target, |from, to| {
            let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
            true
        });
        if full { sdata.stas.remove(peer); }
        sdata.with(|s| s.keys.forget_peer(peer));
        if let Some(wiphy) = local.wiphy() {
            wireless::events::del_station(&wiphy, &sdata.wdev, peer);
        }
        return;
    }

    if sdata.with(|s| s.mlme.bssid) != Some(peer) && sdata.bssid() != Some(peer) { return; }
    run::event(local, sdata, MlmeEvent::Deauth { reason });
    if let Some(wiphy) = local.wiphy() {
        wireless::events::disconnected(&wiphy, &sdata.wdev, reason, true, &[]);
    }
    run::teardown(local, sdata);
}

/// Send a deauthenticate to a peer and drop it locally. # C: O(len)
pub fn deauth_peer(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, reason: u16,
                   local_only: bool) {
    if !local_only {
        let bssid = if sdata.iftype().is_ap() { sdata.addr } else { peer };
        let mut frame = build::deauth(peer, sdata.addr, bssid, reason);
        crate::tx::tx_mgmt(local, sdata, &mut frame);
    }
    sdata.stas.set_state(peer, StaState::NotExist, |from, to| {
        let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
        true
    });
    sdata.stas.remove(peer);
    sdata.with(|s| s.keys.forget_peer(peer));
    if sdata.iftype().is_ap() {
        if let Some(wiphy) = local.wiphy() {
            wireless::events::del_station(&wiphy, &sdata.wdev, peer);
        }
        return;
    }
    run::teardown(local, sdata);
    if let Some(wiphy) = local.wiphy() {
        wireless::events::disconnected(&wiphy, &sdata.wdev, reason, false, &[]);
    }
}

/// Send a disassociate, which leaves the authentication standing. # C: O(len)
pub fn disassoc_peer(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, reason: u16,
                     local_only: bool) {
    if !local_only {
        let bssid = if sdata.iftype().is_ap() { sdata.addr } else { peer };
        let mut frame = build::disassoc(peer, sdata.addr, bssid, reason);
        crate::tx::tx_mgmt(local, sdata, &mut frame);
    }
    sdata.stas.set_state(peer, StaState::Auth, |from, to| {
        let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
        true
    });
    if !sdata.iftype().is_ap() { run::teardown(local, sdata); }
}

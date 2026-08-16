// The authentication exchange, client side.
//
// A response is only acted on when it comes from the peer the attempt names.
// A response from anywhere else is a frame an attacker can trivially inject,
// and acting on it either aborts a live attempt or advances one to a peer
// that never answered.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::{hdr::MacHeader, mgmt::AuthBody};

use super::run;
use super::state::MlmeEvent;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::StaState;

/// Handle an authentication frame on a client interface. # C: O(len)
pub fn rx_auth(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8],
               raw: &[u8]) {
    if sdata.iftype().is_ap() { super::ap::rx_auth_req(local, sdata, header, body); return; }
    let Some(peer) = header.transmitter() else { return; };
    let Some(expect) = sdata.with(|s| s.mlme.bssid) else { return; };
    if peer != expect { return; }
    let Some(parsed) = AuthBody::parse(body) else { return; };
    // Only the response half of the exchange concerns a client. The request
    // half arriving here is another station trying to authenticate with us,
    // which a client interface has no business answering.
    if parsed.transaction < 2 { return; }

    if parsed.status == wireless::ieee80211::status::status::SUCCESS {
        sdata.stas.set_state(peer, StaState::Auth, |from, to| {
            let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
            true
        });
        if let Some(wiphy) = local.wiphy() {
            wireless::events::rx_auth(&wiphy, &sdata.wdev, raw);
        }
    }
    run::event(local, sdata, MlmeEvent::AuthResp(parsed.status));
}

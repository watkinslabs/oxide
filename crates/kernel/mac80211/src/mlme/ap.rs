// The access-point side of the management exchange.
//
// A note on where this belongs. On a system with a userspace access-point
// daemon, the daemon runs this exchange and the kernel only carries the
// frames. A radio that advertises that its own firmware runs the exchange
// takes it instead, and this layer is that firmware for the radios it drives:
// it answers probes, authenticates and associates stations. An interface
// whose radio does NOT advertise it leaves every frame to whoever registered
// for it, which is how a userspace daemon still gets to run.
//
// The admission order is the part with a contract. A station must be
// authenticated before it may associate; an association request from one that
// is not is refused with the code that says so, because a supplicant branches
// on it and restarts the exchange from the beginning.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use wireless::ieee80211::status::{reason, status};
use wireless::ieee80211::{build, elem, hdr::MacHeader, mgmt};

use crate::flags;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::StaState;
use crate::uapi::elem_id;

/// Whether this interface runs the exchange itself. # C: O(1)
pub fn runs_sme(local: &Arc<Local>, sdata: &Arc<Sdata>) -> bool {
    sdata.iftype().is_ap() && local.hw.has(flags::hw::AP_SME)
}

/// Answer an authentication request. # C: O(len)
pub fn rx_auth_req(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8]) {
    if !runs_sme(local, sdata) { return; }
    let Some(peer) = header.transmitter() else { return; };
    let Some(parsed) = mgmt::AuthBody::parse(body) else { return; };
    if parsed.transaction != 1 { return; }
    // Only the open algorithm is answered here. Anything else — shared key,
    // the password-authenticated exchange — is a multi-frame protocol whose
    // state belongs to whoever implements it, and answering its first frame
    // with a success would strand the peer.
    let code = if parsed.alg == mgmt::auth_alg::OPEN { status::SUCCESS }
               else { status::NOT_SUPPORTED_AUTH_ALG };

    if code == status::SUCCESS {
        let now = local.now_ns();
        if !sdata.stas.contains(peer) {
            sdata.stas.insert(crate::sta_info::Sta::new(peer, now));
        }
        sdata.stas.set_state(peer, StaState::Auth, |from, to| {
            let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
            true
        });
    }
    let mut frame = build::auth(peer, sdata.addr, sdata.addr, parsed.alg, 2, code, &[]);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// Answer an association request. # C: O(len + N stations)
pub fn rx_assoc_req(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8],
                    reassoc: bool) {
    if !runs_sme(local, sdata) { return; }
    let Some(peer) = header.transmitter() else { return; };
    let Some(parsed) = mgmt::AssocReqBody::parse(body, reassoc) else { return; };
    if !elem::is_well_formed(parsed.elements) { return; }

    let state = sdata.stas.state(peer);
    if state < StaState::Auth {
        // The peer skipped the authentication exchange. Telling it so is what
        // makes it start again rather than retry the association forever.
        let mut frame = build::deauth(peer, sdata.addr, sdata.addr,
                                      reason::STA_REQ_ASSOC_WITHOUT_AUTH);
        crate::tx::tx_mgmt(local, sdata, &mut frame);
        return;
    }

    let ssid = elem::find(parsed.elements, elem_id::SSID).map(|e| e.body).unwrap_or(&[]);
    let our_ssid = sdata.with(|s| s.bss.ssid.clone());
    if !ssid.is_empty() && !our_ssid.is_empty() && ssid != our_ssid.as_slice() {
        send_refusal(local, sdata, peer, reassoc, status::ASSOC_DENIED_UNSPEC);
        return;
    }

    let supp = elem::find(parsed.elements, elem_id::SUPP_RATES).map(|e| e.body).unwrap_or(&[]);
    let ext = elem::find(parsed.elements, elem_id::EXT_SUPP_RATES)
        .map(|e| e.body).unwrap_or(&[]);
    let peer_rates = crate::rate::rates_from_elements(supp, ext);
    let band_rates = band_rates(local, sdata);
    let usable = crate::rate::intersect(&band_rates, &peer_rates);
    if usable.is_empty() && !band_rates.is_empty() {
        send_refusal(local, sdata, peer, reassoc, status::ASSOC_DENIED_RATES);
        return;
    }

    let Some(aid) = sdata.stas.next_aid() else {
        send_refusal(local, sdata, peer, reassoc, status::AP_UNABLE_TO_HANDLE_NEW_STA);
        return;
    };
    let now = local.now_ns();
    let qos = parsed.capability & mgmt::capability::QOS != 0;
    sdata.stas.with(peer, |sta| {
        sta.aid = aid;
        sta.assoc_at_ns = now;
        sta.listen_interval = parsed.listen_interval;
        sta.qos = qos;
        sta.supported_rates = peer_rates.clone();
        sta.assoc_ie = parsed.elements.to_vec();
        sta.rate.start(&usable);
    });
    // The port opens immediately on an open network and waits for the key
    // exchange on a protected one.
    let target = if sdata.with(|s| s.keys.any()) { StaState::Assoc } else { StaState::Authorized };
    sdata.stas.set_state(peer, target, |from, to| {
        let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
        true
    });

    let mut elements = Vec::new();
    let rates = crate::rate::rates_element(&band_rates, 0);
    let (s, e) = crate::rate::split_rates(&rates);
    build::element(&mut elements, elem_id::SUPP_RATES, s);
    if !e.is_empty() { build::element(&mut elements, elem_id::EXT_SUPP_RATES, e); }
    elements.extend_from_slice(&sdata.with(|st| st.assocresp_ies.clone()));

    let capability = capability_of(sdata);
    let mut frame = build::assoc_resp(peer, sdata.addr, sdata.addr, capability,
                                      status::SUCCESS, aid, reassoc, &elements);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
    if let Some(wiphy) = local.wiphy() {
        wireless::events::new_station(&wiphy, &sdata.wdev, peer, parsed.elements);
    }
}

/// Answer a probe request, if it asks for a network this interface serves. A
/// probe naming a different network is not ours to answer. # C: O(len)
pub fn rx_probe_req(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8]) {
    if !runs_sme(local, sdata) { return; }
    if !sdata.with(|s| s.bss.enable_beacon) { return; }
    let Some(peer) = header.transmitter() else { return; };
    let asked = elem::find(body, elem_id::SSID).map(|e| e.body).unwrap_or(&[]);
    let ours = sdata.with(|s| s.bss.ssid.clone());
    if !asked.is_empty() && asked != ours.as_slice() { return; }

    let Some(beacon) = super::beacon::build_beacon(local, sdata) else { return; };
    let Some(bhdr) = MacHeader::parse(&beacon) else { return; };
    let Some(parsed) = mgmt::BeaconBody::parse(&beacon[bhdr.len..]) else { return; };
    let mut extra = parsed.elements.to_vec();
    extra.extend_from_slice(&sdata.with(|s| s.proberesp_ies.clone()));
    let mut frame = build::probe_resp(peer, sdata.addr, sdata.addr, parsed.timestamp,
                                      parsed.beacon_int, parsed.capability, &extra);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

fn send_refusal(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: wireless::ieee80211::MacAddr,
                reassoc: bool, code: u16) {
    let capability = capability_of(sdata);
    let mut frame = build::assoc_resp(peer, sdata.addr, sdata.addr, capability, code, 0,
                                      reassoc, &[]);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

fn capability_of(sdata: &Arc<Sdata>) -> u16 {
    let mut cap = mgmt::capability::ESS;
    if sdata.with(|s| s.keys.any()) { cap |= mgmt::capability::PRIVACY; }
    cap
}

fn band_rates(local: &Arc<Local>, sdata: &Arc<Sdata>) -> Vec<wireless::wiphy::Bitrate> {
    let Some(def) = sdata.chandef() else { return Vec::new(); };
    local.hw.bands.iter().find(|b| b.band == def.chan.band)
        .map(|b| b.bitrates.clone()).unwrap_or_default()
}

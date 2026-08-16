// Action frames. Only the block-ack category is handled here; the rest are
// offered to whoever registered for them.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::hdr::MacHeader;
use wireless::ieee80211::mgmt::{action_category, block_ack_action, parse_addba_req,
                                parse_addba_resp, parse_delba};
use wireless::ieee80211::{build, MacAddr};

use crate::agg::action as agg_action;
use crate::agg::ReorderBuf;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::AmpduAction;

/// Dispatch an action frame. # C: O(len)
pub fn rx_action(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8]) {
    if body.len() < 2 { return; }
    if body[0] != action_category::BLOCK_ACK { return; }
    let Some(peer) = header.transmitter() else { return; };
    match body[1] {
        block_ack_action::ADDBA_REQ => rx_addba_req(local, sdata, peer, &body[2..]),
        block_ack_action::ADDBA_RESP => rx_addba_resp(local, sdata, peer, &body[2..]),
        block_ack_action::DELBA => rx_delba(local, sdata, peer, &body[2..]),
        _ => {}
    }
}

fn rx_addba_req(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, body: &[u8]) {
    let Some(req) = parse_addba_req(body) else { return; };
    let d = agg_action::on_addba_req(&req, local.hw.max_rx_aggregation_subframes);
    if d.accepted() {
        let now = local.now_ns();
        let mut buf = ReorderBuf::new(d.ssn, d.buf_size, now);
        buf.dialog_token = d.dialog_token;
        buf.timeout_tu = d.timeout;
        let installed = sdata.stas.with(peer, |sta| {
            sta.tid_rx[d.tid as usize] = Some(buf);
        }).is_some();
        if !installed { return; }
        let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
            AmpduAction::RxStart { tid: d.tid, ssn: d.ssn, buf_size: d.buf_size });
    }
    let mut frame = build::addba_resp(peer, sdata.addr, bssid_for(sdata), d.dialog_token,
                                      d.status, d.resp_params(), d.timeout);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

fn rx_addba_resp(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, body: &[u8]) {
    let Some(resp) = parse_addba_resp(body) else { return; };
    let outcome = agg_action::on_addba_resp(&resp);
    if (outcome.tid as usize) >= wireless::ieee80211::fctl::NUM_BA_TIDS { return; }
    let applied = sdata.stas.with(peer, |sta| {
        sta.tid_tx[outcome.tid as usize].response(outcome.dialog_token, outcome.accepted,
                                                  outcome.buf_size)
    });
    if applied != Some(true) { return; }
    if outcome.accepted {
        let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
            AmpduAction::TxOperational { tid: outcome.tid, buf_size: outcome.buf_size });
    } else {
        let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
            AmpduAction::TxFlush { tid: outcome.tid });
    }
}

fn rx_delba(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, body: &[u8]) {
    let Some(delba) = parse_delba(body) else { return; };
    let d = agg_action::on_delba(&delba);
    if (d.tid as usize) >= wireless::ieee80211::fctl::NUM_BA_TIDS { return; }
    // The sender says which half it is tearing down. A sender that originated
    // the session is tearing down OUR receiving half, and the other way round.
    if d.initiator {
        let released = sdata.stas.with(peer, |sta| {
            sta.tid_rx[d.tid as usize].take().map(|mut b| b.flush()).unwrap_or_default()
        }).unwrap_or_default();
        let status = crate::ops::RxStatus { now_ns: local.now_ns(), ..Default::default() };
        for f in released { crate::rx::data::deliver_released(local, sdata, &status, &f); }
        let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
            AmpduAction::RxStop { tid: d.tid });
    } else {
        sdata.stas.with(peer, |sta| sta.tid_tx[d.tid as usize].stopped());
        let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
            AmpduAction::TxStop { tid: d.tid });
    }
}

/// Begin an outgoing aggregation session. # C: O(len)
pub fn start_tx_agg(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, tid: u8) {
    if (tid as usize) >= wireless::ieee80211::fctl::NUM_BA_TIDS { return; }
    let now = local.now_ns();
    let Some((token, ssn)) = sdata.stas.with(peer, |sta| {
        let token = sta.tid_tx[tid as usize].dialog_token.wrapping_add(1);
        let ssn = sta.seq[crate::sta_info::Sta::slot(Some(tid))];
        sta.tid_tx[tid as usize].request_sent(token, now);
        (token, ssn)
    }) else { return; };
    let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
        AmpduAction::TxStart { tid, ssn });
    let params = agg_action::req_params(tid, crate::limits::DEFAULT_AGG_BUF_SIZE, false);
    let mut frame = build::addba_req(peer, sdata.addr, bssid_for(sdata), token, params,
                                     0, ssn);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
}

/// Tear down a session this end originated. # C: O(len)
pub fn stop_tx_agg(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr, tid: u8,
                   reason: u16) {
    if (tid as usize) >= wireless::ieee80211::fctl::NUM_BA_TIDS { return; }
    sdata.stas.with(peer, |sta| sta.tid_tx[tid as usize].stop());
    let mut frame = build::delba(peer, sdata.addr, bssid_for(sdata), tid, true, reason);
    crate::tx::tx_mgmt(local, sdata, &mut frame);
    sdata.stas.with(peer, |sta| sta.tid_tx[tid as usize].stopped());
    let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
        AmpduAction::TxStop { tid });
}

fn bssid_for(sdata: &Arc<Sdata>) -> MacAddr {
    if sdata.iftype().is_ap() { sdata.addr } else { sdata.bssid().unwrap_or(sdata.addr) }
}

// The periodic work: deadlines that have passed, buffers that waited too
// long, sessions that went idle, and peers that stopped talking.
//
// It is one function rather than a timer per thing on purpose. Every deadline
// here is expressed against a monotonic time that is passed in, so the whole
// set can be driven forward deterministically without a clock — which is the
// only way any of these expiries can be tested at all.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::fctl::NUM_BA_TIDS;

use super::run;
use super::state::MlmeEvent;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::RxStatus;

/// Run every expiry for one radio at `now_ns`. # C: O(N interfaces × N stations)
pub fn tick(local: &Arc<Local>, now_ns: u64) {
    local.set_now_ns(now_ns);
    for sdata in local.ifaces() {
        if !sdata.is_up() { continue; }
        tick_iface(local, &sdata, now_ns);
    }
    crate::scan::tick(local, now_ns);
}

fn tick_iface(local: &Arc<Local>, sdata: &Arc<Sdata>, now_ns: u64) {
    // An outstanding management frame whose deadline passed.
    let expired = sdata.with(|s| {
        if !s.mlme.expired(now_ns) { return None; }
        Some(s.mlme.step)
    });
    if let Some(step) = expired {
        use super::state::MlmeStep;
        let ev = match step {
            MlmeStep::Authenticating => MlmeEvent::AuthTimeout,
            MlmeStep::Associating => MlmeEvent::AssocTimeout,
            _ => return,
        };
        run::event(local, sdata, ev);
        return;
    }

    if sdata.with(|s| s.mlme.is_associated()) {
        if super::beacon::check_connection(local, sdata) { return; }
    }
    sdata.with(|s| s.frags.expire(now_ns));
    release_reorder(local, sdata, now_ns);
    expire_agg(local, sdata, now_ns);
    if sdata.iftype().is_ap() { evict_inactive(local, sdata, now_ns); }
}

/// Release whatever the reorder buffers have given up waiting for.
/// # C: O(N stations × identifiers)
fn release_reorder(local: &Arc<Local>, sdata: &Arc<Sdata>, now_ns: u64) {
    let status = RxStatus { now_ns, ..Default::default() };
    let batches = sdata.stas.for_each(|sta| {
        let mut out = alloc::vec::Vec::new();
        for tid in 0..NUM_BA_TIDS {
            let Some(buf) = sta.tid_rx[tid].as_mut() else { continue; };
            out.extend(buf.release_timed_out(now_ns));
        }
        if out.is_empty() { None } else { Some(out) }
    });
    for batch in batches {
        for frame in batch { crate::rx::data::deliver_released(local, sdata, &status, &frame); }
    }
}

/// Tear down aggregation sessions that carried nothing, and retry or abandon
/// requests that went unanswered. # C: O(N stations × identifiers)
fn expire_agg(local: &Arc<Local>, sdata: &Arc<Sdata>, now_ns: u64) {
    let work = sdata.stas.for_each(|sta| {
        let mut out = alloc::vec::Vec::new();
        for tid in 0..NUM_BA_TIDS {
            if sta.tid_rx[tid].as_ref().is_some_and(|b| b.is_idle(now_ns)) {
                out.push((sta.addr, tid as u8, AggExpiry::RxIdle));
            }
            let tx = &mut sta.tid_tx[tid];
            if tx.request_timed_out(now_ns) {
                if tx.may_retry() { out.push((sta.addr, tid as u8, AggExpiry::Retry)); }
                else { tx.stopped(); out.push((sta.addr, tid as u8, AggExpiry::GiveUp)); }
            } else if tx.is_idle(now_ns) {
                out.push((sta.addr, tid as u8, AggExpiry::TxIdle));
            }
        }
        if out.is_empty() { None } else { Some(out) }
    });
    for batch in work {
        for (peer, tid, what) in batch {
            match what {
                AggExpiry::RxIdle => {
                    sdata.stas.with(peer, |sta| sta.tid_rx[tid as usize] = None);
                    let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
                        crate::ops::AmpduAction::RxStop { tid });
                }
                AggExpiry::Retry => super::action::start_tx_agg(local, sdata, peer, tid),
                AggExpiry::GiveUp => {
                    let _ = local.ops.ampdu_action(&local.hw, &sdata.vif(), peer,
                        crate::ops::AmpduAction::TxFlush { tid });
                }
                AggExpiry::TxIdle => super::action::stop_tx_agg(local, sdata, peer, tid,
                    wireless::ieee80211::status::reason::UNSPECIFIED),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggExpiry { RxIdle, TxIdle, Retry, GiveUp }

/// Drop stations that stopped talking. # C: O(N stations)
fn evict_inactive(local: &Arc<Local>, sdata: &Arc<Sdata>, now_ns: u64) {
    for peer in sdata.stas.inactive(now_ns) {
        super::deauth::deauth_peer(local, sdata, peer,
            wireless::ieee80211::status::reason::DISASSOC_DUE_TO_INACTIVITY, false);
    }
}

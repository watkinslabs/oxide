// Control frames.
//
// Only two matter above the radio. A power-save poll asks for one buffered
// frame, and a block-ack request says the sender has given up on everything
// before a sequence number — which releases whatever the reorder buffer is
// still holding behind that point. Ignoring the second is the other way a
// traffic identifier stalls.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::fctl::{self, ctl_stype};
use wireless::ieee80211::hdr::MacHeader;
use wireless::ieee80211::mgmt::{ba_params, SSC_SSN_SHIFT};

use crate::hw::Local;
use crate::iface::Sdata;

/// Handle a control frame. # C: O(released)
pub fn rx_ctl(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8]) {
    match fctl::stype(header.frame_control) {
        ctl_stype::PSPOLL => crate::ps::rx_pspoll(local, sdata, header),
        ctl_stype::BACK_REQ => rx_bar(local, sdata, header, body),
        _ => {}
    }
}

/// A block-ack request: the peer says everything before this sequence number
/// is gone. # C: O(released)
fn rx_bar(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8]) {
    let Some(sender) = header.transmitter() else { return; };
    // The body of a block-ack request is the control field and the starting
    // sequence control, in that order.
    if body.len() < 4 { return; }
    let control = u16::from_le_bytes([body[0], body[1]]);
    let ssc = u16::from_le_bytes([body[2], body[3]]);
    let tid = ba_params::delba_tid(control);
    let start_sn = ssc >> SSC_SSN_SHIFT;
    if (tid as usize) >= wireless::ieee80211::fctl::NUM_BA_TIDS { return; }

    let now = local.now_ns();
    let released = sdata.stas.with(sender, |sta| {
        sta.tid_rx[tid as usize].as_mut().map(|buf| buf.bar(start_sn)).unwrap_or_default()
    }).unwrap_or_default();
    let status = crate::ops::RxStatus { now_ns: now, ..Default::default() };
    for frame in released { super::data::deliver_released(local, sdata, &status, &frame); }
}

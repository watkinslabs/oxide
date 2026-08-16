// Management-frame dispatch.
//
// The management-frame-protection rule lives here and is the single most
// consequential decision in the receive path: on a link where management
// frames are protected, an UNPROTECTED deauthenticate or disassociate MUST
// NOT tear the link down. Acting on one is the whole attack that protection
// was introduced to stop — a single spoofed frame from anywhere in range
// disconnects the station. The frame is reported upward under its own event,
// which is how a supplicant learns it is being attacked, and the association
// survives.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::fctl::mgmt_stype as st;
use wireless::ieee80211::{fctl, hdr::MacHeader};

use crate::hw::Local;
use crate::iface::Sdata;
use crate::ops::RxStatus;

/// Whether a received robust management frame may be ACTED ON, as opposed to
/// merely reported. On a protected link only a frame that arrived protected
/// may be acted on. # C: O(1)
pub fn may_act_on_mlme(fc: u16, mfp: bool) -> bool {
    if !mfp { return true; }
    if !fctl::is_robust_mgmt(fc) { return true; }
    fctl::is_protected(fc)
}

/// Dispatch one management frame. `body` is the frame body after the MAC
/// header, decrypted if it was protected; `raw` is the frame as it arrived,
/// which is what the upward reports carry. # C: O(len)
pub fn rx_mgmt(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader,
               status: &RxStatus, body: &[u8], raw: &[u8]) {
    let fc = header.frame_control;
    let subtype = fctl::stype(fc);
    let mfp = sdata.mfp();

    match subtype {
        st::BEACON | st::PROBE_RESP => {
            crate::scan::note_beacon(local, sdata, status, raw);
            if fctl::stype(fc) == st::BEACON { crate::mlme::beacon::rx_beacon(local, sdata, header, status, body); }
        }
        st::AUTH => crate::mlme::auth::rx_auth(local, sdata, header, body, raw),
        st::ASSOC_RESP | st::REASSOC_RESP =>
            crate::mlme::assoc::rx_assoc_resp(local, sdata, header, body, raw),
        st::ASSOC_REQ | st::REASSOC_REQ =>
            crate::mlme::ap::rx_assoc_req(local, sdata, header, body,
                                          subtype == st::REASSOC_REQ),
        st::PROBE_REQ => crate::mlme::ap::rx_probe_req(local, sdata, header, body),
        st::DEAUTH | st::DISASSOC => {
            if !may_act_on_mlme(fc, mfp) {
                report_unprotected(local, sdata, raw);
                return;
            }
            crate::mlme::deauth::rx_deauth(local, sdata, header, body, raw,
                                           subtype == st::DEAUTH);
        }
        st::ACTION => crate::mlme::action::rx_action(local, sdata, header, body),
        _ => {}
    }
    report_to_userspace(local, sdata, status, raw);
}

fn report_unprotected(local: &Arc<Local>, sdata: &Arc<Sdata>, raw: &[u8]) {
    let Some(wiphy) = local.wiphy() else { return; };
    wireless::events::rx_unprot_mlme(&wiphy, &sdata.wdev, raw);
}

/// Offer the frame to whichever netlink port registered for it. A frame
/// nobody registered for is not an error: most management frames are handled
/// entirely in the kernel. # C: O(N registrations)
fn report_to_userspace(local: &Arc<Local>, sdata: &Arc<Sdata>, status: &RxStatus, raw: &[u8]) {
    let Some(wiphy) = local.wiphy() else { return; };
    wireless::events::rx_mgmt(&wiphy, &sdata.wdev, status.freq, status.signal as i32, raw);
}

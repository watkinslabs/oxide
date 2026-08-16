// The association exchange, client side.
//
// The response's elements are not decoration: they carry the rate set the
// network will actually use, whether quality of service is in force, and the
// identifier every buffered-traffic announcement will refer to. A client that
// associated and ignored them transmits at rates the network rejects and
// misses its own traffic indications.

extern crate alloc;

use alloc::sync::Arc;

use wireless::ieee80211::{elem, hdr::MacHeader, mgmt};

use super::run;
use super::state::MlmeEvent;
use crate::hw::Local;
use crate::iface::Sdata;
use crate::uapi::elem_id;

/// Handle an association response on a client interface. # C: O(len)
pub fn rx_assoc_resp(local: &Arc<Local>, sdata: &Arc<Sdata>, header: &MacHeader, body: &[u8],
                     raw: &[u8]) {
    let Some(peer) = header.transmitter() else { return; };
    let Some(expect) = sdata.with(|s| s.mlme.bssid) else { return; };
    if peer != expect { return; }
    let Some(parsed) = mgmt::AssocRespBody::parse(body) else { return; };
    if !elem::is_well_formed(parsed.elements) { return; }

    if parsed.status == wireless::ieee80211::status::status::SUCCESS {
        apply_resp_elements(local, sdata, peer, parsed.capability, parsed.elements);
        if let Some(wiphy) = local.wiphy() {
            wireless::events::rx_assoc(&wiphy, &sdata.wdev, raw);
        }
    }
    sdata.with(|s| s.mlme.resp_ie = parsed.elements.to_vec());
    run::event(local, sdata, MlmeEvent::AssocResp { status: parsed.status, aid: parsed.aid });
}

/// Take from the response what the link will run on. # C: O(len)
fn apply_resp_elements(local: &Arc<Local>, sdata: &Arc<Sdata>,
                       peer: wireless::ieee80211::MacAddr, capability: u16, elements: &[u8]) {
    let supp = elem::find(elements, elem_id::SUPP_RATES).map(|e| e.body).unwrap_or(&[]);
    let ext = elem::find(elements, elem_id::EXT_SUPP_RATES).map(|e| e.body).unwrap_or(&[]);
    let peer_rates = crate::rate::rates_from_elements(supp, ext);
    let band_rates = band_rates(local, sdata);
    let usable = crate::rate::intersect(&band_rates, &peer_rates);
    let basic = crate::rate::basic_rate_mask(&band_rates, supp, ext);
    let qos = capability & mgmt::capability::QOS != 0
        || elem::find_vendor(elements, WMM_OUI, WMM_PARAM_TYPE).is_some();

    sdata.stas.with(peer, |sta| {
        sta.supported_rates = peer_rates.clone();
        sta.qos = qos;
        sta.rate.start(&usable);
    });
    crate::iface::update_bss(local, sdata, |bss| {
        bss.basic_rates = basic;
        bss.qos = qos;
        bss.use_short_preamble = capability & mgmt::capability::SHORT_PREAMBLE != 0;
        bss.use_short_slot = capability & mgmt::capability::SHORT_SLOT_TIME != 0;
    });
}

/// The Wi-Fi Alliance organisational identifier the quality-of-service
/// element sits under.
pub const WMM_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
/// Vendor element type of the quality-of-service parameter set.
pub const WMM_PARAM_TYPE: u8 = 2;

fn band_rates(local: &Arc<Local>, sdata: &Arc<Sdata>) -> alloc::vec::Vec<wireless::wiphy::Bitrate> {
    let Some(def) = sdata.chandef() else { return alloc::vec::Vec::new(); };
    local.hw.bands.iter().find(|b| b.band == def.chan.band)
        .map(|b| b.bitrates.clone()).unwrap_or_default()
}

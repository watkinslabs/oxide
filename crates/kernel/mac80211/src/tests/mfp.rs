// Management-frame protection.
//
// On a link where management frames are protected, an UNPROTECTED
// deauthenticate or disassociate must not tear the link down. Acting on one
// is the entire attack protection exists to stop: any radio in range can
// forge the frame, and a station that believes it disconnects on demand.
//
// The rule has two halves and both are checked here: the decision itself, and
// the association still standing after such a frame arrives on a live
// interface.

use alloc::vec;

use wireless::ieee80211::fctl::mgmt_stype as st;
use wireless::ieee80211::{build, fctl};
use wireless::uapi::ciphers::cipher;
use wireless::uapi::enums::IfType;

use crate::key::Key;
use crate::ops::RxStatus;
use crate::rx::may_act_on_mlme;
use crate::tests_fixture as f;

fn mgmt_fc(subtype: u16, protected: bool) -> u16 {
    fctl::FTYPE_MGMT | subtype | if protected { fctl::FCTL_PROTECTED } else { 0 }
}

#[test]
fn an_unprotected_teardown_may_not_be_acted_on_when_protection_is_in_force() {
    for subtype in [st::DEAUTH, st::DISASSOC] {
        assert!(!may_act_on_mlme(mgmt_fc(subtype, false), true),
                "subtype {subtype:#x} unprotected on a protected link");
        assert!(may_act_on_mlme(mgmt_fc(subtype, true), true),
                "subtype {subtype:#x} protected on a protected link");
    }
}

#[test]
fn without_protection_an_unprotected_teardown_is_acted_on() {
    // On a link with no management-frame protection there is nothing to
    // compare against, and refusing the frame would make an ordinary open
    // network impossible to leave.
    for subtype in [st::DEAUTH, st::DISASSOC] {
        assert!(may_act_on_mlme(mgmt_fc(subtype, false), false));
    }
}

#[test]
fn frames_outside_the_protected_class_are_unaffected() {
    // A beacon, a probe response and the association exchange are never
    // protected; requiring protection of them would make the network
    // unusable rather than safer.
    for subtype in [st::BEACON, st::PROBE_RESP, st::ASSOC_RESP, st::AUTH] {
        assert!(may_act_on_mlme(mgmt_fc(subtype, false), true),
                "subtype {subtype:#x} is not in the protected class");
    }
}

#[test]
fn an_unprotected_deauthenticate_does_not_disconnect_a_protected_link() {
    let (local, rec) = f::radio(f::STA);
    let sdata = f::iface(&local, IfType::Station, "wlan-mfp");
    // A protected, associated link.
    sdata.with(|s| {
        s.keys.install(Key::new(cipher::CCMP, vec![0x44; 16], 0, true, Some(f::AP), None));
        s.mlme.bssid = Some(f::AP);
    });
    crate::iface::update_bss(&local, &sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(f::AP);
        bss.protected_mgmt = true;
        bss.port_authorized = true;
    });
    sdata.stas.insert(crate::sta_info::Sta::new(f::AP, 0));
    sdata.stas.set_state(f::AP, crate::ops::StaState::Authorized, |_, _| true);
    rec.taken();
    assert!(sdata.is_assoc());

    // A forged, unprotected deauthenticate from the access point's address.
    let frame = build::deauth(f::STA, f::AP, f::AP,
                              wireless::ieee80211::status::reason::UNSPECIFIED);
    let status = RxStatus { freq: 2412, now_ns: 1_000, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);

    assert!(sdata.is_assoc(), "an unprotected teardown must not end the association");
    assert!(sdata.stas.contains(f::AP), "and the peer must still be there");
    assert_eq!(sdata.stas.state(f::AP), crate::ops::StaState::Authorized);
    assert!(sdata.port_authorized(), "and the port must still be open");
    f::drop_radio(&local);
}

#[test]
fn an_unprotected_deauthenticate_does_disconnect_an_unprotected_link() {
    // The positive half: without protection in force the same frame works,
    // so the rule above is not simply "never act on a deauthenticate".
    let (local, _rec) = f::radio(f::STA);
    let sdata = f::iface(&local, IfType::Station, "wlan-nomfp");
    sdata.with(|s| s.mlme.bssid = Some(f::AP));
    crate::iface::update_bss(&local, &sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(f::AP);
        bss.protected_mgmt = false;
    });
    sdata.stas.insert(crate::sta_info::Sta::new(f::AP, 0));
    sdata.stas.set_state(f::AP, crate::ops::StaState::Authorized, |_, _| true);

    let frame = build::deauth(f::STA, f::AP, f::AP,
                              wireless::ieee80211::status::reason::UNSPECIFIED);
    let status = RxStatus { freq: 2412, now_ns: 1_000, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);

    assert!(!sdata.is_assoc(), "an unprotected link does end on a deauthenticate");
    assert!(!sdata.stas.contains(f::AP));
    f::drop_radio(&local);
}

#[test]
fn an_unprotected_disassociate_does_not_end_a_protected_association() {
    let (local, _rec) = f::radio(f::STA);
    let sdata = f::iface(&local, IfType::Station, "wlan-mfp2");
    sdata.with(|s| {
        s.keys.install(Key::new(cipher::CCMP, vec![0x44; 16], 0, true, Some(f::AP), None));
        s.mlme.bssid = Some(f::AP);
    });
    crate::iface::update_bss(&local, &sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(f::AP);
        bss.protected_mgmt = true;
    });
    sdata.stas.insert(crate::sta_info::Sta::new(f::AP, 0));
    sdata.stas.set_state(f::AP, crate::ops::StaState::Assoc, |_, _| true);

    let frame = build::disassoc(f::STA, f::AP, f::AP,
                                wireless::ieee80211::status::reason::UNSPECIFIED);
    let status = RxStatus { freq: 2412, now_ns: 1_000, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);

    assert!(sdata.is_assoc());
    assert_eq!(sdata.stas.state(f::AP), crate::ops::StaState::Assoc);
    f::drop_radio(&local);
}

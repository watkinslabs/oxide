// The controlled port, as a decision and as behaviour on a live interface.
//
// Before the port is authorized, only the exchange that authorizes it may
// leave. Everything else — the first name lookup, a retransmission from a
// socket that survived a roam — would go out in the clear on a network the
// user believes is protected.

use alloc::vec;

use wireless::uapi::ciphers::cipher;
use wireless::uapi::enums::IfType;

use crate::key::Key;
use crate::netdev::convert::EthFrame;
use crate::tests_fixture as f;
use crate::tx::port::{allowed, crosses_unauthorized_port, verdict, PortVerdict};
use crate::uapi::{ETH_P_PAE, ETH_P_PREAUTH, ETH_P_TDLS};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86dd;

#[test]
fn only_the_authentication_protocols_cross_a_closed_port() {
    for proto in [ETH_P_PAE, ETH_P_PREAUTH, ETH_P_TDLS] {
        assert!(crosses_unauthorized_port(proto), "{proto:#06x} must cross");
    }
    for proto in [ETH_P_IP, ETH_P_ARP, ETH_P_IPV6, 0x0000, 0xffff, 0x888f, 0x888d] {
        assert!(!crosses_unauthorized_port(proto), "{proto:#06x} must not cross");
    }
}

#[test]
fn a_data_frame_is_refused_before_the_port_is_authorized() {
    assert_eq!(verdict(true, false, ETH_P_IP), PortVerdict::Blocked);
    assert_eq!(verdict(true, false, ETH_P_ARP), PortVerdict::Blocked);
    assert_eq!(verdict(true, false, ETH_P_IPV6), PortVerdict::Blocked);
}

#[test]
fn the_authentication_protocol_is_permitted_before_the_port_is_authorized() {
    assert_eq!(verdict(true, false, ETH_P_PAE), PortVerdict::Allow);
}

#[test]
fn everything_is_permitted_after_the_port_is_authorized() {
    for proto in [ETH_P_IP, ETH_P_ARP, ETH_P_IPV6, ETH_P_PAE] {
        assert_eq!(verdict(true, true, proto), PortVerdict::Allow, "{proto:#06x}");
    }
}

#[test]
fn an_open_network_has_no_port_to_close() {
    for proto in [ETH_P_IP, ETH_P_ARP, ETH_P_PAE] {
        assert!(allowed(false, false, proto), "{proto:#06x} on an open network");
    }
}

#[test]
fn a_live_interface_refuses_then_permits() {
    // The same decision, driven through the whole transmit chain rather than
    // through the predicate alone, so a chain that forgot to consult it fails
    // here even though the predicate is correct.
    let (local, rec) = f::radio(f::STA);
    let sdata = f::iface(&local, IfType::Station, "wlan-port");
    crate::iface::update_bss(&local, &sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(f::AP);
        bss.port_authorized = false;
    });
    sdata.stas.insert(crate::sta_info::Sta::new(f::AP, 0));
    // A key exists, so the interface runs a controlled port.
    sdata.with(|s| s.keys.install(Key::new(cipher::CCMP, vec![0x33; 16], 0, true,
                                           Some(f::AP), None)));
    rec.taken();

    let payload = vec![0xaa; 20];
    let ip = EthFrame { dst: f::AP, src: f::STA, proto: ETH_P_IP, payload: payload.clone() };
    assert!(!crate::tx::xmit_eth(&local, &sdata, &ip), "a data frame must be refused");
    assert_eq!(rec.count(), 0, "nothing may reach the radio");
    assert_eq!(sdata.stats().tx_port_blocked, 1);

    let eapol = EthFrame { dst: f::AP, src: f::STA, proto: ETH_P_PAE, payload };
    assert!(crate::tx::xmit_eth(&local, &sdata, &eapol));
    assert_eq!(rec.count(), 1, "the exchange that opens the port must get out");

    crate::iface::update_bss(&local, &sdata, |bss| bss.port_authorized = true);
    rec.taken();
    assert!(crate::tx::xmit_eth(&local, &sdata, &ip), "and afterwards everything flows");
    assert_eq!(rec.count(), 1);
    f::drop_radio(&local);
}

#[test]
fn a_received_data_frame_is_refused_from_an_unauthorized_peer() {
    use crate::rx::data::frame_allowed;
    let (local, _rec) = f::radio(f::AP);
    let sdata = f::iface(&local, IfType::Ap, "wlan-rxport");
    sdata.with(|s| s.keys.install(Key::new(cipher::CCMP, vec![1; 16], 0, false, None, None)));
    sdata.stas.insert(crate::sta_info::Sta::new(f::PEER, 0));
    sdata.stas.set_state(f::PEER, crate::ops::StaState::Assoc, |_, _| true);

    let ip = EthFrame { dst: f::AP, src: f::PEER, proto: ETH_P_IP, payload: vec![0; 8] };
    assert!(!frame_allowed(&sdata, f::PEER, &ip));
    let eapol = EthFrame { dst: f::AP, src: f::PEER, proto: ETH_P_PAE, payload: vec![0; 8] };
    assert!(frame_allowed(&sdata, f::PEER, &eapol));

    sdata.stas.set_state(f::PEER, crate::ops::StaState::Authorized, |_, _| true);
    assert!(frame_allowed(&sdata, f::PEER, &ip));
    f::drop_radio(&local);
}

#[test]
fn the_authentication_protocol_is_refused_for_a_destination_that_is_not_ours() {
    use crate::rx::data::{frame_allowed, PAE_GROUP_ADDR};
    let (local, _rec) = f::radio(f::AP);
    let sdata = f::iface(&local, IfType::Ap, "wlan-paedst");
    // Addressed to us, or to the protocol's own group address: allowed.
    let mine = EthFrame { dst: f::AP, src: f::PEER, proto: ETH_P_PAE, payload: vec![] };
    let group = EthFrame { dst: PAE_GROUP_ADDR, src: f::PEER, proto: ETH_P_PAE,
                           payload: vec![] };
    assert!(frame_allowed(&sdata, f::PEER, &mine));
    assert!(frame_allowed(&sdata, f::PEER, &group));
    // Addressed to somebody else: refused, whatever the port state, so a peer
    // cannot relay another station's exchange through us.
    let theirs = EthFrame { dst: f::OTHER, src: f::PEER, proto: ETH_P_PAE, payload: vec![] };
    assert!(!frame_allowed(&sdata, f::PEER, &theirs));
    f::drop_radio(&local);
}

// Connecting, disconnecting, and the raw management exchanges.

extern crate alloc;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::nl80211::connect_cmd;
use crate::nl80211::tests_support::{lock, radio_with, Call, Req};
use crate::uapi::attr as a;
use crate::uapi::ciphers::cipher;
use crate::uapi::enums::{auth_type, mfp, IfType};
use crate::wdev::Wdev;

/// The address the fixture connects to.
const PEER: MacAddr = MacAddr([0x02, 0x99, 0, 0, 0, 1]);

/// Put an interface into the associated state. # C: O(1)
fn associate(d: &alloc::sync::Arc<Wdev>) {
    d.with(|w| w.conn.associated(PEER, 1, alloc::vec::Vec::new(),
                                 alloc::vec::Vec::new(), true));
}

/// A minimal well-formed connect request. # C: O(1)
fn connect_req(d: &alloc::sync::Arc<Wdev>) -> Req {
    let mut req = Req::wdev(d);
    req.bytes(a::SSID, b"oxide");
    req
}

#[test]
fn a_connect_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    assert!(connect_req(&d).call(connect_cmd::connect).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Connect);
}

#[test]
fn a_connect_with_no_network_name_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn an_empty_network_name_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.bytes(a::SSID, b"");
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn a_connect_on_an_access_point_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    assert!(connect_req(&d).call(connect_cmd::connect).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_bad_cipher_outranks_the_wrong_interface_type() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = connect_req(&d);
    req.u32(a::CIPHER_SUITE_GROUP, cipher::GCMP_256);
    // The security suites are validated before the interface type, so a
    // request that is wrong in both ways reports the argument.
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn an_authentication_type_out_of_range_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = connect_req(&d);
    req.u32(a::AUTH_TYPE, auth_type::MAX + 5);
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn a_pairwise_cipher_the_radio_lacks_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = connect_req(&d);
    let mut suites = alloc::vec::Vec::new();
    suites.extend_from_slice(&cipher::CCMP.to_ne_bytes());
    suites.extend_from_slice(&cipher::GCMP.to_ne_bytes());
    req.bytes(a::CIPHER_SUITES_PAIRWISE, &suites);
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn a_cipher_list_that_is_not_a_whole_number_of_suites_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = connect_req(&d);
    req.bytes(a::CIPHER_SUITES_PAIRWISE, &[1, 2, 3]);
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn a_protection_level_out_of_range_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = connect_req(&d);
    req.u32(a::USE_MFP, mfp::MAX + 1);
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn a_second_connect_while_connected_is_already_done() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    associate(&d);
    assert!(connect_req(&d).call(connect_cmd::connect).is_err(Errno::Ealready));
}

#[test]
fn a_reassociation_naming_the_wrong_previous_address_is_not_connected() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    associate(&d);
    let mut req = connect_req(&d);
    req.mac(a::PREV_BSSID, MacAddr([0x02, 0x77, 0, 0, 0, 9]));
    assert!(req.call(connect_cmd::connect).is_err(Errno::Enotconn));
}

#[test]
fn a_reassociation_naming_the_right_previous_address_is_admitted() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    associate(&d);
    let mut req = connect_req(&d);
    req.mac(a::PREV_BSSID, PEER);
    assert!(req.call(connect_cmd::connect).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Connect);
}

#[test]
fn a_frequency_the_radio_has_no_channel_for_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = connect_req(&d);
    req.u32(a::WIPHY_FREQ, 9999);
    assert!(req.call(connect_cmd::connect).is_err(Errno::Einval));
}

#[test]
fn disconnecting_a_connected_interface_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    associate(&d);
    let mut req = Req::wdev(&d);
    req.u16(a::REASON_CODE, 3);
    assert!(req.call(connect_cmd::disconnect).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Disconnect(3));
}

#[test]
fn disconnecting_an_idle_interface_succeeds_and_reaches_nothing() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(connect_cmd::disconnect).is_ack());
    assert!(ops.calls.lock().unwrap().is_empty());
}

#[test]
fn a_reserved_reason_code_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u16(a::REASON_CODE, 0);
    assert!(req.call(connect_cmd::disconnect).is_err(Errno::Einval));
}

/// A well-formed authenticate request. # C: O(1)
fn auth_req(d: &alloc::sync::Arc<Wdev>) -> Req {
    let mut req = Req::wdev(d);
    req.mac(a::MAC, PEER);
    req.u32(a::AUTH_TYPE, auth_type::OPEN_SYSTEM);
    req.bytes(a::SSID, b"oxide");
    req.u32(a::WIPHY_FREQ, 2412);
    req
}

#[test]
fn an_authenticate_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    assert!(auth_req(&d).call(connect_cmd::authenticate).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Auth);
}

#[test]
fn an_authenticate_missing_any_required_attribute_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    for skip in 0..4 {
        let mut req = Req::wdev(&d);
        if skip != 0 { req.mac(a::MAC, PEER); }
        if skip != 1 { req.u32(a::AUTH_TYPE, auth_type::OPEN_SYSTEM); }
        if skip != 2 { req.bytes(a::SSID, b"oxide"); }
        if skip != 3 { req.u32(a::WIPHY_FREQ, 2412); }
        assert!(req.call(connect_cmd::authenticate).is_err(Errno::Einval),
                "missing attribute {skip} must be refused");
    }
}

#[test]
fn a_local_state_change_puts_no_frame_on_the_air() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = auth_req(&d);
    req.flag(a::LOCAL_STATE_CHANGE);
    assert!(req.call(connect_cmd::authenticate).is_ack());
    assert!(ops.calls.lock().unwrap().is_empty(),
            "a local state change must reach no driver");
}

#[test]
fn an_authenticate_needing_a_payload_without_one_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u32(a::AUTH_TYPE, auth_type::SAE);
    req.bytes(a::SSID, b"oxide");
    req.u32(a::WIPHY_FREQ, 2412);
    assert!(req.call(connect_cmd::authenticate).is_err(Errno::Einval));
}

#[test]
fn an_authentication_payload_on_an_algorithm_that_takes_none_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = auth_req(&d);
    req.bytes(a::AUTH_DATA, &[1, 2, 3]);
    assert!(req.call(connect_cmd::authenticate).is_err(Errno::Einval));
}

#[test]
fn an_associate_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.bytes(a::SSID, b"oxide");
    req.u32(a::WIPHY_FREQ, 2412);
    assert!(req.call(connect_cmd::associate).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Assoc);
}

#[test]
fn a_deauthenticate_carries_its_reason_and_its_local_flag() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u16(a::REASON_CODE, 7);
    req.flag(a::LOCAL_STATE_CHANGE);
    assert!(req.call(connect_cmd::deauthenticate).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Deauth(7, true));
}

#[test]
fn a_disassociate_carries_its_reason() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u16(a::REASON_CODE, 8);
    assert!(req.call(connect_cmd::disassociate).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::Disassoc(8, false));
}

#[test]
fn a_teardown_without_a_reason_code_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    assert!(req.call(connect_cmd::deauthenticate).is_err(Errno::Einval));
}

#[test]
fn a_teardown_on_an_access_point_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u16(a::REASON_CODE, 3);
    assert!(req.call(connect_cmd::deauthenticate).is_err(Errno::Eopnotsupp));
}

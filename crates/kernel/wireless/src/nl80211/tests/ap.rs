// Starting and stopping an access point.

extern crate alloc;

use syscall::errno::Errno;

use crate::nl80211::ap_cmd;
use crate::nl80211::tests_support::{lock, radio_with, Call, Req};
use crate::uapi::attr as a;
use crate::uapi::enums::{auth_type, IfType};
use crate::wdev::Wdev;

/// A well-formed start request on channel 6. # C: O(1)
fn start_req(d: &alloc::sync::Arc<Wdev>) -> Req {
    let mut req = Req::wdev(d);
    req.u32(a::BEACON_INTERVAL, 100);
    req.u32(a::DTIM_PERIOD, 2);
    req.bytes(a::BEACON_HEAD, &[0u8; 36]);
    req.bytes(a::SSID, b"oxide-ap");
    req.u32(a::WIPHY_FREQ, 2437);
    req
}

#[test]
fn a_well_formed_start_reaches_the_driver_and_marks_the_interface() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    assert!(start_req(&d).call(ap_cmd::start).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::StartAp { beacon_interval: 100, dtim: 2 });
    assert!(d.with(|w| w.beaconing));
    assert_eq!(d.ssid(), b"oxide-ap".to_vec());
    assert_eq!(d.chandef().map(|c| c.chan.center_freq), Some(2437));
}

#[test]
fn a_start_on_a_client_interface_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(start_req(&d).call(ap_cmd::start).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_second_start_on_a_beaconing_interface_is_already_done() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    assert!(start_req(&d).call(ap_cmd::start).is_ack());
    assert!(start_req(&d).call(ap_cmd::start).is_err(Errno::Ealready));
}

#[test]
fn a_start_missing_any_required_attribute_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    for skip in 0..3 {
        let mut req = Req::wdev(&d);
        if skip != 0 { req.u32(a::BEACON_INTERVAL, 100); }
        if skip != 1 { req.u32(a::DTIM_PERIOD, 2); }
        if skip != 2 { req.bytes(a::BEACON_HEAD, &[0u8; 36]); }
        req.u32(a::WIPHY_FREQ, 2437);
        assert!(req.call(ap_cmd::start).is_err(Errno::Einval),
                "missing attribute {skip} must be refused");
    }
}

#[test]
fn a_beacon_interval_out_of_range_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    for interval in [9u32, 10_001] {
        let mut fresh = Req::wdev(&d);
        fresh.u32(a::BEACON_INTERVAL, interval);
        fresh.u32(a::DTIM_PERIOD, 2);
        fresh.bytes(a::BEACON_HEAD, &[0u8; 36]);
        fresh.u32(a::WIPHY_FREQ, 2437);
        assert!(fresh.call(ap_cmd::start).is_err(Errno::Einval));
    }
}

#[test]
fn an_empty_network_name_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.u32(a::BEACON_INTERVAL, 100);
    req.u32(a::DTIM_PERIOD, 2);
    req.bytes(a::BEACON_HEAD, &[0u8; 36]);
    req.bytes(a::SSID, b"");
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(ap_cmd::start).is_err(Errno::Einval));
}

#[test]
fn a_start_with_no_channel_at_all_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.u32(a::BEACON_INTERVAL, 100);
    req.u32(a::DTIM_PERIOD, 2);
    req.bytes(a::BEACON_HEAD, &[0u8; 36]);
    assert!(req.call(ap_cmd::start).is_err(Errno::Einval));
}

#[test]
fn a_channel_the_domain_forbids_initiating_on_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.u32(a::BEACON_INTERVAL, 100);
    req.u32(a::DTIM_PERIOD, 2);
    req.bytes(a::BEACON_HEAD, &[0u8; 36]);
    // The world domain marks every 5 GHz channel receive-only, so beaconing
    // on one is refused even though the channel exists.
    req.u32(a::WIPHY_FREQ, 5180);
    assert!(req.call(ap_cmd::start).is_err(Errno::Einval));
}

#[test]
fn an_authentication_type_the_command_does_not_take_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = start_req(&d);
    req.u32(a::AUTH_TYPE, auth_type::SAE);
    assert!(req.call(ap_cmd::start).is_err(Errno::Einval));
}

#[test]
fn a_driver_refusal_leaves_the_interface_not_beaconing() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    ops.program.lock().unwrap().start_ap_fails = Some(Errno::Ebusy);
    assert!(start_req(&d).call(ap_cmd::start).is_err(Errno::Ebusy));
    assert!(!d.with(|w| w.beaconing));
}

#[test]
fn stopping_a_running_access_point_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    assert!(start_req(&d).call(ap_cmd::start).is_ack());
    assert!(Req::wdev(&d).call(ap_cmd::stop).is_ack());
    assert!(ops.calls.lock().unwrap().contains(&Call::StopAp));
    assert!(!d.with(|w| w.beaconing));
    assert!(d.ssid().is_empty());
}

#[test]
fn stopping_an_interface_that_is_not_beaconing_reports_no_entry() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    assert!(Req::wdev(&d).call(ap_cmd::stop).is_err(Errno::Enoent));
}

#[test]
fn a_stop_on_a_client_interface_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(ap_cmd::stop).is_err(Errno::Eopnotsupp));
}

#[test]
fn changing_network_parameters_on_a_client_interface_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u8(a::BSS_CTS_PROT, 1);
    assert!(req.call(ap_cmd::set_bss).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_network_parameter_that_is_neither_on_nor_off_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.u8(a::BSS_CTS_PROT, 7);
    assert!(req.call(ap_cmd::set_bss).is_err(Errno::Einval));
}

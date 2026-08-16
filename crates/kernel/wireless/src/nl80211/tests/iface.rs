// Interface creation, change and removal: the refusals, their order, and
// what the reply carries back.

extern crate alloc;

use alloc::string::ToString;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::nl80211::tests_support::{find, lock, radio, radio_with, u32_of, u8_of, Call,
                                    Req};
use crate::nl80211::iface_cmd;
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{ps_state, IfType};
use crate::uapi::nested::{cqm, mntr_flag};
use crate::wiphy::registry;

#[test]
fn new_interface_creates_and_replies_with_its_description() {
    let _g = lock();
    let (w, ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "wlan7");
    req.u32(a::IFTYPE, IfType::Station.as_u32());
    let reply = req.call(iface_cmd::new);
    assert_eq!(reply.cmd(), Some(cmd::NEW_INTERFACE));
    let b = reply.body();
    assert_eq!(u32_of(b, a::IFTYPE), Some(IfType::Station.as_u32()));
    assert_eq!(u32_of(b, a::WIPHY), Some(w.index));
    assert!(find(b, a::WDEV).is_some());
    assert!(find(b, a::MAC).is_some());
    assert_eq!(u8_of(b, a::_4ADDR), Some(0));
    assert_eq!(find(b, a::IFNAME).map(|p| p[..5].to_vec()), Some(b"wlan7".to_vec()));
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::AddIface("wlan7".to_string(), IfType::Station.as_u32()));
    assert_eq!(w.wdevs().len(), 1);
}

#[test]
fn new_interface_without_a_name_is_a_bad_request() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.u32(a::IFTYPE, IfType::Station.as_u32());
    assert!(req.call(iface_cmd::new).is_err(Errno::Einval));
}

#[test]
fn new_interface_of_an_unsupported_type_is_unsupported() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "mesh0");
    req.u32(a::IFTYPE, IfType::MeshPoint.as_u32());
    assert!(req.call(iface_cmd::new).is_err(Errno::Eopnotsupp));
}

#[test]
fn an_unsupported_type_on_an_absent_radio_reports_the_absent_radio() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.u32(a::WIPHY, 99);
    req.text(a::IFNAME, "mesh0");
    req.u32(a::IFTYPE, IfType::MeshPoint.as_u32());
    // Both refusals apply. The radio is resolved first, so the caller is told
    // the radio is gone rather than that a type it never asked about is
    // unsupported on a radio that does not exist.
    assert!(req.call(iface_cmd::new).is_err(Errno::Enodev));
}

#[test]
fn a_name_another_interface_holds_already_exists() {
    let _g = lock();
    let (w, _ops, _d) = radio_with(IfType::Station);
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "wlan0");
    req.u32(a::IFTYPE, IfType::Ap.as_u32());
    assert!(req.call(iface_cmd::new).is_err(Errno::Eexist));
}

#[test]
fn a_name_taken_on_another_radio_also_already_exists() {
    let _g = lock();
    let (_w1, _o1, _d) = radio_with(IfType::Station);
    let (w2, _o2) = radio();
    let mut req = Req::wiphy(&w2);
    req.text(a::IFNAME, "wlan0");
    req.u32(a::IFTYPE, IfType::Ap.as_u32());
    assert!(req.call(iface_cmd::new).is_err(Errno::Eexist));
}

#[test]
fn monitor_flags_on_a_type_that_is_not_a_monitor_are_a_bad_request() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "wlan1");
    req.u32(a::IFTYPE, IfType::Station.as_u32());
    req.nest(a::MNTR_FLAGS, |out| {
        netlink::genetlink::attr::put(out, mntr_flag::CONTROL, &[]);
    });
    assert!(req.call(iface_cmd::new).is_err(Errno::Einval));
}

#[test]
fn cooked_monitor_capture_is_refused() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "mon0");
    req.u32(a::IFTYPE, IfType::Monitor.as_u32());
    req.nest(a::MNTR_FLAGS, |out| {
        netlink::genetlink::attr::put(out, mntr_flag::COOK_FRAMES, &[]);
    });
    assert!(req.call(iface_cmd::new).is_err(Errno::Eopnotsupp));
}

#[test]
fn the_socket_owner_flag_records_the_caller() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "p2p0");
    req.u32(a::IFTYPE, IfType::P2pDevice.as_u32());
    req.flag(a::SOCKET_OWNER);
    assert_eq!(req.call(iface_cmd::new).cmd(), Some(cmd::NEW_INTERFACE));
    let wdev = w.wdevs().remove(0);
    assert_eq!(wdev.with(|d| d.owner_portid),
               Some(crate::nl80211::tests_support::PORT));
}

#[test]
fn an_address_a_station_cannot_hold_is_refused() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "p2p0");
    req.u32(a::IFTYPE, IfType::P2pDevice.as_u32());
    req.mac(a::MAC, MacAddr::BROADCAST);
    assert!(req.call(iface_cmd::new).is_err(Errno::Eaddrnotavail));
}

#[test]
fn a_driver_refusal_leaves_no_interface_behind() {
    let _g = lock();
    let (w, ops) = radio();
    ops.program.lock().unwrap().add_iface_fails = Some(Errno::Enomem);
    let mut req = Req::wiphy(&w);
    req.text(a::IFNAME, "wlan3");
    req.u32(a::IFTYPE, IfType::Station.as_u32());
    assert!(req.call(iface_cmd::new).is_err(Errno::Enomem));
    assert!(w.wdevs().is_empty());
    assert!(registry::lookup_wdev_by_name("wlan3").is_none());
}

#[test]
fn del_interface_removes_it_from_the_radio() {
    let _g = lock();
    let (w, ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(iface_cmd::del).is_ack());
    assert!(w.wdevs().is_empty());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::DelIface(d.identifier));
}

#[test]
fn get_and_dump_agree_with_what_creation_returned() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let one = Req::wdev(&d).call(iface_cmd::get);
    let all = Req::bare().dump().call(iface_cmd::dump);
    assert_eq!(all.parts().len(), 1);
    assert!(all.is_done());
    let parts = all.parts();
    let part = parts[0];
    assert_eq!(u32_of(one.body(), a::IFTYPE), u32_of(part, a::IFTYPE));
    assert_eq!(find(one.body(), a::MAC), find(part, a::MAC));
}

#[test]
fn set_interface_changes_the_type_through_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::IFTYPE, IfType::Ap.as_u32());
    assert!(req.call(iface_cmd::set).is_ack());
    assert_eq!(d.iftype(), IfType::Ap);
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::ChangeIface(d.identifier, IfType::Ap.as_u32()));
}

#[test]
fn set_interface_refuses_a_type_the_radio_lacks() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::IFTYPE, IfType::MeshPoint.as_u32());
    assert!(req.call(iface_cmd::set).is_err(Errno::Eopnotsupp));
    assert_eq!(d.iftype(), IfType::Station);
}

#[test]
fn set_interface_refuses_a_type_number_that_is_not_a_type() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::IFTYPE, 99);
    assert!(req.call(iface_cmd::set).is_err(Errno::Einval));
}

#[test]
fn power_save_reaches_the_driver_once_and_reads_back() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut on = Req::wdev(&d);
    on.u32(a::PS_STATE, ps_state::ENABLED);
    assert!(on.call(iface_cmd::set_power_save).is_ack());
    // Asking again for the state already in force must not reach the driver.
    assert!(on.call(iface_cmd::set_power_save).is_ack());
    assert_eq!(ops.calls.lock().unwrap().iter()
                   .filter(|c| matches!(c, Call::SetPowerMgmt(_))).count(), 1);
    let read = Req::wdev(&d).call(iface_cmd::get_power_save);
    assert_eq!(u32_of(read.body(), a::PS_STATE), Some(ps_state::ENABLED));
}

#[test]
fn power_save_with_no_state_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(iface_cmd::set_power_save).is_err(Errno::Einval));
}

#[test]
fn set_channel_programs_a_channel_the_domain_allows() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Monitor);
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(iface_cmd::set_channel).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::SetChannel(2437));
    assert_eq!(d.chandef().map(|c| c.chan.center_freq), Some(2437));
}

#[test]
fn set_channel_refuses_a_frequency_the_radio_has_no_channel_for() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Monitor);
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 9999);
    assert!(req.call(iface_cmd::set_channel).is_err(Errno::Einval));
}

#[test]
fn set_channel_refuses_a_client_interface() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(iface_cmd::set_channel).is_err(Errno::Eopnotsupp));
}

#[test]
fn set_channel_refuses_a_definition_the_domain_does_not_permit() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Monitor);
    // The world domain admits no 160 MHz channel at 5180, so the definition
    // is refused even though the primary channel exists.
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 5180);
    req.u32(a::CHANNEL_WIDTH, crate::uapi::enums::ChanWidth::Width160.as_u32());
    req.u32(a::CENTER_FREQ1, 5250);
    assert!(req.call(iface_cmd::set_channel).is_err(Errno::Einval));
}

#[test]
fn the_legacy_channel_type_derives_the_same_centre() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Monitor);
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 2437);
    req.u32(a::WIPHY_CHANNEL_TYPE, crate::uapi::enums::channel_type::HT40MINUS);
    assert!(req.call(iface_cmd::set_channel).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::SetChannel(2437));
    let def = d.chandef().expect("channel");
    assert_eq!(def.center_freq1, 2427);
    assert_eq!(def.width, crate::uapi::enums::ChanWidth::Width40);
}

#[test]
fn a_legacy_channel_type_disagreeing_with_the_centre_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Monitor);
    let mut req = Req::wdev(&d);
    req.u32(a::WIPHY_FREQ, 2437);
    req.u32(a::WIPHY_CHANNEL_TYPE, crate::uapi::enums::channel_type::HT40MINUS);
    req.u32(a::CENTER_FREQ1, 2447);
    assert!(req.call(iface_cmd::set_channel).is_err(Errno::Einval));
}

#[test]
fn cqm_stores_the_threshold_and_the_hysteresis() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::CQM, |out| {
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_THOLD, (-70i32) as u32);
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_HYST, 4);
    });
    assert!(req.call(iface_cmd::set_cqm).is_ack());
    assert_eq!(d.with(|w| (w.cqm.rssi_thold, w.cqm.rssi_hyst)), (-70, 4));
}

#[test]
fn a_positive_cqm_threshold_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::CQM, |out| {
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_THOLD, 10);
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_HYST, 4);
    });
    assert!(req.call(iface_cmd::set_cqm).is_err(Errno::Einval));
}

#[test]
fn cqm_on_an_access_point_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.nest(a::CQM, |out| {
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_THOLD, (-70i32) as u32);
        netlink::genetlink::attr::put_u32(out, cqm::RSSI_HYST, 4);
    });
    assert!(req.call(iface_cmd::set_cqm).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_command_addressing_a_radio_and_not_an_interface_is_a_bad_request() {
    let _g = lock();
    let (w, _ops, _d) = radio_with(IfType::Station);
    assert!(Req::wiphy(&w).call(iface_cmd::get).is_err(Errno::Einval));
}

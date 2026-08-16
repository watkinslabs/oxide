// Station reporting and modification, and the channel survey.

extern crate alloc;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::nl80211::station_cmd;
use crate::nl80211::tests_support::{find, has, lock, radio_with, u16_of, u32_of, u8_of,
                                    Call, Req};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::IfType;
use crate::uapi::nested::{rate_info, sta_flag, sta_info, survey_info};

/// The peer the fixture reports on.
const PEER: MacAddr = MacAddr([0x02, 0x33, 0, 0, 0, 1]);

#[test]
fn a_station_report_carries_only_the_fields_the_driver_filled() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    let reply = req.call(station_cmd::get);
    assert_eq!(reply.cmd(), Some(cmd::NEW_STATION));
    let b = reply.body();
    assert_eq!(find(b, a::MAC), Some(&PEER.0[..]));
    assert_eq!(u32_of(b, a::GENERATION), Some(7));
    let nest = find(b, a::STA_INFO).expect("station info");
    assert_eq!(u32_of(nest, sta_info::INACTIVE_TIME), Some(120));
    assert!(find(nest, sta_info::RX_BYTES64).is_some());
    assert!(find(nest, sta_info::SIGNAL).is_some());
    // The fake driver keeps no retry counter, so none is reported: zero
    // retries is a measurement and must not be invented.
    assert!(find(nest, sta_info::TX_RETRIES).is_none());
    assert!(find(nest, sta_info::TX_FAILED).is_none());
    assert!(find(nest, sta_info::BEACON_LOSS).is_none());
}

#[test]
fn the_station_flags_are_a_mask_and_a_value_word() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    let reply = req.call(station_cmd::get);
    let nest = find(reply.body(), a::STA_INFO).expect("station info");
    let raw = find(nest, sta_info::STA_FLAGS).expect("flags");
    assert_eq!(raw.len(), 8);
    let mask = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let set = u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]);
    assert!(mask & (1 << sta_flag::AUTHORIZED) != 0);
    assert!(set & (1 << sta_flag::AUTHORIZED) != 0);
    // A flag the driver knows and reports as off is in the mask and not in
    // the value: absent from both would mean it did not know.
    assert!(mask & (1 << sta_flag::WME) != 0);
    assert!(set & (1 << sta_flag::WME) == 0);
}

#[test]
fn each_rate_is_its_own_nest_with_the_wide_and_narrow_forms() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    let reply = req.call(station_cmd::get);
    let nest = find(reply.body(), a::STA_INFO).expect("station info");

    let tx = find(nest, sta_info::TX_BITRATE).expect("tx rate");
    assert_eq!(u32_of(tx, rate_info::BITRATE32), Some(650));
    assert_eq!(u16_of(tx, rate_info::BITRATE), Some(650));
    assert_eq!(u8_of(tx, rate_info::MCS), Some(7));
    assert!(has(tx, rate_info::WIDTH_40));
    assert!(has(tx, rate_info::SHORT_GI));
    assert!(!has(tx, rate_info::WIDTH_80));

    let rx = find(nest, sta_info::RX_BITRATE).expect("rx rate");
    assert_eq!(u8_of(rx, rate_info::VHT_MCS), Some(9));
    assert_eq!(u8_of(rx, rate_info::VHT_NSS), Some(2));
    assert!(has(rx, rate_info::WIDTH_80));
    assert!(!has(rx, rate_info::SHORT_GI));
}

#[test]
fn a_query_without_an_address_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    assert!(Req::wdev(&d).call(station_cmd::get).is_err(Errno::Einval));
}

#[test]
fn a_dump_reports_one_message_per_station_and_terminates() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    ops.program.lock().unwrap().stations = 3;
    let reply = Req::wdev(&d).dump().call(station_cmd::dump);
    assert_eq!(reply.parts().len(), 3);
    assert!(reply.is_done());
    assert_eq!(reply.part_cmds(), alloc::vec![cmd::NEW_STATION; 3]);
}

#[test]
fn a_dump_with_no_stations_reports_only_the_terminator() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let reply = Req::wdev(&d).dump().call(station_cmd::dump);
    assert!(reply.parts().is_empty());
    assert!(reply.is_done());
}

#[test]
fn adding_a_station_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u16(a::STA_AID, 3);
    assert!(req.call(station_cmd::new).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::AddStation(PEER));
}

#[test]
fn changing_a_station_reaches_the_other_driver_call() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    assert!(req.call(station_cmd::set).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::ChangeStation(PEER));
}

#[test]
fn a_mesh_link_state_out_of_range_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u8(a::STA_PLINK_STATE, 99);
    assert!(req.call(station_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_flag_mask_naming_a_flag_this_build_does_not_know_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    let mut payload = alloc::vec::Vec::new();
    payload.extend_from_slice(&(1u32 << 31).to_ne_bytes());
    payload.extend_from_slice(&0u32.to_ne_bytes());
    req.bytes(a::STA_FLAGS2, &payload);
    assert!(req.call(station_cmd::set).is_err(Errno::Einval));
}

#[test]
fn removing_a_station_carries_its_reason_and_defaults_it() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    assert!(req.call(station_cmd::del).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::DelStation(Some(PEER), crate::ieee80211::status::reason::PREV_AUTH_NOT_VALID));
}

#[test]
fn removing_a_station_with_a_reserved_reason_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u16(a::REASON_CODE, 0);
    assert!(req.call(station_cmd::del).is_err(Errno::Einval));
}

#[test]
fn removing_a_station_from_a_client_interface_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    assert!(req.call(station_cmd::del).is_err(Errno::Einval));
}

#[test]
fn a_removal_frame_subtype_that_is_neither_teardown_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Ap);
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.u8(a::MGMT_SUBTYPE, 1);
    assert!(req.call(station_cmd::del).is_err(Errno::Einval));
}

#[test]
fn a_survey_dump_reports_one_message_per_channel_and_terminates() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    ops.program.lock().unwrap().surveys = 2;
    let reply = Req::wdev(&d).dump().call(station_cmd::dump_survey);
    let parts = reply.parts();
    assert_eq!(parts.len(), 2);
    assert!(reply.is_done());
    let nest = find(parts[0], a::SURVEY_INFO).expect("survey info");
    assert_eq!(u32_of(nest, survey_info::FREQUENCY), Some(2412));
    assert!(has(nest, survey_info::IN_USE));
    assert!(find(nest, survey_info::TIME).is_some());
    // The second channel is not the one the radio sits on, so its flag is
    // absent rather than written with a false value.
    let second = find(parts[1], a::SURVEY_INFO).expect("survey info");
    assert!(!has(second, survey_info::IN_USE));
}

#[test]
fn a_driver_with_no_survey_reporting_says_so() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let reply = Req::wdev(&d).dump().call(station_cmd::dump_survey);
    assert!(reply.parts().is_empty());
    assert!(reply.is_done());
}

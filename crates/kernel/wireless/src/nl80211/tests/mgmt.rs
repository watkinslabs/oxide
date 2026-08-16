// Management-frame registration and transmission, and who a received frame
// reaches.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::ieee80211::{fctl, MacAddr};
use crate::nl80211::mgmt_cmd;
use crate::nl80211::tests_support::{find, lock, mgmt_frame, radio_with, Call, Req, PORT,
                                    PORT_B};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::IfType;
use crate::wdev::MgmtRegistration;

/// A public action frame, which is what a peer-to-peer exchange uses.
const ACTION: u16 = fctl::FTYPE_MGMT | fctl::mgmt_stype::ACTION;
/// Category byte of a public action frame.
const CATEGORY_PUBLIC: u8 = 0x04;
/// Category byte of a vendor-specific action frame.
const CATEGORY_VENDOR: u8 = 0x7f;

#[test]
fn a_registration_records_the_calling_port() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    req.u16(a::FRAME_TYPE, ACTION);
    assert!(req.call(mgmt_cmd::register_frame).is_ack());
    let regs = mgmt_cmd::registrations(&d);
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].portid, PORT);
    assert_eq!(regs[0].frame_type, ACTION);
}

#[test]
fn a_registration_with_no_match_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u16(a::FRAME_TYPE, ACTION);
    assert!(req.call(mgmt_cmd::register_frame).is_err(Errno::Einval));
}

#[test]
fn only_a_management_frame_may_be_registered_for() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    req.u16(a::FRAME_TYPE, fctl::FTYPE_DATA);
    assert!(req.call(mgmt_cmd::register_frame).is_err(Errno::Einval));
}

#[test]
fn a_frame_number_carrying_more_than_a_type_and_subtype_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    req.u16(a::FRAME_TYPE, ACTION | fctl::FCTL_PROTECTED);
    assert!(req.call(mgmt_cmd::register_frame).is_err(Errno::Einval));
}

#[test]
fn a_station_registering_for_every_authentication_frame_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME_MATCH, &[]);
    req.u16(a::FRAME_TYPE, fctl::FTYPE_MGMT | fctl::mgmt_stype::AUTH);
    assert!(req.call(mgmt_cmd::register_frame).is_err(Errno::Einval));
    // Naming the algorithm makes the same registration acceptable.
    let mut ok = Req::wdev(&d);
    ok.bytes(a::FRAME_MATCH, &[0x03, 0x00]);
    ok.u16(a::FRAME_TYPE, fctl::FTYPE_MGMT | fctl::mgmt_stype::AUTH);
    assert!(ok.call(mgmt_cmd::register_frame).is_ack());
}

#[test]
fn a_subtype_the_radio_cannot_receive_is_refused() {
    let _g = lock();
    // The fixture radio advertises no receivable subtype for this type.
    let (_w, _ops, d) = radio_with(IfType::P2pClient);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    req.u16(a::FRAME_TYPE, ACTION);
    assert!(req.call(mgmt_cmd::register_frame).is_err(Errno::Einval));
}

#[test]
fn a_second_socket_claiming_a_match_that_is_taken_is_already_done() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut first = Req::wdev(&d);
    first.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    first.u16(a::FRAME_TYPE, ACTION);
    assert!(first.call(mgmt_cmd::register_frame).is_ack());

    let mut second = Req::wdev(&d);
    second.hdr.nlmsg_pid = PORT_B;
    second.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    second.u16(a::FRAME_TYPE, ACTION);
    assert!(second.call(mgmt_cmd::register_frame).is_err(Errno::Ealready));
}

#[test]
fn a_frame_reaches_only_the_port_that_registered_for_it() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut mine = Req::wdev(&d);
    mine.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    mine.u16(a::FRAME_TYPE, ACTION);
    assert!(mine.call(mgmt_cmd::register_frame).is_ack());

    let mut theirs = Req::wdev(&d);
    theirs.hdr.nlmsg_pid = PORT_B;
    theirs.bytes(a::FRAME_MATCH, &[CATEGORY_VENDOR]);
    theirs.u16(a::FRAME_TYPE, ACTION);
    assert!(theirs.call(mgmt_cmd::register_frame).is_ack());

    assert_eq!(d.mgmt_targets(ACTION, &[CATEGORY_PUBLIC, 0x0a]), alloc::vec![PORT]);
    assert_eq!(d.mgmt_targets(ACTION, &[CATEGORY_VENDOR, 0x01]), alloc::vec![PORT_B]);
    // A subtype nobody registered for goes nowhere at all.
    assert!(d.mgmt_targets(fctl::FTYPE_MGMT | fctl::mgmt_stype::PROBE_REQ,
                           &[CATEGORY_PUBLIC]).is_empty());
}

#[test]
fn a_port_with_two_matching_registrations_is_told_once() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    // The command refuses a second overlapping registration, so the pair is
    // installed directly: what is being pinned is the delivery side, which
    // must not hand one socket the same frame twice.
    d.register_mgmt(MgmtRegistration {
        portid: PORT, frame_type: ACTION, match_prefix: alloc::vec![CATEGORY_PUBLIC],
        multicast_rx: false,
    });
    d.register_mgmt(MgmtRegistration {
        portid: PORT, frame_type: ACTION,
        match_prefix: alloc::vec![CATEGORY_PUBLIC, 0x0a], multicast_rx: false,
    });
    assert_eq!(mgmt_cmd::registrations(&d).len(), 2);
    assert_eq!(d.mgmt_targets(ACTION, &[CATEGORY_PUBLIC, 0x0a, 0x01]),
               alloc::vec![PORT]);
}

#[test]
fn releasing_a_port_drops_only_its_registrations() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut mine = Req::wdev(&d);
    mine.bytes(a::FRAME_MATCH, &[CATEGORY_PUBLIC]);
    mine.u16(a::FRAME_TYPE, ACTION);
    assert!(mine.call(mgmt_cmd::register_frame).is_ack());
    let mut theirs = Req::wdev(&d);
    theirs.hdr.nlmsg_pid = PORT_B;
    theirs.bytes(a::FRAME_MATCH, &[CATEGORY_VENDOR]);
    theirs.u16(a::FRAME_TYPE, ACTION);
    assert!(theirs.call(mgmt_cmd::register_frame).is_ack());

    mgmt_cmd::release_port(PORT, crate::nl80211::tests_support::NS);
    let left = mgmt_cmd::registrations(&d);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].portid, PORT_B);
}

/// A transmit request carrying a frame from the interface's own address.
/// # C: O(len)
fn tx_req(d: &alloc::sync::Arc<crate::wdev::Wdev>, frame: &[u8]) -> Req {
    let mut req = Req::wdev(d);
    req.bytes(a::FRAME, frame);
    req
}

#[test]
fn a_transmission_returns_the_drivers_cookie() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC, 0x0a]);
    let reply = tx_req(&d, &frame).call(mgmt_cmd::tx);
    assert_eq!(reply.cmd(), Some(cmd::FRAME));
    let raw = find(reply.body(), a::COOKIE).expect("cookie");
    let cookie = u64::from_ne_bytes(raw[..8].try_into().unwrap());
    assert_eq!(cookie, 0xfeed_1234);
    assert!(matches!(ops.calls.lock().unwrap()[0], Call::MgmtTx { offchan: false, .. }));
}

#[test]
fn a_transmission_from_another_address_is_refused() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, MacAddr([0x02, 0x77, 0, 0, 0, 9]),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    assert!(tx_req(&d, &frame).call(mgmt_cmd::tx).is_err(Errno::Einval));
    assert!(ops.calls.lock().unwrap().is_empty());
}

#[test]
fn a_frame_that_is_not_a_management_frame_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                               MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    let fc = fctl::FTYPE_DATA;
    frame[..2].copy_from_slice(&fc.to_le_bytes());
    assert!(tx_req(&d, &frame).call(mgmt_cmd::tx).is_err(Errno::Einval));
}

#[test]
fn a_frame_too_short_to_be_one_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let short: Vec<u8> = alloc::vec![0u8; 20];
    assert!(tx_req(&d, &short).call(mgmt_cmd::tx).is_err(Errno::Einval));
}

#[test]
fn a_transmission_with_no_frame_at_all_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(mgmt_cmd::tx).is_err(Errno::Einval));
}

#[test]
fn leaving_the_operating_channel_needs_somewhere_to_go() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    let mut req = tx_req(&d, &frame);
    req.flag(a::OFFCHANNEL_TX_OK);
    assert!(req.call(mgmt_cmd::tx).is_err(Errno::Einval));
}

#[test]
fn an_off_channel_transmission_with_a_channel_is_accepted() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    let mut req = tx_req(&d, &frame);
    req.flag(a::OFFCHANNEL_TX_OK);
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(mgmt_cmd::tx).cmd().is_some());
    assert!(matches!(ops.calls.lock().unwrap()[0], Call::MgmtTx { offchan: true, .. }));
}

#[test]
fn a_wait_shorter_than_the_floor_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    let mut req = tx_req(&d, &frame);
    req.u32(a::DURATION, 1);
    assert!(req.call(mgmt_cmd::tx).is_err(Errno::Einval));
}

#[test]
fn a_caller_that_does_not_wait_for_an_answer_gets_no_cookie() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let frame = mgmt_frame(fctl::mgmt_stype::ACTION, d.addr(),
                           MacAddr([0x02, 0x99, 0, 0, 0, 1]), &[CATEGORY_PUBLIC]);
    let mut req = tx_req(&d, &frame);
    req.flag(a::DONT_WAIT_FOR_ACK);
    assert!(req.call(mgmt_cmd::tx).is_ack());
}

#[test]
fn cancelling_a_wait_needs_the_cookie_it_is_cancelling() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(mgmt_cmd::tx_cancel_wait).is_err(Errno::Einval));
    let mut req = Req::wdev(&d);
    req.u64(a::COOKIE, 1);
    assert!(req.call(mgmt_cmd::tx_cancel_wait).is_ack());
}

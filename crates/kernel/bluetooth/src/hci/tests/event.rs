use super::*;
use crate::uapi::bt::{BT_CONNECTED, BDADDR_LE_RANDOM};
use crate::uapi::hci_cmd::HCI_OP_RESET;

fn dev() -> HciDevState { HciDevState::new(0, HCI_VIRTUAL) }
fn addr() -> BdAddr { BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) }

#[test]
fn a_command_complete_decodes_its_credit_opcode_and_parameters() {
    let ev = decode(HCI_EV_CMD_COMPLETE, &[0x01, 0x03, 0x0c, 0x00, 0xaa]).unwrap();
    assert_eq!(ev, Event::CmdComplete { ncmd: 1, opcode: HCI_OP_RESET,
        params: alloc::vec![0x00, 0xaa] });
}

#[test]
fn a_command_status_decodes_its_status_credit_and_opcode() {
    let ev = decode(HCI_EV_CMD_STATUS, &[0x0c, 0x01, 0x03, 0x0c]).unwrap();
    assert_eq!(ev, Event::CmdStatus { status: HCI_ERROR_COMMAND_DISALLOWED, ncmd: 1,
        opcode: HCI_OP_RESET });
}

// Decoding is total and refuses anything short, so a malformed event can never
// partially mutate state.
#[test]
fn every_typed_event_refuses_a_short_payload() {
    assert!(decode(HCI_EV_CMD_COMPLETE, &[0x01, 0x03]).is_none());
    assert!(decode(HCI_EV_CMD_STATUS, &[0x00, 0x01, 0x03]).is_none());
    assert!(decode(HCI_EV_CONN_COMPLETE, &[0u8; 10]).is_none());
    assert!(decode(HCI_EV_DISCONN_COMPLETE, &[0u8; 3]).is_none());
    assert!(decode(HCI_EV_ENCRYPT_CHANGE, &[0u8; 3]).is_none());
    assert!(decode(HCI_EV_AUTH_COMPLETE, &[0u8; 2]).is_none());
    assert!(decode(HCI_EV_HARDWARE_ERROR, &[]).is_none());
    assert!(decode(HCI_EV_NUM_COMP_PKTS, &[]).is_none());
}

// A declared entry count larger than the payload holds is malformed: trusting
// it would credit links that were never reported.
#[test]
fn a_completed_packets_event_refuses_a_count_the_payload_cannot_hold() {
    assert!(decode(HCI_EV_NUM_COMP_PKTS, &[2, 1, 0, 5, 0]).is_none());
    let ev = decode(HCI_EV_NUM_COMP_PKTS, &[2, 1, 0, 5, 0, 2, 0, 7, 0]).unwrap();
    assert_eq!(ev, Event::NumCompPkts { entries: alloc::vec![(1, 5), (2, 7)] });
}

// The handle word carries flags above the handle; a decoder that kept them
// would look up a handle no link has.
#[test]
fn a_handle_is_masked_free_of_its_flag_bits() {
    let mut body = [0u8; EV_DISCONN_COMPLETE_LEN];
    body[1..3].copy_from_slice(&0xF02Au16.to_le_bytes());
    let ev = decode(HCI_EV_DISCONN_COMPLETE, &body).unwrap();
    assert_eq!(ev, Event::DisconnComplete { status: 0, handle: 0x02a, reason: 0 });
}

#[test]
fn an_unrecognised_event_decodes_as_an_opaque_one_rather_than_failing() {
    let ev = decode(0x77, &[1, 2, 3]).unwrap();
    assert_eq!(ev, Event::Other { code: 0x77, params: alloc::vec![1, 2, 3] });
}

#[test]
fn an_le_connection_completion_decodes_its_address_and_type() {
    let mut body = alloc::vec![HCI_EV_LE_CONN_COMPLETE];
    body.extend_from_slice(&[0x00, 0x2a, 0x00, 0x01, BDADDR_LE_RANDOM]);
    body.extend_from_slice(addr().as_bytes());
    body.extend_from_slice(&[0u8; 7]);
    let ev = decode(HCI_EV_LE_META, &body).unwrap();
    assert_eq!(ev, Event::LeConnComplete { status: 0, handle: 0x2a,
        addr_type: BDADDR_LE_RANDOM, addr: addr() });
}

#[test]
fn an_unhandled_le_subevent_keeps_its_subevent_code_and_payload() {
    let ev = decode(HCI_EV_LE_META, &[HCI_EV_LE_ADVERTISING_REPORT, 1, 2]).unwrap();
    assert_eq!(ev, Event::LeMeta { subevent: HCI_EV_LE_ADVERTISING_REPORT,
        params: alloc::vec![1, 2] });
}

#[test]
fn a_connection_completion_adds_an_established_link() {
    let mut d = dev();
    let ev = Event::ConnComplete { status: 0, handle: 0x2a, addr: addr(),
        link_type: ACL_LINK, encrypted: false };
    assert_eq!(apply(&mut d, &ev, 0), Effect::LinkUp { handle: 0x2a });
    let c = d.conns.by_handle(0x2a).unwrap();
    assert_eq!(c.state, BT_CONNECTED);
    assert_eq!(c.peer.addr_type, crate::uapi::bt::BDADDR_BREDR);
}

// A failed connection attempt must add nothing: a link that never formed in a
// table is a handle every later lookup can hit.
#[test]
fn a_failed_connection_completion_adds_no_link() {
    let mut d = dev();
    let ev = Event::ConnComplete { status: HCI_ERROR_CONNECTION_TIMEOUT, handle: 0x2a,
        addr: addr(), link_type: ACL_LINK, encrypted: false };
    assert_eq!(apply(&mut d, &ev, 0), Effect::None);
    assert!(d.conns.is_empty());
}

#[test]
fn a_failed_le_connection_completion_adds_no_link() {
    let mut d = dev();
    let ev = Event::LeConnComplete { status: HCI_ERROR_UNKNOWN_CONN_ID, handle: 1,
        addr_type: BDADDR_LE_RANDOM, addr: addr() };
    assert_eq!(apply(&mut d, &ev, 0), Effect::None);
    assert!(d.conns.is_empty());
}

// A failed disconnection means the controller did NOT tear the link down.
// Dropping the entry would lose a live link from the table.
#[test]
fn a_failed_disconnection_leaves_the_link_in_place() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: false }, 0);
    let ev = Event::DisconnComplete { status: HCI_ERROR_COMMAND_DISALLOWED, handle: 5, reason: 0 };
    assert_eq!(apply(&mut d, &ev, 0), Effect::None);
    assert!(d.conns.by_handle(5).is_some());
}

#[test]
fn a_successful_disconnection_removes_the_link_and_reports_the_reason() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: false }, 0);
    let ev = Event::DisconnComplete { status: 0, handle: 5,
        reason: HCI_ERROR_REMOTE_USER_TERM };
    assert_eq!(apply(&mut d, &ev, 0),
        Effect::LinkDown { handle: 5, reason: HCI_ERROR_REMOTE_USER_TERM });
    assert!(d.conns.by_handle(5).is_none());
}

// Encryption turning off must drop the key size with it: a stale size would
// let a level check pass on an unprotected link.
#[test]
fn encryption_turning_off_clears_the_key_size() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: false }, 0);
    d.conns.by_handle_mut(5).unwrap().enc_key_size = 16;
    apply(&mut d, &Event::EncryptChange { status: 0, handle: 5, encrypted: true }, 0);
    assert!(d.conns.by_handle(5).unwrap().encrypted);
    apply(&mut d, &Event::EncryptChange { status: 0, handle: 5, encrypted: false }, 0);
    let c = d.conns.by_handle(5).unwrap();
    assert!(!c.encrypted);
    assert_eq!(c.enc_key_size, 0);
}

// A failed encryption change reports nothing about the link's state, so it must
// not be taken as a change.
#[test]
fn a_failed_encryption_change_leaves_the_state_alone() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: true }, 0);
    apply(&mut d, &Event::EncryptChange { status: HCI_ERROR_AUTH_FAILURE, handle: 5,
        encrypted: false }, 0);
    assert!(d.conns.by_handle(5).unwrap().encrypted);
}

#[test]
fn a_failed_authentication_marks_the_link_unauthenticated() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: false }, 0);
    apply(&mut d, &Event::AuthComplete { status: 0, handle: 5 }, 0);
    assert!(d.conns.by_handle(5).unwrap().authenticated);
    apply(&mut d, &Event::AuthComplete { status: HCI_ERROR_AUTH_FAILURE, handle: 5 }, 0);
    assert!(!d.conns.by_handle(5).unwrap().authenticated);
}

#[test]
fn completed_packets_credit_the_links_they_name_and_ignore_unknown_handles() {
    let mut d = dev();
    apply(&mut d, &Event::ConnComplete { status: 0, handle: 5, addr: addr(),
        link_type: ACL_LINK, encrypted: false }, 0);
    apply(&mut d, &Event::NumCompPkts { entries: alloc::vec![(5, 3), (99, 7)] }, 0);
    assert_eq!(d.conns.by_handle(5).unwrap().tx_credits, 3);
}

#[test]
fn a_command_answer_releases_the_credit_and_reports_the_opcode_and_status() {
    let mut d = dev();
    d.cmd.enqueue(HCI_OP_RESET, alloc::vec::Vec::new());
    d.cmd.dequeue(0);
    let ev = Event::CmdComplete { ncmd: 1, opcode: HCI_OP_RESET, params: alloc::vec![HCI_SUCCESS] };
    assert_eq!(apply(&mut d, &ev, 10),
        Effect::CommandAnswered { opcode: HCI_OP_RESET, status: HCI_SUCCESS, params: alloc::vec![] });
    assert_eq!(d.cmd.credits(), 1);
    assert_eq!(d.cmd.in_flight(), None);
}

// A complete with no parameters at all carries no status byte and is a success.
#[test]
fn a_parameterless_completion_reads_as_success() {
    assert_eq!(complete_status(&[]), HCI_SUCCESS);
    assert_eq!(complete_status(&[HCI_ERROR_UNSPECIFIED]), HCI_ERROR_UNSPECIFIED);
}

#[test]
fn a_hardware_error_asks_for_the_controller_to_be_taken_down() {
    let mut d = dev();
    assert_eq!(apply(&mut d, &Event::HardwareError { code: 0x03 }, 0),
        Effect::ControllerFailed { code: 0x03 });
}

#[test]
fn every_applied_event_counts_toward_the_receive_statistic() {
    let mut d = dev();
    for _ in 0..4 { apply(&mut d, &Event::Other { code: 0x77, params: alloc::vec![] }, 0); }
    assert_eq!(d.stats.evt_rx, 4);
}

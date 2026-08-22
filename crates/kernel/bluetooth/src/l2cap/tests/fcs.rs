//! CRC-16 framing at the sequence-numbered L2CAP wire boundary.

use super::super::*;
use alloc::vec;
use alloc::vec::Vec;
use crate::uapi::bt::BT_CONNECTED;
use crate::uapi::l2cap as u;

fn chan() -> Channel {
    let mut c = Channel::new();
    c.state = BT_CONNECTED;
    c.mode = u::MODE_ERTM;
    c.ertm_init();
    c
}

#[test]
fn crc16_is_appended_over_header_control_and_payload() {
    let c = chan();
    let frame = ertm_tx::OutFrame { ctrl: Ctrl::iframe(3, u::SAR_UNSEGMENTED, 2), body: vec![7, 8, 9] };
    let wire = fcs::encode(0x0042, &c, &frame).unwrap();
    assert_eq!(wire.len(), u::HDR_SIZE + u::ENH_CTRL_SIZE + 3 + u::FCS_SIZE);
    let (cid, ctrl, body) = fcs::decode(&c, &wire).unwrap();
    assert_eq!(cid, 0x0042);
    assert_eq!(ctrl, frame.ctrl);
    assert_eq!(body, &frame.body[..]);
}

#[test]
fn a_corrupted_fcs_is_refused_before_delivery() {
    let c = chan();
    let frame = ertm_tx::OutFrame { ctrl: Ctrl::sframe(u::SUPER_RR, 0), body: Vec::new() };
    let mut wire = fcs::encode(7, &c, &frame).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    assert!(fcs::decode(&c, &wire).is_none());
}

#[test]
fn no_fcs_configuration_does_not_add_or_require_a_checksum() {
    let mut c = chan();
    c.fcs = u::FCS_NONE;
    let frame = ertm_tx::OutFrame { ctrl: Ctrl::iframe(0, u::SAR_UNSEGMENTED, 0), body: vec![1, 2] };
    let wire = fcs::encode(1, &c, &frame).unwrap();
    assert_eq!(wire.len(), u::HDR_SIZE + u::ENH_CTRL_SIZE + 2);
    assert_eq!(fcs::decode(&c, &wire).unwrap().2, &frame.body[..]);
}

#[test]
fn extended_control_fcs_covers_the_four_byte_control_field() {
    let mut c = chan();
    c.flags |= chan::FLAG_EXT_CTRL;
    let frame = ertm_tx::OutFrame { ctrl: Ctrl::sframe(u::SUPER_RNR, 4), body: vec![0xaa] };
    let wire = fcs::encode(2, &c, &frame).unwrap();
    assert_eq!(wire.len(), u::HDR_SIZE + u::EXT_CTRL_SIZE + 1 + u::FCS_SIZE);
    assert_eq!(fcs::decode(&c, &wire).unwrap().1, frame.ctrl);
}

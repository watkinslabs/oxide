//! Framing and the two reply shapes.

use super::*;
use crate::uapi::mgmt::limits::MGMT_INDEX_NONE;
use crate::uapi::mgmt::op::{MGMT_OP_READ_VERSION, MGMT_OP_SET_POWERED};
use crate::uapi::mgmt::status::{MGMT_STATUS_PERMISSION_DENIED, MGMT_STATUS_SUCCESS};

#[test]
fn a_header_is_six_little_endian_bytes() {
    let h = MgmtHdr::new(0x0102, 0x0304, 0x0506);
    assert_eq!(h.encode(), alloc::vec![0x02, 0x01, 0x04, 0x03, 0x06, 0x05]);
    assert_eq!(MgmtHdr::decode(&h.encode()), Some(h));
    assert_eq!(h.encode().len(), MGMT_HDR_SIZE);
}

#[test]
fn a_short_header_decodes_to_nothing() {
    for n in 0..MGMT_HDR_SIZE {
        assert_eq!(MgmtHdr::decode(&alloc::vec![0u8; n]), None, "len {n}");
    }
}

#[test]
fn split_refuses_a_length_that_disagrees() {
    let good = frame(MGMT_OP_SET_POWERED, 0, &[1]);
    let (h, body) = split(&good).expect("well formed");
    assert_eq!(h.opcode, MGMT_OP_SET_POWERED);
    assert_eq!(body, &[1]);

    let mut long = good.clone();
    long.push(0xff);
    assert!(split(&long).is_none(), "a trailing byte is a disagreement");

    let short = &good[..good.len() - 1];
    assert!(split(short).is_none());
}

/// A command complete is an EVENT: its header opcode is the event code, and the
/// command it answers is the first field of the payload.
#[test]
fn a_command_complete_carries_the_event_code_in_the_header() {
    let msg = cmd_complete(0x0007, MGMT_OP_READ_VERSION, MGMT_STATUS_SUCCESS, &[1, 23, 0]);
    let (h, body) = split(&msg).expect("well formed");
    assert_eq!(h.opcode, MGMT_EV_CMD_COMPLETE);
    assert_eq!(h.index, 0x0007);
    assert_eq!(h.len as usize, body.len());
    let (op, status, data) = parse_cmd_complete(body).expect("payload");
    assert_eq!(op, MGMT_OP_READ_VERSION);
    assert_eq!(status, MGMT_STATUS_SUCCESS);
    assert_eq!(data, &[1, 23, 0]);
}

#[test]
fn a_command_status_is_exactly_three_payload_bytes() {
    let msg = cmd_status(0xffff, MGMT_OP_SET_POWERED, MGMT_STATUS_PERMISSION_DENIED);
    let (h, body) = split(&msg).expect("well formed");
    assert_eq!(h.opcode, MGMT_EV_CMD_STATUS);
    assert_eq!(body.len(), 3);
    assert_eq!(parse_cmd_status(body), Some((MGMT_OP_SET_POWERED, MGMT_STATUS_PERMISSION_DENIED)));
}

#[test]
fn a_command_status_payload_refuses_extra_bytes() {
    assert_eq!(parse_cmd_status(&[0x05, 0x00, 0x00, 0x00]), None);
    assert_eq!(parse_cmd_status(&[0x05, 0x00]), None);
}

#[test]
fn an_empty_payload_frames_with_a_zero_length() {
    let msg = frame(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[]);
    assert_eq!(msg.len(), MGMT_HDR_SIZE);
    let (h, body) = split(&msg).expect("well formed");
    assert_eq!(h.len, 0);
    assert!(body.is_empty());
}

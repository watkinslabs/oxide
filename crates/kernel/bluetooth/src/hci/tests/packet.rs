use super::*;
use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_COMMAND_PKT, HCI_EVENT_PKT, HCI_SCODATA_PKT};

// A command frame: prefix, little-endian opcode, one length byte, then body.
#[test]
fn command_frame_round_trips() {
    let built = build_frame(HCI_COMMAND_PKT, 0x0c03, &[]).unwrap();
    assert_eq!(built, alloc::vec![0x01, 0x03, 0x0c, 0x00]);
    let f = parse_frame(&built).unwrap();
    assert_eq!(f.pkt_type, HCI_COMMAND_PKT);
    assert_eq!(f.head, 0x0c03);
    assert!(f.body.is_empty());
}

// An event frame's header word is the single event-code byte, not a word.
#[test]
fn event_frame_round_trips() {
    let built = build_frame(HCI_EVENT_PKT, 0x0e, &[0x01, 0x03, 0x0c, 0x00]).unwrap();
    assert_eq!(built, alloc::vec![0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]);
    let f = parse_frame(&built).unwrap();
    assert_eq!((f.pkt_type, f.head), (HCI_EVENT_PKT, 0x0e));
    assert_eq!(f.body, alloc::vec![0x01, 0x03, 0x0c, 0x00]);
}

// ACL declares its length in two bytes, so a body over 255 is representable
// where a command's would not be.
#[test]
fn acl_frame_carries_a_sixteen_bit_length() {
    let body = alloc::vec![0xAB; 300];
    let built = build_frame(HCI_ACLDATA_PKT, crate::uapi::hci::acl_pack(0x2a, crate::uapi::hci::ACL_START), &body).unwrap();
    assert_eq!(&built[3..5], &[0x2c, 0x01]);
    let f = parse_frame(&built).unwrap();
    let (handle, flags) = crate::uapi::hci::acl_unpack(f.head);
    assert_eq!((handle, flags), (0x2a, crate::uapi::hci::ACL_START));
    assert_eq!(f.body.len(), 300);
}

#[test]
fn command_body_over_the_single_length_byte_is_refused() {
    assert!(build_frame(HCI_COMMAND_PKT, 0x0c03, &alloc::vec![0u8; 256]).is_none());
}

// A frame carrying fewer bytes than its header declares must NOT parse: a short
// read that produced a valid short frame would hand the dispatcher a payload
// the controller never sent.
#[test]
fn a_short_body_is_refused_rather_than_truncated() {
    let mut bytes = build_frame(HCI_EVENT_PKT, 0x0e, &[1, 2, 3, 4]).unwrap();
    bytes.pop();
    assert!(parse_frame(&bytes).is_none());
}

#[test]
fn a_long_body_is_refused_rather_than_trimmed() {
    let mut bytes = build_frame(HCI_EVENT_PKT, 0x0e, &[1, 2, 3, 4]).unwrap();
    bytes.push(0xff);
    assert!(parse_frame(&bytes).is_none());
}

#[test]
fn an_unknown_packet_type_has_no_header_width() {
    assert!(header_len(0x77).is_none());
    assert!(parse_frame(&[0x77, 0, 0, 0]).is_none());
}

#[test]
fn header_widths_match_each_packet_type() {
    assert_eq!(header_len(HCI_COMMAND_PKT), Some(3));
    assert_eq!(header_len(HCI_EVENT_PKT), Some(2));
    assert_eq!(header_len(HCI_ACLDATA_PKT), Some(4));
    assert_eq!(header_len(HCI_SCODATA_PKT), Some(3));
}

// The decoder must reassemble a frame that arrived split across reads, and must
// yield it exactly once.
#[test]
fn decoder_reassembles_a_frame_split_one_byte_at_a_time() {
    let frame = build_frame(HCI_EVENT_PKT, 0x0e, &[0x01, 0x03, 0x0c, 0x00]).unwrap();
    let mut d = H4Decoder::new();
    let mut got = alloc::vec::Vec::new();
    for b in &frame { got.extend(d.feed(&[*b])); }
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], parse_frame(&frame).unwrap());
}

#[test]
fn decoder_yields_two_frames_from_one_read() {
    let a = build_frame(HCI_EVENT_PKT, 0x0e, &[1]).unwrap();
    let b = build_frame(HCI_COMMAND_PKT, 0x0c03, &[]).unwrap();
    let mut both = a.clone(); both.extend_from_slice(&b);
    let mut d = H4Decoder::new();
    let got = d.feed(&both);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].pkt_type, HCI_EVENT_PKT);
    assert_eq!(got[1].pkt_type, HCI_COMMAND_PKT);
}

// A zero-length body completes the frame at the header, with no body wait.
#[test]
fn decoder_completes_an_empty_body_at_the_header() {
    let mut d = H4Decoder::new();
    let got = d.feed(&[0x01, 0x03, 0x0c, 0x00]);
    assert_eq!(got.len(), 1);
    assert!(got[0].body.is_empty());
}

// There is no framing to resynchronise against, so an unknown type byte is a
// permanent desync rather than a byte to skip.
#[test]
fn decoder_desyncs_on_an_unknown_type_byte_and_stays_desynced() {
    let mut d = H4Decoder::new();
    assert!(d.feed(&[0x77]).is_empty());
    assert!(d.desynced());
    let good = build_frame(HCI_EVENT_PKT, 0x0e, &[1]).unwrap();
    assert!(d.feed(&good).is_empty());
    d.reset();
    assert!(!d.desynced());
    assert_eq!(d.feed(&good).len(), 1);
}

// A corrupt ACL header claiming a body larger than the transport can carry must
// not park the decoder forever waiting for bytes that never arrive.
#[test]
fn decoder_desyncs_on_an_impossible_declared_length() {
    let mut d = H4Decoder::new();
    d.feed(&[0x02, 0x2a, 0x20, 0xff, 0xff]);
    assert!(d.desynced());
}

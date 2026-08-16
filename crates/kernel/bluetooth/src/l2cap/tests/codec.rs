//! Header framing: a declared length must equal the bytes delivered, and a
//! command with no identifier cannot be correlated so is never parsed.

use super::*;

#[test]
fn a_basic_header_round_trips() {
    let h = Hdr { len: 5, cid: 0x0041 };
    let mut w = Writer::new();
    h.encode(&mut w);
    assert_eq!(w.as_slice(), &[0x05, 0x00, 0x41, 0x00]);
    assert_eq!(Hdr::decode(w.as_slice()), Some(h));
}

#[test]
fn a_frame_round_trips_through_its_header() {
    let body = [1u8, 2, 3];
    let f = encode_frame(u::CID_SIGNALING, &body).unwrap();
    assert_eq!(decode_frame(&f), Some((u::CID_SIGNALING, &body[..])));
}

#[test]
fn a_frame_shorter_than_its_declared_length_is_refused() {
    let mut f = encode_frame(0x0040, &[1, 2, 3]).unwrap();
    f.pop();
    assert_eq!(decode_frame(&f), None);
}

#[test]
fn a_frame_longer_than_its_declared_length_is_refused() {
    let mut f = encode_frame(0x0040, &[1, 2, 3]).unwrap();
    f.push(9);
    assert_eq!(decode_frame(&f), None);
}

#[test]
fn a_buffer_shorter_than_a_header_has_no_frame() {
    assert_eq!(decode_frame(&[0, 0, 0]), None);
    assert_eq!(Hdr::decode(&[0, 0, 0]), None);
}

#[test]
fn a_command_round_trips_and_reports_where_the_next_one_starts() {
    let c = encode_cmd(u::CONN_REQ, 7, &[1, 2, 3, 4]).unwrap();
    let s = split_cmd(&c).unwrap();
    assert_eq!(s.hdr, CmdHdr { code: u::CONN_REQ, ident: 7, len: 4 });
    assert_eq!(s.body, &[1, 2, 3, 4]);
    assert_eq!(s.next, c.len());
}

#[test]
fn two_commands_in_one_packet_split_in_order() {
    let mut packet = encode_cmd(u::ECHO_REQ, 1, &[]).unwrap();
    packet.extend_from_slice(&encode_cmd(u::INFO_REQ, 2, &[2, 0]).unwrap());
    let first = split_cmd(&packet).unwrap();
    assert_eq!(first.hdr.code, u::ECHO_REQ);
    let second = split_cmd(&packet[first.next..]).unwrap();
    assert_eq!(second.hdr.code, u::INFO_REQ);
    assert_eq!(second.body, &[2, 0]);
}

#[test]
fn a_command_declaring_more_than_the_packet_holds_is_refused() {
    let mut c = encode_cmd(u::CONN_REQ, 7, &[1, 2, 3, 4]).unwrap();
    c[2] = 0xff;
    assert!(split_cmd(&c).is_none());
}

#[test]
fn a_command_with_no_identifier_is_refused() {
    let c = encode_cmd(u::CONN_REQ, 0, &[1, 2, 3, 4]).unwrap();
    assert!(split_cmd(&c).is_none());
}

#[test]
fn a_reader_never_consumes_past_the_end() {
    let mut r = Reader::new(&[1, 2, 3]);
    assert_eq!(r.le16(), Some(0x0201));
    assert_eq!(r.le16(), None);
    assert_eq!(r.remaining(), 1);
    assert_eq!(r.u8(), Some(3));
    assert!(r.is_empty());
    assert_eq!(r.u8(), None);
}

#[test]
fn the_writer_lays_words_out_least_significant_byte_first() {
    let mut w = Writer::new();
    w.le32(0x0403_0201);
    assert_eq!(w.as_slice(), &[1, 2, 3, 4]);
}

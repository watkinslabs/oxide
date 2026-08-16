//! Configuration framing and the option list, including the hint bit and an
//! option that declares more bytes than the list holds.

use super::*;
use alloc::vec;

#[test]
fn an_option_list_round_trips() {
    let opts = vec![
        RawOpt::le16(u::CONF_MTU, 1000),
        RawOpt::byte(u::CONF_FCS, u::FCS_NONE),
        Rfc { mode: u::MODE_ERTM, txwin_size: 63, max_transmit: 3, retrans_timeout: 2000, monitor_timeout: 12000, max_pdu_size: 1000 }.opt(),
    ];
    let buf = encode_opts(&opts).unwrap();
    let p = parse_opts(&buf);
    assert!(!p.truncated);
    assert_eq!(p.opts, opts);
}

#[test]
fn the_hint_bit_is_split_off_the_type_and_carried_separately() {
    let mut buf = encode_opts(&[RawOpt::le16(u::CONF_MTU, 48)]).unwrap();
    buf[0] |= u::CONF_HINT;
    let p = parse_opts(&buf);
    assert_eq!(p.opts.len(), 1);
    assert_eq!(p.opts[0].otype, u::CONF_MTU);
    assert!(p.opts[0].hint);
    // Re-encoding puts the bit back where it was.
    assert_eq!(encode_opts(&p.opts).unwrap(), buf);
}

#[test]
fn an_option_declaring_more_than_the_list_holds_stops_the_walk() {
    let mut buf = encode_opts(&[RawOpt::le16(u::CONF_MTU, 48), RawOpt::le16(u::CONF_FLUSH_TO, 100)]).unwrap();
    let last = buf.len() - 3;
    buf[last] = 0x40;
    let p = parse_opts(&buf);
    assert!(p.truncated);
    assert_eq!(p.opts.len(), 1);
    assert_eq!(p.opts[0].otype, u::CONF_MTU);
}

#[test]
fn a_trailing_fragment_shorter_than_an_option_header_ends_the_list() {
    let mut buf = encode_opts(&[RawOpt::le16(u::CONF_MTU, 48)]).unwrap();
    buf.push(u::CONF_FCS);
    let p = parse_opts(&buf);
    assert!(!p.truncated);
    assert_eq!(p.opts.len(), 1);
}

#[test]
fn an_option_value_past_the_largest_permitted_is_refused_when_encoding() {
    let big = RawOpt { otype: u::CONF_QOS, hint: false, val: vec![0; u::CONF_MAX_SIZE + 1] };
    assert!(encode_opts(&[big]).is_none());
    let ok = RawOpt { otype: u::CONF_QOS, hint: false, val: vec![0; u::CONF_MAX_SIZE] };
    assert!(encode_opts(&[ok]).is_some());
}

#[test]
fn a_value_of_the_wrong_width_reads_as_nothing() {
    let o = RawOpt { otype: u::CONF_MTU, hint: false, val: vec![1] };
    assert_eq!(o.as_le16(), None);
    assert_eq!(o.as_byte(), Some(1));
    let o2 = RawOpt::le16(u::CONF_MTU, 300);
    assert_eq!(o2.as_le16(), Some(300));
    assert_eq!(o2.as_byte(), None);
    assert_eq!(o2.wire_len(), u::CONF_OPT_SIZE + u::CONF_MTU_LEN);
}

#[test]
fn the_retransmission_option_round_trips_at_its_declared_width() {
    let r = Rfc { mode: u::MODE_STREAMING, txwin_size: 10, max_transmit: 4, retrans_timeout: 1, monitor_timeout: 2, max_pdu_size: 3 };
    let v = r.encode();
    assert_eq!(v.len(), u::CONF_RFC_LEN);
    assert_eq!(Rfc::decode(&v), Some(r));
    assert!(Rfc::decode(&v[..v.len() - 1]).is_none());
    assert_eq!(Rfc::basic().mode, u::MODE_BASIC);
}

#[test]
fn the_flow_specification_round_trips_at_its_declared_width() {
    let e = Efs { id: 1, stype: u::SERV_BESTEFFORT, msdu: 600, sdu_itime: 7, acc_lat: 8, flush_to: 9 };
    let v = e.encode();
    assert_eq!(v.len(), u::CONF_EFS_LEN);
    assert_eq!(Efs::decode(&v), Some(e));
    assert!(Efs::decode(&v[..v.len() - 1]).is_none());
    assert_eq!(e.opt().otype, u::CONF_EFS);
}

#[test]
fn a_configuration_request_round_trips_with_its_options() {
    let opts = encode_opts(&[RawOpt::le16(u::CONF_MTU, 672)]).unwrap();
    let q = ConfReq { dcid: 0x0041, flags: u::CONF_FLAG_CONTINUATION, opts };
    let back = ConfReq::decode(&q.encode()).unwrap();
    assert_eq!(back, q);
    assert!(back.more());
    assert!(ConfReq::decode(&[0, 0, 0]).is_none());
}

#[test]
fn a_configuration_response_round_trips_with_its_verdict() {
    let s = ConfRsp { scid: 0x0040, flags: 0, result: u::CONF_UNACCEPT, opts: alloc::vec::Vec::new() };
    let back = ConfRsp::decode(&s.encode()).unwrap();
    assert_eq!(back, s);
    assert!(!back.more());
    assert!(ConfRsp::decode(&[0, 0, 0, 0, 0]).is_none());
}

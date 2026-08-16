// 802.11 header width, addressing under the DS bits, and frame construction.
//
// Provenance: the widths and address maps encoded here are the ones a real
// capture shows, checked against the standard's frame-format clause. The
// round-trip tests are what make the builders and the parser inverse.

use crate::ieee80211::build;
use crate::ieee80211::fctl::{self, ctl_stype, data_stype, mgmt_stype};
use crate::ieee80211::hdr::{hdrlen, MacAddr, MacHeader};
use crate::ieee80211::mgmt;

const A: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
const B: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
const C: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);
const D: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x04]);

#[test]
fn header_width_follows_the_frame_type() {
    // A plain three-address data frame.
    assert_eq!(hdrlen(fctl::FTYPE_DATA), 24);
    // Four addresses add six bytes.
    assert_eq!(hdrlen(fctl::FTYPE_DATA | fctl::FCTL_TODS | fctl::FCTL_FROMDS), 30);
    // A quality-of-service data frame adds the two-byte control field.
    assert_eq!(hdrlen(fctl::FTYPE_DATA | data_stype::QOS_DATA), 26);
    // With the order bit it also carries the four-byte high-throughput field.
    assert_eq!(hdrlen(fctl::FTYPE_DATA | data_stype::QOS_DATA | fctl::FCTL_ORDER), 30);
    // Four addresses and quality of service together.
    assert_eq!(hdrlen(fctl::FTYPE_DATA | fctl::FCTL_TODS | fctl::FCTL_FROMDS
                      | data_stype::QOS_DATA), 32);
    // Management is three addresses, and grows only for the order bit.
    assert_eq!(hdrlen(fctl::FTYPE_MGMT | mgmt_stype::BEACON), 24);
    assert_eq!(hdrlen(fctl::FTYPE_MGMT | mgmt_stype::BEACON | fctl::FCTL_ORDER), 28);
    // Acknowledgement and clear-to-send are the two short control frames.
    assert_eq!(hdrlen(fctl::FTYPE_CTL | ctl_stype::ACK), 10);
    assert_eq!(hdrlen(fctl::FTYPE_CTL | ctl_stype::CTS), 10);
    assert_eq!(hdrlen(fctl::FTYPE_CTL | ctl_stype::RTS), 16);
    assert_eq!(hdrlen(fctl::FTYPE_CTL | ctl_stype::BACK), 16);
    // An extension frame has a four-byte header and no addressing.
    assert_eq!(hdrlen(fctl::FTYPE_EXT), 4);
}

/// Build a bare data header with chosen DS bits and four addresses.
fn data_frame(tods: bool, fromds: bool) -> alloc::vec::Vec<u8> {
    let mut fc = fctl::FTYPE_DATA;
    if tods { fc |= fctl::FCTL_TODS; }
    if fromds { fc |= fctl::FCTL_FROMDS; }
    let mut out = alloc::vec::Vec::new();
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&A.0);
    out.extend_from_slice(&B.0);
    out.extend_from_slice(&C.0);
    out.extend_from_slice(&0u16.to_le_bytes());
    if tods && fromds { out.extend_from_slice(&D.0); }
    out
}

#[test]
fn ds_bits_select_which_address_means_what() {
    // Neither bit: independent network. Destination, source, network id.
    let h = MacHeader::parse(&data_frame(false, false)).unwrap();
    assert_eq!(h.destination(), Some(A));
    assert_eq!(h.source(), Some(B));
    assert_eq!(h.bssid(), Some(C));

    // From the distribution system: destination, network id, source.
    let h = MacHeader::parse(&data_frame(false, true)).unwrap();
    assert_eq!(h.destination(), Some(A));
    assert_eq!(h.bssid(), Some(B));
    assert_eq!(h.source(), Some(C));

    // To the distribution system: network id, source, destination.
    let h = MacHeader::parse(&data_frame(true, false)).unwrap();
    assert_eq!(h.bssid(), Some(A));
    assert_eq!(h.source(), Some(B));
    assert_eq!(h.destination(), Some(C));

    // Both: receiver, transmitter, destination, source — and no single
    // network id, because the frame belongs to no one network.
    let h = MacHeader::parse(&data_frame(true, true)).unwrap();
    assert_eq!(h.receiver(), A);
    assert_eq!(h.transmitter(), Some(B));
    assert_eq!(h.destination(), Some(C));
    assert_eq!(h.source(), Some(D));
    assert_eq!(h.bssid(), None);
}

#[test]
fn a_frame_shorter_than_its_own_header_is_refused() {
    let full = data_frame(true, true);
    for cut in 0..full.len() {
        assert!(MacHeader::parse(&full[..cut]).is_none(),
            "a {cut}-byte four-address frame must not parse");
    }
    assert!(MacHeader::parse(&full).is_some());
}

#[test]
fn sequence_control_round_trips() {
    for sn in [0u16, 1, 2047, 4094, 4095] {
        for frag in 0u16..16 {
            let seq = fctl::sn_to_seq(sn, frag);
            assert_eq!(fctl::seq_to_sn(seq), sn);
            assert_eq!(seq & fctl::SCTL_FRAG, frag);
        }
    }
}

#[test]
fn quality_of_service_fields_are_read_from_the_right_offset() {
    let mut frame = alloc::vec::Vec::new();
    build::data_header_to_ds(&mut frame, C, A, B, Some(6), false);
    let h = MacHeader::parse(&frame).unwrap();
    assert_eq!(h.len, 26);
    assert_eq!(h.tid(), 6);
    assert_eq!(h.bssid(), Some(C));
    assert_eq!(h.source(), Some(A));
    assert_eq!(h.destination(), Some(B));

    // The same on a four-address frame, where the field sits six bytes later.
    let mut frame = alloc::vec::Vec::new();
    let fc = fctl::FTYPE_DATA | fctl::FCTL_TODS | fctl::FCTL_FROMDS | data_stype::QOS_DATA;
    frame.extend_from_slice(&fc.to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes());
    for a in [A, B, C] { frame.extend_from_slice(&a.0); }
    frame.extend_from_slice(&0u16.to_le_bytes());
    frame.extend_from_slice(&D.0);
    frame.extend_from_slice(&5u16.to_le_bytes());
    let h = MacHeader::parse(&frame).unwrap();
    assert_eq!(h.len, 32);
    assert_eq!(h.tid(), 5);
}

#[test]
fn a_frame_with_no_quality_of_service_is_best_effort() {
    let h = MacHeader::parse(&data_frame(true, false)).unwrap();
    assert_eq!(h.tid(), 0);
    assert!(!h.is_amsdu());
    assert!(!h.is_blockack_policy());
}

#[test]
fn built_management_frames_parse_back() {
    let auth = build::auth(A, B, B, mgmt::auth_alg::OPEN, 1, 0, &[]);
    let h = MacHeader::parse(&auth).unwrap();
    assert_eq!(fctl::stype(h.frame_control), mgmt_stype::AUTH);
    assert_eq!(h.destination(), Some(A));
    assert_eq!(h.source(), Some(B));
    let body = mgmt::AuthBody::parse(&auth[h.len..]).unwrap();
    assert_eq!((body.alg, body.transaction, body.status), (mgmt::auth_alg::OPEN, 1, 0));

    let de = build::deauth(A, B, B, crate::ieee80211::status::reason::DEAUTH_LEAVING);
    let h = MacHeader::parse(&de).unwrap();
    assert_eq!(fctl::stype(h.frame_control), mgmt_stype::DEAUTH);
    assert_eq!(mgmt::ReasonBody::parse(&de[h.len..]).unwrap().reason,
               crate::ieee80211::status::reason::DEAUTH_LEAVING);

    let bcn = build::beacon(B, B, 0x0102_0304_0506_0708, 100, 0x0431, &[]);
    let h = MacHeader::parse(&bcn).unwrap();
    assert!(fctl::is_beacon(h.frame_control));
    let body = mgmt::BeaconBody::parse(&bcn[h.len..]).unwrap();
    assert_eq!(body.timestamp, 0x0102_0304_0506_0708);
    assert_eq!(body.beacon_int, 100);
    assert!(body.privacy());
}

#[test]
fn an_association_identifier_keeps_its_reserved_bits_off_the_air_only() {
    let resp = build::assoc_resp(A, B, B, 0x0421, 0, 7, false, &[]);
    let h = MacHeader::parse(&resp).unwrap();
    let body = mgmt::AssocRespBody::parse(&resp[h.len..]).unwrap();
    // The two top bits are set in the transmitted field and are not part of
    // the identifier a caller reads back.
    assert_eq!(body.aid, 7);
    let raw = u16::from_le_bytes([resp[h.len + 4], resp[h.len + 5]]);
    assert_eq!(raw & !mgmt::AID_MASK, !mgmt::AID_MASK);
}

#[test]
fn a_reassociation_request_carries_the_previous_network_and_a_plain_one_does_not() {
    let plain = build::assoc_req(B, A, 0x0431, 10, None, &[0x00, 0x02, b'h', b'i']);
    let h = MacHeader::parse(&plain).unwrap();
    assert_eq!(fctl::stype(h.frame_control), mgmt_stype::ASSOC_REQ);
    let body = mgmt::AssocReqBody::parse(&plain[h.len..], false).unwrap();
    assert_eq!(body.listen_interval, 10);
    assert_eq!(body.current_ap, None);
    assert_eq!(body.elements, &[0x00, 0x02, b'h', b'i']);

    let re = build::assoc_req(B, A, 0x0431, 10, Some(C), &[]);
    let h = MacHeader::parse(&re).unwrap();
    assert_eq!(fctl::stype(h.frame_control), mgmt_stype::REASSOC_REQ);
    let body = mgmt::AssocReqBody::parse(&re[h.len..], true).unwrap();
    assert_eq!(body.current_ap, Some(C));
}

#[test]
fn block_ack_parameters_round_trip_and_the_two_identifier_fields_differ() {
    use mgmt::ba_params;
    for tid in 0u8..16 {
        for buf in [1u16, 16, 64, 1023] {
            let p = ba_params::build(tid, buf, false, true);
            assert_eq!(ba_params::tid(p), tid);
            assert_eq!(ba_params::buf_size(p), buf);
            assert!(p & ba_params::POLICY != 0);
            assert!(p & ba_params::AMSDU == 0);
        }
    }
    // The teardown frame carries its identifier in a different field, so a
    // reader that used the setup accessor would read the wrong four bits.
    let frame = build::delba(A, B, B, 5, true, 39);
    let h = MacHeader::parse(&frame).unwrap();
    let body = &frame[h.len + 2..];
    let d = mgmt::parse_delba(body).unwrap();
    assert_eq!(ba_params::delba_tid(d.params), 5);
    assert!(d.params & ba_params::DELBA_INITIATOR != 0);
    assert_eq!(d.reason, 39);
    assert_ne!(ba_params::tid(d.params), 5, "the two identifier fields are not the same bits");
}

#[test]
fn an_addba_request_round_trips_its_starting_sequence_number() {
    for ssn in [0u16, 1, 2048, 4095] {
        let params = mgmt::ba_params::build(3, 64, false, true);
        let frame = build::addba_req(A, B, B, 0x11, params, 0, ssn);
        let h = MacHeader::parse(&frame).unwrap();
        let req = mgmt::parse_addba_req(&frame[h.len + 2..]).unwrap();
        assert_eq!(req.start_seq_num, ssn);
        assert_eq!(req.dialog_token, 0x11);
        assert_eq!(mgmt::ba_params::tid(req.params), 3);
    }
}

#[test]
fn the_two_protocols_that_cannot_use_the_common_encapsulation_get_the_other_one() {
    let mut out = alloc::vec::Vec::new();
    build::snap_header(&mut out, 0x0800);
    assert_eq!(&out[..6], &build::RFC1042_HEADER);
    let mut out = alloc::vec::Vec::new();
    build::snap_header(&mut out, 0x8137);
    assert_eq!(&out[..6], &build::BRIDGE_TUNNEL_HEADER);
    let mut out = alloc::vec::Vec::new();
    build::snap_header(&mut out, 0x80f3);
    assert_eq!(&out[..6], &build::BRIDGE_TUNNEL_HEADER);
    // Everything else, including the authentication protocol, uses the common
    // encapsulation.
    let mut out = alloc::vec::Vec::new();
    build::snap_header(&mut out, 0x888e);
    assert_eq!(&out[..6], &build::RFC1042_HEADER);
}

#[test]
fn only_the_robust_management_subtypes_are_protected() {
    let robust = [mgmt_stype::DEAUTH, mgmt_stype::DISASSOC, mgmt_stype::ACTION];
    let plain = [mgmt_stype::BEACON, mgmt_stype::PROBE_REQ, mgmt_stype::PROBE_RESP,
                 mgmt_stype::AUTH, mgmt_stype::ASSOC_REQ, mgmt_stype::ASSOC_RESP,
                 mgmt_stype::REASSOC_REQ, mgmt_stype::REASSOC_RESP];
    for s in robust { assert!(fctl::is_robust_mgmt(fctl::FTYPE_MGMT | s)); }
    for s in plain { assert!(!fctl::is_robust_mgmt(fctl::FTYPE_MGMT | s)); }
    // A data frame is never a robust management frame however it is marked.
    assert!(!fctl::is_robust_mgmt(fctl::FTYPE_DATA | data_stype::QOS_DATA));
}

#[test]
fn address_predicates_agree_with_the_group_bit() {
    assert!(MacAddr::BROADCAST.is_broadcast());
    assert!(MacAddr::BROADCAST.is_multicast());
    assert!(!MacAddr::BROADCAST.is_unicast());
    assert!(MacAddr::ZERO.is_zero());
    assert!(!MacAddr::ZERO.is_unicast());
    assert!(A.is_unicast());
    assert!(A.is_local());
    assert!(MacAddr([0x01, 0, 0, 0, 0, 1]).is_multicast());
    assert!(!MacAddr([0x00, 0, 0, 0, 0, 1]).is_local());
}

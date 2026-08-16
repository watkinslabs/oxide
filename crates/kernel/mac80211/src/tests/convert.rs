// Frame conversion, both ways, over all four address layouts.
//
// The address map has four cases and no sensible default. A conversion that
// assumed one layout addresses frames to the wrong station in three of them,
// and the frames still look well formed.

use alloc::vec;
use alloc::vec::Vec;

use wireless::ieee80211::{build, fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::enums::IfType;

use crate::netdev::convert::{self, EthFrame};
use crate::tests_fixture as f;
use crate::uapi::{ETH_HDR_LEN, ETH_P_AARP, ETH_P_IPX, SNAP_HDR_LEN};

const ETH_P_IP: u16 = 0x0800;
const PAYLOAD: [u8; 6] = [1, 2, 3, 4, 5, 6];

fn snap(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    build::snap_header(&mut out, proto);
    out.extend_from_slice(payload);
    out
}

#[test]
fn a_frame_from_the_distribution_system_takes_its_source_from_the_third_address() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, false);
    let parsed = f::parse(&hdr);
    let eth = convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Station, f::STA)
        .expect("a station accepts a frame from its access point");
    assert_eq!(eth.dst, f::STA);
    assert_eq!(eth.src, f::PEER, "the source is the third address, not the transmitter");
    assert_eq!(eth.proto, ETH_P_IP);
    assert_eq!(eth.payload, PAYLOAD);
}

#[test]
fn a_frame_toward_the_distribution_system_takes_its_destination_from_the_third() {
    let hdr = f::data_hdr_to_ds(f::AP, f::STA, f::PEER, None, false);
    let parsed = f::parse(&hdr);
    let eth = convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Ap, f::AP)
        .expect("an access point accepts a frame from its station");
    assert_eq!(eth.dst, f::PEER);
    assert_eq!(eth.src, f::STA);
}

#[test]
fn a_direct_frame_uses_the_first_two_addresses() {
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&fctl::FTYPE_DATA.to_le_bytes());
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&f::STA.0);
    hdr.extend_from_slice(&f::PEER.0);
    hdr.extend_from_slice(&f::AP.0);
    hdr.extend_from_slice(&0u16.to_le_bytes());
    let parsed = f::parse(&hdr);
    let eth = convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Adhoc, f::STA)
        .expect("an ad-hoc interface accepts a direct frame");
    assert_eq!(eth.dst, f::STA);
    assert_eq!(eth.src, f::PEER);
}

#[test]
fn a_four_address_frame_takes_its_source_from_the_fourth() {
    let mut hdr = Vec::new();
    let fc = fctl::FTYPE_DATA | fctl::FCTL_TODS | fctl::FCTL_FROMDS;
    hdr.extend_from_slice(&fc.to_le_bytes());
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&f::AP.0);      // receiver
    hdr.extend_from_slice(&f::PEER.0);    // transmitter
    hdr.extend_from_slice(&f::STA.0);     // destination
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&f::OTHER.0);   // source
    let parsed = f::parse(&hdr);
    let eth = convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Station, f::AP)
        .expect("a bridged client accepts a four-address frame");
    assert_eq!(eth.dst, f::STA);
    assert_eq!(eth.src, f::OTHER);
}

#[test]
fn each_layout_is_refused_on_an_interface_type_it_cannot_belong_to() {
    // A client accepting a frame travelling toward the distribution system
    // would forward traffic addressed to its own access point.
    assert!(!convert::ds_bits_allowed(IfType::Station, true, false));
    assert!(convert::ds_bits_allowed(IfType::Ap, true, false));
    // An access point accepting one travelling FROM the distribution system
    // would accept a frame another access point sent.
    assert!(!convert::ds_bits_allowed(IfType::Ap, false, true));
    assert!(convert::ds_bits_allowed(IfType::Station, false, true));
    // A monitor is not a member of any of them.
    for (tods, fromds) in [(false, false), (false, true), (true, false), (true, true)] {
        assert!(!convert::ds_bits_allowed(IfType::Monitor, tods, fromds));
    }
}

#[test]
fn a_client_refuses_a_group_frame_it_apparently_sent_itself() {
    // An access point looping a broadcast back is what this looks like, and
    // delivering it would duplicate every broadcast the station sends.
    let hdr = f::data_hdr_from_ds(MacAddr::BROADCAST, f::AP, f::STA, None, false);
    let parsed = f::parse(&hdr);
    assert!(convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Station,
                             f::STA).is_none());
    // From anybody else it is fine.
    assert!(convert::to_8023(&parsed, &snap(ETH_P_IP, &PAYLOAD), IfType::Station,
                             f::OTHER).is_some());
}

#[test]
fn the_bridge_tunnel_encapsulation_is_used_for_the_two_protocols_that_need_it() {
    for proto in [ETH_P_AARP, ETH_P_IPX] {
        assert!(build::needs_bridge_tunnel(proto), "{proto:#06x}");
        let eth = EthFrame { dst: f::STA, src: f::PEER, proto, payload: PAYLOAD.to_vec() };
        let frame = convert::from_8023(&eth, IfType::Ap, f::AP, f::AP, None, false).unwrap();
        let hdr = MacHeader::parse(&frame).unwrap();
        assert_eq!(&frame[hdr.len..hdr.len + 6], &build::BRIDGE_TUNNEL_HEADER);
        // And it comes back as itself.
        let back = convert::to_8023(&hdr, &frame[hdr.len..], IfType::Station, f::STA).unwrap();
        assert_eq!(back.proto, proto);
        assert_eq!(back.payload, PAYLOAD);
    }
}

#[test]
fn those_two_protocols_under_the_ordinary_encapsulation_are_not_unwrapped() {
    // The standard says they must use the other form. A frame that used this
    // one is not unwrapped, because accepting it would accept a frame built
    // the way the standard forbids.
    for proto in [ETH_P_AARP, ETH_P_IPX] {
        let mut body = build::RFC1042_HEADER.to_vec();
        body.extend_from_slice(&proto.to_be_bytes());
        body.extend_from_slice(&PAYLOAD);
        assert_eq!(convert::tunnel_proto(&body), None, "{proto:#06x}");
    }
}

#[test]
fn a_payload_with_no_recognised_encapsulation_reports_its_length() {
    // An 802.3 frame's two-byte field is a length, not a type, and a frame
    // that carried neither must not be given a fabricated EtherType.
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, false);
    let parsed = f::parse(&hdr);
    let body = vec![0u8; 20];
    let eth = convert::to_8023(&parsed, &body, IfType::Station, f::STA).unwrap();
    assert_eq!(eth.proto, 20);
    assert_eq!(eth.payload.len(), 20);
}

#[test]
fn ethernet_to_eight_oh_two_eleven_and_back_is_the_identity() {
    let eth = EthFrame { dst: f::PEER, src: f::STA, proto: ETH_P_IP,
                         payload: PAYLOAD.to_vec() };
    // As a station: toward the distribution system.
    let frame = convert::from_8023(&eth, IfType::Station, f::STA, f::AP, None, false)
        .unwrap();
    let hdr = MacHeader::parse(&frame).unwrap();
    assert_eq!(hdr.frame_control & fctl::FCTL_TODS, fctl::FCTL_TODS);
    assert_eq!(hdr.addr1, f::AP);
    assert_eq!(hdr.addr2, Some(f::STA));
    assert_eq!(hdr.addr3, Some(f::PEER));
    let back = convert::to_8023(&hdr, &frame[hdr.len..], IfType::Ap, f::AP).unwrap();
    assert_eq!(back, eth);
}

#[test]
fn an_access_point_builds_a_frame_from_the_distribution_system() {
    let eth = EthFrame { dst: f::STA, src: f::PEER, proto: ETH_P_IP,
                         payload: PAYLOAD.to_vec() };
    let frame = convert::from_8023(&eth, IfType::Ap, f::AP, f::AP, None, false).unwrap();
    let hdr = MacHeader::parse(&frame).unwrap();
    assert_eq!(hdr.frame_control & fctl::FCTL_FROMDS, fctl::FCTL_FROMDS);
    assert_eq!(hdr.addr1, f::STA);
    assert_eq!(hdr.addr2, Some(f::AP));
    assert_eq!(hdr.addr3, Some(f::PEER));
    let back = convert::to_8023(&hdr, &frame[hdr.len..], IfType::Station, f::STA).unwrap();
    assert_eq!(back, eth);
}

#[test]
fn a_quality_of_service_frame_carries_its_identifier_and_survives_the_round_trip() {
    let eth = EthFrame { dst: f::PEER, src: f::STA, proto: ETH_P_IP,
                         payload: PAYLOAD.to_vec() };
    let frame = convert::from_8023(&eth, IfType::Station, f::STA, f::AP, Some(5), false)
        .unwrap();
    let hdr = MacHeader::parse(&frame).unwrap();
    assert!(fctl::is_data_qos(hdr.frame_control));
    assert_eq!(hdr.tid(), 5);
    let back = convert::to_8023(&hdr, &frame[hdr.len..], IfType::Ap, f::AP).unwrap();
    assert_eq!(back, eth);
}

#[test]
fn the_protected_bit_is_set_when_asked_for() {
    let eth = EthFrame { dst: f::PEER, src: f::STA, proto: ETH_P_IP, payload: vec![] };
    let frame = convert::from_8023(&eth, IfType::Station, f::STA, f::AP, None, true).unwrap();
    assert!(fctl::is_protected(u16::from_le_bytes([frame[0], frame[1]])));
}

#[test]
fn an_interface_type_that_carries_no_data_frames_converts_nothing() {
    let eth = EthFrame { dst: f::PEER, src: f::STA, proto: ETH_P_IP, payload: vec![] };
    assert!(convert::from_8023(&eth, IfType::Monitor, f::STA, f::AP, None, false).is_none());
}

#[test]
fn an_aggregated_frame_splits_into_its_subframes() {
    let mut body = Vec::new();
    let subs = [(f::STA, f::PEER, ETH_P_IP, &[1u8, 2, 3][..]),
                (f::OTHER, f::AP, ETH_P_IP, &[4u8, 5, 6, 7, 8][..])];
    for (i, (dst, src, proto, payload)) in subs.iter().enumerate() {
        let inner = snap(*proto, payload);
        body.extend_from_slice(&dst.0);
        body.extend_from_slice(&src.0);
        body.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        body.extend_from_slice(&inner);
        // Every subframe but the last is padded to a four-byte boundary.
        if i + 1 < subs.len() {
            while body.len() % convert::AMSDU_PAD != 0 { body.push(0); }
        }
    }
    let out = convert::parse_amsdu(&body).expect("the walk completes");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].dst, f::STA);
    assert_eq!(out[0].payload, vec![1, 2, 3]);
    assert_eq!(out[1].dst, f::OTHER);
    assert_eq!(out[1].payload, vec![4, 5, 6, 7, 8]);
}

#[test]
fn an_aggregated_subframe_longer_than_the_buffer_aborts_the_whole_walk() {
    // Continuing would read the next subframe's header out of the middle of
    // this one's payload — an attacker-chosen offset.
    let mut body = Vec::new();
    body.extend_from_slice(&f::STA.0);
    body.extend_from_slice(&f::PEER.0);
    body.extend_from_slice(&9999u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 8]);
    assert!(convert::parse_amsdu(&body).is_none());
}

#[test]
fn an_ethernet_frame_round_trips_through_its_own_bytes() {
    let eth = EthFrame { dst: f::STA, src: f::PEER, proto: ETH_P_IP,
                         payload: PAYLOAD.to_vec() };
    let bytes = eth.to_bytes();
    assert_eq!(bytes.len(), ETH_HDR_LEN + PAYLOAD.len());
    assert_eq!(EthFrame::parse(&bytes), Some(eth));
    assert_eq!(EthFrame::parse(&bytes[..ETH_HDR_LEN - 1]), None);
}

#[test]
fn the_encapsulation_is_the_expected_width() {
    let mut out = Vec::new();
    build::snap_header(&mut out, ETH_P_IP);
    assert_eq!(out.len(), SNAP_HDR_LEN);
}

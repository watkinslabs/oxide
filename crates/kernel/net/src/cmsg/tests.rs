// Hosted coverage for the receive ancillary plan: which message each option
// produces, the ORDER the control buffer carries them in, and the wire layout
// of every payload.

use alloc::vec::Vec;

use super::payload;
use super::*;

const V4: [u8; 4] = [10, 1, 2, 3];
const SRC: [u8; 4] = [198, 51, 100, 9];
const V6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn meta4() -> RxMeta {
    RxMeta { dst: Some((V4, 7)), ttl: Some(64), tos: Some(0x28), dport: 53, src: SRC,
        ..Default::default() }
}

/// One received option area, compiled and filled the way delivery fills it.
fn area(bytes: &[u8]) -> crate::ipv4_options::Compiled {
    crate::ipv4_options::received(bytes, &crate::ipv4_options::NoUnicast,
        crate::addr::Ipv4Addr::new(V4[0], V4[1], V4[2], V4[3]), 0x0102_0304).unwrap()
}

fn meta6() -> RxMeta {
    RxMeta { dst6: Some((V6, 7)), hoplimit: Some(255), tclass: Some(0x28), dport: 5353,
        flowinfo: flowinfo(0x28, 0x1_2345), ..Default::default() }
}

fn kinds(want: &Want, meta: &RxMeta) -> Vec<(i32, i32)> {
    plan(want, meta).iter().map(|m| (m.level, m.kind)).collect()
}

fn all4() -> Want {
    Want { pktinfo: true, ttl: true, tos: true, recvopts: true, retopts: true,
        passsec: true, origdstaddr: true, checksum: true, fragsize: true, ..Default::default() }
}

// ---- nothing asked for, nothing produced --------------------------------

#[test]
fn a_socket_with_no_receive_option_produces_no_message() {
    assert!(plan(&Want::default(), &meta4()).is_empty());
    assert!(plan(&Want::default(), &meta6()).is_empty());
    assert!(!Want::default().any());
    assert!(all4().any());
}

// ---- the IPv4 level ------------------------------------------------------

#[test]
fn the_ipv4_level_is_ordered_by_how_often_it_is_asked_for() {
    let meta = RxMeta {
        options: area(&[7u8, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        frag_max: 1400,
        checksum: Some(0xdead_beef),
        security: Some(Vec::from(b"system_u".as_slice())),
        ..meta4()
    };
    assert_eq!(kinds(&all4(), &meta), alloc::vec![
        (SOL_IP, IP_PKTINFO),
        (SOL_IP, IP_TTL),
        (SOL_IP, IP_TOS),
        (SOL_IP, IP_RECVOPTS),
        (SOL_IP, IP_RETOPTS),
        (SOL_IP, SCM_SECURITY),
        (SOL_IP, IP_ORIGDSTADDR),
        (SOL_IP, IP_CHECKSUM),
        (SOL_IP, IP_RECVFRAGSIZE),
    ]);
}

#[test]
fn the_type_of_service_is_one_byte_where_the_hop_limit_is_an_int() {
    let want = Want { ttl: true, tos: true, ..Default::default() };
    let msgs = plan(&want, &meta4());
    assert_eq!(msgs[0].bytes, Vec::from(64i32.to_ne_bytes()));
    // The one scalar at this level that is NOT `int`-shaped.
    assert_eq!(msgs[1].bytes, alloc::vec![0x28]);
}

#[test]
fn the_packet_info_carries_the_interface_then_the_destination_twice() {
    let want = Want { pktinfo: true, ..Default::default() };
    let msgs = plan(&want, &meta4());
    assert_eq!(msgs[0].bytes, Vec::from(payload::in_pktinfo(V4, 7)));
    assert_eq!(&msgs[0].bytes[..4], &7i32.to_ne_bytes());
    // The chosen source address and the destination are the same answer here.
    assert_eq!(&msgs[0].bytes[4..8], &V4);
    assert_eq!(&msgs[0].bytes[8..12], &V4);
}

#[test]
fn the_original_destination_is_a_socket_address_with_the_port_in_network_order() {
    let want = Want { origdstaddr: true, ..Default::default() };
    let msgs = plan(&want, &meta4());
    assert_eq!(msgs[0].bytes.len(), 16);
    assert_eq!(&msgs[0].bytes[..2], &2u16.to_ne_bytes());
    assert_eq!(&msgs[0].bytes[2..4], &53u16.to_be_bytes());
    assert_eq!(&msgs[0].bytes[4..8], &V4);
    // The padding a caller may compare against zero.
    assert_eq!(&msgs[0].bytes[8..], &[0u8; 8]);
}

#[test]
fn the_absent_values_produce_no_message_rather_than_an_empty_one() {
    // A header with no option area, a datagram that arrived whole, a receive
    // path that computed no checksum, and no module labelling the peer.
    let produced: Vec<i32> = plan(&all4(), &meta4()).iter().map(|m| m.kind).collect();
    assert_eq!(produced, alloc::vec![IP_PKTINFO, IP_TTL, IP_TOS, IP_ORIGDSTADDR]);
}

#[test]
fn a_datagram_that_arrived_whole_reports_no_fragment_size() {
    let want = Want { fragsize: true, ..Default::default() };
    assert!(plan(&want, &meta4()).is_empty());
    let fragmented = RxMeta { frag_max: 1400, ..meta4() };
    assert_eq!(plan(&want, &fragmented)[0].bytes, Vec::from(1400i32.to_ne_bytes()));
}

// ---- the echoed option area ---------------------------------------------
//
// The echo pass itself is `ipv4_options::tests_rx`; what belongs here is which
// message each half of it becomes.

#[test]
fn the_reply_area_and_the_received_area_are_two_messages_from_one_echo() {
    let want = Want { recvopts: true, retopts: true, ..Default::default() };
    let filled = area(&[7u8, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let msgs = plan(&want, &RxMeta { options: filled.clone(), ..meta4() });
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].kind, IP_RECVOPTS);
    assert_eq!(msgs[1].kind, IP_RETOPTS);
    // The record this host made rode back in both.
    assert_eq!(&msgs[0].bytes[3..7], &V4);
    assert_eq!(&msgs[1].bytes[3..7], &V4);
    // The reply names the slot it will fill next; the received area does not.
    assert_eq!(msgs[1].bytes[2], 12);
    assert_eq!(msgs[0].bytes[2], 8);
}

#[test]
fn an_area_with_nothing_worth_echoing_produces_no_message() {
    // A security option is never reflected at its sender, and it is the only
    // option this header carries.
    let want = Want { recvopts: true, retopts: true, ..Default::default() };
    let meta = RxMeta { options: area(&[130u8, 4, 0, 0]), ..meta4() };
    assert!(plan(&want, &meta).is_empty());
}

// ---- the IPv6 level ------------------------------------------------------

#[test]
fn the_modern_personality_leads_and_the_compatibility_one_follows() {
    let want = Want { pktinfo6: true, hoplimit6: true, tclass6: true, flowinfo6: true,
        origdstaddr6: true, fragsize6: true, old_pktinfo6: true, old_hoplimit6: true,
        ..Default::default() };
    let meta = RxMeta { frag_max: 1280, ..meta6() };
    assert_eq!(kinds(&want, &meta), alloc::vec![
        (SOL_IPV6, IPV6_PKTINFO),
        (SOL_IPV6, IPV6_HOPLIMIT),
        (SOL_IPV6, IPV6_TCLASS),
        (SOL_IPV6, IPV6_FLOWINFO),
        (SOL_IPV6, IPV6_2292PKTINFO),
        (SOL_IPV6, IPV6_2292HOPLIMIT),
        (SOL_IPV6, IPV6_ORIGDSTADDR),
        (SOL_IPV6, IPV6_RECVFRAGSIZE),
    ]);
}

#[test]
fn the_two_personalities_are_independent() {
    let modern = Want { pktinfo6: true, ..Default::default() };
    assert_eq!(kinds(&modern, &meta6()), alloc::vec![(SOL_IPV6, IPV6_PKTINFO)]);
    let legacy = Want { old_pktinfo6: true, ..Default::default() };
    assert_eq!(kinds(&legacy, &meta6()), alloc::vec![(SOL_IPV6, IPV6_2292PKTINFO)]);
    // Both carry the same payload under different numbers.
    assert_eq!(plan(&modern, &meta6())[0].bytes, plan(&legacy, &meta6())[0].bytes);
}

#[test]
fn the_flow_info_is_the_traffic_class_and_label_without_the_version() {
    assert_eq!(flowinfo(0x28, 0x1_2345), (0x28 << 20) | 0x1_2345);
    // The label is twenty bits and the whole field twenty-eight.
    assert_eq!(flowinfo(0xff, 0xfff_ffff), 0x0fff_ffff);
    assert_eq!(flowinfo(0, 0), 0);
    // An all-zero field produces no message at all.
    let want = Want { flowinfo6: true, ..Default::default() };
    assert!(plan(&want, &RxMeta { flowinfo: 0, ..meta6() }).is_empty());
    // And it is published in network byte order.
    assert_eq!(plan(&want, &meta6())[0].bytes,
        Vec::from(flowinfo(0x28, 0x1_2345).to_be_bytes()));
}

#[test]
fn the_ipv6_packet_info_is_the_address_then_the_interface() {
    let want = Want { pktinfo6: true, ..Default::default() };
    let msgs = plan(&want, &meta6());
    assert_eq!(msgs[0].bytes.len(), 20);
    assert_eq!(&msgs[0].bytes[..16], &V6);
    assert_eq!(&msgs[0].bytes[16..], &7i32.to_ne_bytes());
}

#[test]
fn the_ipv6_original_destination_carries_the_scope_identifier() {
    let want = Want { origdstaddr6: true, ..Default::default() };
    let meta = RxMeta { scope_id: 9, ..meta6() };
    let msgs = plan(&want, &meta);
    assert_eq!(msgs[0].bytes.len(), 28);
    assert_eq!(&msgs[0].bytes[..2], &10u16.to_ne_bytes());
    assert_eq!(&msgs[0].bytes[2..4], &5353u16.to_be_bytes());
    // The flow-info field of an original-destination answer is zero.
    assert_eq!(&msgs[0].bytes[4..8], &[0u8; 4]);
    assert_eq!(&msgs[0].bytes[8..24], &V6);
    assert_eq!(&msgs[0].bytes[24..], &9u32.to_ne_bytes());
}

// ---- the received extension headers -------------------------------------

fn hdr(kind: u8, tag: u8) -> (u8, Vec<u8>) {
    (kind, alloc::vec![tag, 0, 0, 0, 0, 0, 0, 0])
}

#[test]
fn the_hop_by_hop_header_is_published_before_the_rest() {
    let meta = RxMeta {
        ext_headers: alloc::vec![hdr(NH_HOP_BY_HOP, 1), hdr(NH_DEST_OPTS, 2)],
        ..meta6()
    };
    let want = Want { hopopts6: true, dstopts6: true, ..Default::default() };
    assert_eq!(kinds(&want, &meta),
        alloc::vec![(SOL_IPV6, IPV6_HOPOPTS), (SOL_IPV6, IPV6_DSTOPTS)]);
}

#[test]
fn the_remaining_headers_are_published_in_arrival_order() {
    // A destination-options header on each side of the routing header: the
    // only way a receiver can tell them apart is the order they arrive in.
    let meta = RxMeta {
        ext_headers: alloc::vec![hdr(NH_DEST_OPTS, 1), hdr(NH_ROUTING, 2),
            hdr(NH_DEST_OPTS, 3)],
        ..meta6()
    };
    let want = Want { dstopts6: true, rthdr6: true, ..Default::default() };
    let msgs = plan(&want, &meta);
    assert_eq!(msgs.iter().map(|m| m.kind).collect::<Vec<_>>(),
        alloc::vec![IPV6_DSTOPTS, IPV6_RTHDR, IPV6_DSTOPTS]);
    assert_eq!(msgs[0].bytes[0], 1);
    assert_eq!(msgs[2].bytes[0], 3);
}

#[test]
fn asking_for_one_header_kind_does_not_produce_another() {
    let meta = RxMeta {
        ext_headers: alloc::vec![hdr(NH_HOP_BY_HOP, 1), hdr(NH_ROUTING, 2),
            hdr(NH_DEST_OPTS, 3)],
        ..meta6()
    };
    let want = Want { rthdr6: true, ..Default::default() };
    assert_eq!(kinds(&want, &meta), alloc::vec![(SOL_IPV6, IPV6_RTHDR)]);
    let hop = Want { hopopts6: true, ..Default::default() };
    assert_eq!(kinds(&hop, &meta), alloc::vec![(SOL_IPV6, IPV6_HOPOPTS)]);
}

#[test]
fn the_compatibility_personality_orders_by_routing_header_not_by_arrival() {
    // The compatibility numbers publish the destination-options header BEFORE
    // the routing header, then the routing header, then the one after it.
    let meta = RxMeta {
        ext_headers: alloc::vec![hdr(NH_HOP_BY_HOP, 1), hdr(NH_DEST_OPTS, 2),
            hdr(NH_ROUTING, 3), hdr(NH_DEST_OPTS, 4)],
        ..meta6()
    };
    let want = Want { old_hopopts6: true, old_dstopts6: true, old_rthdr6: true,
        ..Default::default() };
    let msgs = plan(&want, &meta);
    assert_eq!(msgs.iter().map(|m| m.kind).collect::<Vec<_>>(),
        alloc::vec![IPV6_2292HOPOPTS, IPV6_2292DSTOPTS, IPV6_2292RTHDR, IPV6_2292DSTOPTS]);
    assert_eq!(msgs[1].bytes[0], 2);
    assert_eq!(msgs[3].bytes[0], 4);
}

#[test]
fn without_a_routing_header_the_sole_destination_options_is_the_trailing_one() {
    let meta = RxMeta { ext_headers: alloc::vec![hdr(NH_DEST_OPTS, 2)], ..meta6() };
    let want = Want { old_dstopts6: true, ..Default::default() };
    let msgs = plan(&want, &meta);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].kind, IPV6_2292DSTOPTS);
    assert_eq!(msgs[0].bytes[0], 2);
}

#[test]
fn a_datagram_with_no_extension_header_produces_none() {
    let want = Want { hopopts6: true, dstopts6: true, rthdr6: true, old_hopopts6: true,
        old_dstopts6: true, old_rthdr6: true, ..Default::default() };
    assert!(plan(&want, &meta6()).is_empty());
}

// ---- the coalescing segment size ----------------------------------------

#[test]
fn the_segment_size_precedes_the_ip_level_ancillary_data() {
    let meta = RxMeta { gro: Some(1_400), ..meta4() };
    let want = Want { gro: true, pktinfo: true, ttl: true, ..Default::default() };
    assert_eq!(kinds(&want, &meta), alloc::vec![
        (SOL_UDP, UDP_GRO), (SOL_IP, IP_PKTINFO), (SOL_IP, IP_TTL),
    ]);
    // And on the IPv6 family too.
    let meta6 = RxMeta { gro: Some(1_400), ..meta6() };
    let want6 = Want { gro: true, pktinfo6: true, ..Default::default() };
    assert_eq!(kinds(&want6, &meta6), alloc::vec![
        (SOL_UDP, UDP_GRO), (SOL_IPV6, IPV6_PKTINFO),
    ]);
    assert_eq!(plan(&want, &meta)[0].bytes, Vec::from(1_400i32.to_ne_bytes()));
}

#[test]
fn the_segment_size_needs_both_a_coalesced_receive_and_the_option() {
    let coalesced = RxMeta { gro: Some(1_400), ..meta4() };
    let single = RxMeta { gro: None, ..meta4() };
    let on = Want { gro: true, ..Default::default() };
    assert_eq!(kinds(&on, &coalesced), alloc::vec![(SOL_UDP, UDP_GRO)]);
    // A receive of one datagram carries no segment size...
    assert!(plan(&on, &single).is_empty());
    // ...and a socket that turned the option off between delivery and the
    // read is told nothing.
    assert!(plan(&Want::default(), &coalesced).is_empty());
}

// ---- the two levels together --------------------------------------------

#[test]
fn a_dual_stack_socket_publishes_the_ipv4_level_first() {
    let meta = RxMeta { dst: Some((V4, 7)), ttl: Some(64), dst6: Some((V6, 7)),
        hoplimit: Some(255), ..Default::default() };
    let want = Want { ttl: true, pktinfo: true, hoplimit6: true, pktinfo6: true,
        ..Default::default() };
    assert_eq!(kinds(&want, &meta), alloc::vec![
        (SOL_IP, IP_PKTINFO), (SOL_IP, IP_TTL),
        (SOL_IPV6, IPV6_PKTINFO), (SOL_IPV6, IPV6_HOPLIMIT),
    ]);
}

// The verified level-17 ABI contract. Every assertion here is the durable
// record of a behaviour checked against the reference implementation.

use core::sync::atomic::Ordering;

use crate::NetError;
use crate::sock::InetSocket;

use super::cork::{self, CorkAction};
use super::segment::{SegmentPlan, plan_v4, plan_v6};
use super::state::{CorkDest, UdpOpts};
use super::table::{SetEffect, get, set};
use super::uapi::*;

const OPT_UNKNOWN: u64 = 9_999;

// ---- option table ------------------------------------------------------

#[test]
fn level_17_option_numbers_are_the_udp_header_values() {
    assert_eq!(
        (UDP_CORK, UDP_ENCAP, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_SEGMENT, UDP_GRO, SOL_UDP),
        (1, 100, 101, 102, 103, 104, 17));
}

#[test]
fn every_level_17_option_round_trips_its_stored_value() {
    let o = UdpOpts::default();
    for (name, written, expect) in [
        (UDP_CORK, 1, 1), (UDP_CORK, 0, 0),
        (UDP_ENCAP, UDP_ENCAP_L2TPINUDP, UDP_ENCAP_L2TPINUDP),
        (UDP_ENCAP, UDP_ENCAP_ESPINUDP, UDP_ENCAP_ESPINUDP),
        (UDP_ENCAP, UDP_ENCAP_NONE, UDP_ENCAP_NONE),
        (UDP_NO_CHECK6_TX, 1, 1), (UDP_NO_CHECK6_RX, 1, 1),
        (UDP_SEGMENT, 1400, 1400), (UDP_SEGMENT, 0, 0),
        (UDP_GRO, 1, 1),
    ] {
        assert!(set(&o, name, written).is_ok(), "set {name}");
        assert_eq!(get(&o, name), Ok(expect), "get {name}");
    }
}

#[test]
fn boolean_options_normalise_any_nonzero_operand_to_one() {
    let o = UdpOpts::default();
    for name in [UDP_CORK, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_GRO] {
        assert!(set(&o, name, -7).is_ok());
        assert_eq!(get(&o, name), Ok(1), "{name}");
    }
    // UDP_SEGMENT is a size, not a flag: it keeps the exact operand.
    assert!(set(&o, UDP_SEGMENT, 1).is_ok());
    assert_eq!(get(&o, UDP_SEGMENT), Ok(1));
}

#[test]
fn clearing_the_cork_is_the_only_set_with_a_transmit_effect() {
    let o = UdpOpts::default();
    assert_eq!(set(&o, UDP_CORK, 1), Ok(SetEffect::None));
    assert_eq!(set(&o, UDP_CORK, 0), Ok(SetEffect::Push));
    for name in [UDP_ENCAP, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_SEGMENT, UDP_GRO] {
        assert_eq!(set(&o, name, 0), Ok(SetEffect::None), "{name}");
    }
}

#[test]
fn encap_accepts_only_the_three_claimed_identities() {
    let o = UdpOpts::default();
    for accepted in [UDP_ENCAP_NONE, UDP_ENCAP_ESPINUDP, UDP_ENCAP_L2TPINUDP] {
        assert!(set(&o, UDP_ENCAP, accepted).is_ok(), "{accepted}");
    }
    for rejected in [UDP_ENCAP_ESPINUDP_NON_IKE, UDP_ENCAP_GTP0, UDP_ENCAP_GTP1U,
        UDP_ENCAP_RXRPC, TCP_ENCAP_ESPINTCP, UDP_ENCAP_OVPNINUDP, -1, 9]
    {
        assert_eq!(set(&o, UDP_ENCAP, rejected), Err(NetError::Enoprotoopt), "{rejected}");
    }
    // A rejected value leaves the previous identity untouched.
    assert!(set(&o, UDP_ENCAP, UDP_ENCAP_L2TPINUDP).is_ok());
    assert_eq!(set(&o, UDP_ENCAP, UDP_ENCAP_GTP0), Err(NetError::Enoprotoopt));
    assert_eq!(get(&o, UDP_ENCAP), Ok(UDP_ENCAP_L2TPINUDP));
}

#[test]
fn segment_size_window_is_zero_through_ushrt_max() {
    let o = UdpOpts::default();
    assert!(set(&o, UDP_SEGMENT, 0).is_ok());
    assert!(set(&o, UDP_SEGMENT, UDP_SEGMENT_MAX).is_ok());
    assert_eq!(get(&o, UDP_SEGMENT), Ok(65_535));
    assert_eq!(set(&o, UDP_SEGMENT, -1), Err(NetError::Einval));
    assert_eq!(set(&o, UDP_SEGMENT, UDP_SEGMENT_MAX + 1), Err(NetError::Einval));
    // A rejected size leaves the previous one in place.
    assert_eq!(get(&o, UDP_SEGMENT), Ok(65_535));
}

#[test]
fn the_udplite_reservations_are_not_level_17_options() {
    // UDP-Lite's two option numbers are reserved at this level, not handled:
    // neither direction recognises them, exactly like any unknown number.
    let o = UdpOpts::default();
    for name in [UDPLITE_SEND_CSCOV, UDPLITE_RECV_CSCOV, OPT_UNKNOWN, 0, 2, 99, 105] {
        assert_eq!(set(&o, name, 8), Err(NetError::Enoprotoopt), "set {name}");
        assert_eq!(get(&o, name), Err(NetError::Enoprotoopt), "get {name}");
    }
}

#[test]
fn defaults_match_a_freshly_created_udp_socket() {
    let o = UdpOpts::default();
    for name in [UDP_CORK, UDP_ENCAP, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_SEGMENT, UDP_GRO] {
        assert_eq!(get(&o, name), Ok(0), "{name}");
    }
}

// ---- level reachability ------------------------------------------------

#[test]
fn level_17_is_reachable_only_from_a_udp_socket() {
    assert!(super::level_supported(&InetSocket::new_udp()));
    assert!(super::level_supported(&InetSocket::new_udp6()));
    assert!(!super::level_supported(&InetSocket::new_tcp()));
    assert!(!super::level_supported(&InetSocket::new_unix()));
}

// ---- segmentation ------------------------------------------------------

#[test]
fn no_segment_size_means_one_ordinary_datagram() {
    assert_eq!(plan_v4(60_000, 0, 1_500, false), Ok(None));
    assert_eq!(plan_v6(60_000, 0, 1_500, true), Ok(None));
}

#[test]
fn a_payload_within_one_segment_is_not_split() {
    assert_eq!(plan_v4(1_000, 1_400, 1_500, false), Ok(None));
    assert_eq!(plan_v4(1_400, 1_400, 1_500, false), Ok(None));
}

#[test]
fn an_oversized_payload_splits_into_segment_sized_datagrams() {
    assert_eq!(plan_v4(3_000, 1_000, 1_500, false),
        Ok(Some(SegmentPlan { seg_size: 1_000, count: 3 })));
    // The last segment carries the remainder.
    assert_eq!(plan_v4(3_001, 1_000, 1_500, false),
        Ok(Some(SegmentPlan { seg_size: 1_000, count: 4 })));
}

#[test]
fn a_segment_that_cannot_fit_the_path_is_rejected_before_the_split() {
    // 1472 payload + 20 IPv4 + 8 UDP is exactly a 1500 path.
    assert!(plan_v4(1_472, 1_472, 1_500, false).is_ok());
    assert_eq!(plan_v4(1_473, 1_473, 1_500, false), Err(NetError::Emsgsize));
    // IPv6 headers are 20 bytes larger, so the same size no longer fits.
    assert_eq!(plan_v6(1_472, 1_472, 1_500, false), Err(NetError::Emsgsize));
    assert!(plan_v6(1_452, 1_452, 1_500, false).is_ok());
    // The check uses the SEGMENT size, not the whole payload, so a large
    // payload of small segments is fine.
    assert!(plan_v4(60_000, 1_000, 1_500, false).is_ok());
}

#[test]
fn more_segments_than_one_send_may_carry_is_rejected() {
    let seg = 100;
    let max = seg * UDP_MAX_SEGMENTS;
    assert!(plan_v4(max, seg, 1_500, false).is_ok());
    assert_eq!(plan_v4(max + 1, seg, 1_500, false), Err(NetError::Einval));
}

#[test]
fn segmentation_and_checksum_suppression_are_mutually_exclusive() {
    assert_eq!(plan_v6(3_000, 1_000, 1_500, true), Err(NetError::Einval));
    // The rejection fires even when the payload needs no split at all.
    assert_eq!(plan_v6(500, 1_000, 1_500, true), Err(NetError::Einval));
}

#[test]
fn segment_rejection_order_is_path_then_count_then_checksum() {
    // All three conditions hold at once; the path failure is reported.
    assert_eq!(plan_v4(1_000_000, 2_000, 1_500, true), Err(NetError::Emsgsize));
    // Path ok, count and checksum both bad -> count wins.
    assert_eq!(plan_v4(200_000, 100, 1_500, true), Err(NetError::Einval));
}

// ---- cork --------------------------------------------------------------

fn v4_dest(last: u8, port: u16) -> Option<CorkDest> {
    Some(CorkDest::V4 { ip: crate::Ipv4Addr::new(127, 0, 0, last), port })
}

#[test]
fn the_first_append_pins_the_destination_and_later_ones_are_ignored() {
    let sock = InetSocket::new_udp();
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, v4_dest(1, 7), b"ab"), Ok(CorkAction::Held(2)));
    assert_eq!(cork::decide(&sock, v4_dest(2, 9), b"cd"), Ok(CorkAction::Held(2)));
    let pending = sock.opts.udp.pending.lock().clone().unwrap();
    assert_eq!(pending.dest, CorkDest::V4 { ip: crate::Ipv4Addr::new(127, 0, 0, 1), port: 7 });
    assert_eq!(&pending.payload[..], b"abcd");
}

#[test]
fn an_uncorked_socket_never_intercepts() {
    let sock = InetSocket::new_udp();
    assert_eq!(cork::decide(&sock, v4_dest(1, 7), b"ab"), Ok(CorkAction::Passthrough));
    assert!(sock.opts.udp.pending.lock().is_none());
}

#[test]
fn appending_across_address_families_to_a_pinned_cork_is_rejected() {
    let sock = InetSocket::new_udp();
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, v4_dest(1, 7), b"ab"), Ok(CorkAction::Held(2)));
    let v6 = Some(CorkDest::V6 { ip: crate::Ipv6Addr::LOOPBACK, port: 7, scope_id: 0 });
    assert_eq!(cork::decide(&sock, v6, b"cd"), Err(NetError::Einval));
    assert_eq!(&sock.opts.udp.pending.lock().clone().unwrap().payload[..], b"ab");
}

#[test]
fn corking_an_unconnected_socket_with_no_address_needs_a_destination() {
    let sock = InetSocket::new_udp();
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, None, b"ab"), Err(NetError::Edestaddrreq));
    assert!(sock.opts.udp.pending.lock().is_none());
}

#[test]
fn a_connected_socket_pins_its_peer_when_no_address_is_given() {
    let sock = InetSocket::new_udp();
    *sock.peer.lock() = Some((crate::Ipv4Addr::new(127, 0, 0, 5), 4_242));
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, None, b"ab"), Ok(CorkAction::Held(2)));
    assert_eq!(sock.opts.udp.pending.lock().clone().unwrap().dest,
        CorkDest::V4 { ip: crate::Ipv4Addr::new(127, 0, 0, 5), port: 4_242 });
}

#[test]
fn a_connected_v6_socket_pins_its_peer_with_the_recorded_scope() {
    let sock = InetSocket::new_udp6();
    *sock.peer6.lock() = Some((crate::Ipv6Addr::LOOPBACK, 5_353));
    sock.peer6_scope.store(3, Ordering::Release);
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, None, b"ab"), Ok(CorkAction::Held(2)));
    assert_eq!(sock.opts.udp.pending.lock().clone().unwrap().dest,
        CorkDest::V6 { ip: crate::Ipv6Addr::LOOPBACK, port: 5_353, scope_id: 3 });
}

#[test]
fn a_cork_holds_every_byte_until_it_is_pushed() {
    let sock = InetSocket::new_udp();
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    for chunk in [&b"one"[..], b"two", b"three"] {
        assert!(cork::decide(&sock, v4_dest(1, 7), chunk).is_ok());
    }
    assert_eq!(&sock.opts.udp.pending.lock().clone().unwrap().payload[..], b"onetwothree");
    // Nothing has been handed to the transmit path yet.
    assert!(sock.local_port.lock().is_none());
    assert_eq!(&cork::discard(&sock)[..], b"onetwothree");
    assert!(sock.opts.udp.pending.lock().is_none());
}

#[test]
fn a_plain_send_onto_a_corked_socket_appends_and_pushes_the_whole_accumulation() {
    let sock = InetSocket::new_udp();
    assert!(set(&sock.opts.udp, UDP_CORK, 1).is_ok());
    assert_eq!(cork::decide(&sock, v4_dest(1, 7), b"held"), Ok(CorkAction::Held(4)));
    // Clearing the cork alone does not drop the accumulation.
    assert_eq!(set(&sock.opts.udp, UDP_CORK, 0), Ok(SetEffect::Push));
    assert_eq!(&sock.opts.udp.pending.lock().clone().unwrap().payload[..], b"held");
    // The next send appends, then hands the WHOLE accumulation to transmit as
    // one datagram against the pinned destination.
    let action = cork::decide(&sock, v4_dest(1, 7), b"more").unwrap();
    match action {
        CorkAction::Push { pending, accepted } => {
            assert_eq!(&pending.payload[..], b"heldmore");
            assert_eq!(pending.dest,
                CorkDest::V4 { ip: crate::Ipv4Addr::new(127, 0, 0, 1), port: 7 });
            // The reported byte count is the LAST write, not the accumulation.
            assert_eq!(accepted, 4);
        }
        other => panic!("expected a push, got {other:?}"),
    }
    assert!(sock.opts.udp.pending.lock().is_none());
}

#[test]
fn taking_a_socket_with_nothing_pending_yields_nothing() {
    let sock = InetSocket::new_udp();
    assert!(cork::take(&sock).is_none());
    assert!(cork::discard(&sock).is_empty());
}

// ---- IPv6 checksum suppression -----------------------------------------

#[test]
fn a_suppressed_ipv6_checksum_goes_on_the_wire_as_zero() {
    let payload = b"no-checksum";
    let mut with = alloc::vec![0u8; crate::udp::UDP_HDR_LEN + payload.len()];
    let mut without = with.clone();
    let (src, dst) = (crate::Ipv6Addr::LOOPBACK, crate::Ipv6Addr::LOOPBACK);
    crate::udp::build_into_v6_opts(1, 2, src, dst, payload, &mut with, false);
    crate::udp::build_into_v6_opts(1, 2, src, dst, payload, &mut without, true);
    assert_ne!(u16::from_be_bytes([with[6], with[7]]), 0);
    assert_eq!(u16::from_be_bytes([without[6], without[7]]), 0);
    assert_eq!(&with[8..], payload);
    assert_eq!(&without[8..], payload);
}

#[test]
fn a_zero_checksum_ipv6_datagram_parses_without_validation() {
    let payload = b"zero";
    let mut wire = alloc::vec![0u8; crate::udp::UDP_HDR_LEN + payload.len()];
    let (src, dst) = (crate::Ipv6Addr::LOOPBACK, crate::Ipv6Addr::LOOPBACK);
    crate::udp::build_into_v6_opts(53, 5_353, src, dst, payload, &mut wire, true);
    let header = crate::udp::parse_v6(&wire, src, dst).expect("zero checksum parses");
    assert_eq!((header.src_port, header.dst_port, header.checksum), (53, 5_353, 0));
    // A NON-zero checksum is still validated.
    wire[6] = 0x12; wire[7] = 0x34;
    assert_eq!(crate::udp::parse_v6(&wire, src, dst).err(),
        Some(crate::udp::UdpError::BadChecksum));
}

#[test]
fn the_no_check6_rx_cell_is_shared_with_the_socket_option() {
    let sock = InetSocket::new_udp6();
    assert!(!sock.opts.udp.no_check6_rx());
    assert!(set(&sock.opts.udp, UDP_NO_CHECK6_RX, 1).is_ok());
    assert!(sock.opts.udp.no_check6_rx());
    // The endpoint reads the SAME cell, so bind order cannot desynchronise it.
    let shared = sock.opts.udp.no_check6_rx.clone();
    assert_eq!(shared.load(Ordering::Acquire), 1);
    assert!(set(&sock.opts.udp, UDP_NO_CHECK6_RX, 0).is_ok());
    assert_eq!(shared.load(Ordering::Acquire), 0);
}

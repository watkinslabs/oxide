// Hosted coverage for `IPV6_2292PKTOPTIONS`, both directions. These encode the
// verified behaviour: which slot each written message settles, the privilege
// and shape screens, and — on the read side — which message number each field
// takes, which receive bit gates it, and in what order.

use super::*;
use crate::cmsg::{IPV6_2292HOPLIMIT, IPV6_2292PKTINFO, IPV6_FLOWINFO, IPV6_HOPLIMIT,
    IPV6_PKTINFO, IPV6_TCLASS};

fn raw() -> OptCaps { OptCaps { net_raw: true, net_admin: false } }
fn none() -> OptCaps { OptCaps::default() }

/// A well-formed options header of `units` eight-byte units.
fn opts(units: u8) -> Vec<u8> {
    let mut out = alloc::vec![0u8; (units as usize + 1) * 8];
    out[1] = units;
    out
}

/// A well-formed type-2 routing header: three eight-byte units, one segment.
fn rthdr2() -> Vec<u8> {
    let mut out = alloc::vec![0u8; 24];
    out[1] = 2; out[2] = 2; out[3] = 1;
    out
}

fn stream(items: &[(i32, i32, Vec<u8>)]) -> Result<Slots, Errno> {
    admit_stream(items.iter().map(|(l, k, d)| (*l, *k, d.as_slice())), raw())
}

// ---------------------------------------------------------------- write side

#[test]
fn an_empty_stream_settles_every_slot_empty() {
    assert_eq!(stream(&[]).unwrap(), Slots::default());
}

#[test]
fn the_stream_ceiling_refuses_only_a_length_past_it() {
    assert_eq!(admit_len(0), Ok(()));
    assert_eq!(admit_len(PKTOPTIONS_MAX), Ok(()));
    assert_eq!(admit_len(PKTOPTIONS_MAX + 1), Err(Errno::Einval));
}

#[test]
fn each_header_message_settles_exactly_its_own_slot() {
    let hop = stream(&[(SOL_IPV6, crate::cmsg::IPV6_HOPOPTS, opts(0))]).unwrap();
    assert_eq!(hop, Slots { hop: Some(opts(0)), ..Default::default() });
    let before = stream(&[(SOL_IPV6, IPV6_RTHDRDSTOPTS_CMSG, opts(0))]).unwrap();
    assert_eq!(before, Slots { dst_before_routing: Some(opts(0)), ..Default::default() });
    let after = stream(&[(SOL_IPV6, crate::cmsg::IPV6_DSTOPTS, opts(0))]).unwrap();
    assert_eq!(after, Slots { dst_after_routing: Some(opts(0)), ..Default::default() });
    let route = stream(&[(SOL_IPV6, crate::cmsg::IPV6_RTHDR, rthdr2())]).unwrap();
    assert_eq!(route, Slots { routing: Some(rthdr2()), ..Default::default() });
}

// The write REPLACES the whole sticky block, so a stream naming one header
// leaves the other three empty rather than untouched. This is what makes a
// zero-length write and a one-header write the same kind of operation.
#[test]
fn a_stream_names_the_whole_block_not_a_delta() {
    let settled = stream(&[(SOL_IPV6, crate::cmsg::IPV6_HOPOPTS, opts(1))]).unwrap();
    assert!(settled.dst_before_routing.is_none());
    assert!(settled.routing.is_none());
    assert!(settled.dst_after_routing.is_none());
}

#[test]
fn the_older_hop_by_hop_number_reaches_the_same_slot() {
    let old = stream(&[(SOL_IPV6, crate::cmsg::IPV6_2292HOPOPTS, opts(0))]).unwrap();
    assert_eq!(old.hop, Some(opts(0)));
}

// The hop-by-hop header can only appear once; a second is refused under EITHER
// number, not silently replaced the way the destination-options one is.
#[test]
fn a_second_hop_by_hop_header_fails_the_whole_write() {
    for second in [crate::cmsg::IPV6_HOPOPTS, crate::cmsg::IPV6_2292HOPOPTS] {
        assert_eq!(stream(&[(SOL_IPV6, crate::cmsg::IPV6_HOPOPTS, opts(0)),
            (SOL_IPV6, second, opts(0))]), Err(Errno::Einval));
    }
}

#[test]
fn the_modern_destination_options_number_replaces_while_the_older_one_refuses() {
    let replaced = stream(&[(SOL_IPV6, crate::cmsg::IPV6_DSTOPTS, opts(0)),
        (SOL_IPV6, crate::cmsg::IPV6_DSTOPTS, opts(1))]).unwrap();
    assert_eq!(replaced.dst_after_routing, Some(opts(1)));
    assert_eq!(stream(&[(SOL_IPV6, crate::cmsg::IPV6_2292DSTOPTS, opts(0)),
        (SOL_IPV6, crate::cmsg::IPV6_2292DSTOPTS, opts(0))]), Err(Errno::Einval));
}

// Under the older routing-header number a destination-options header already
// seen belongs BEFORE the routing header, so it changes slots; under the
// modern number it stays where it was.
#[test]
fn the_older_routing_number_moves_a_preceding_destination_header() {
    let old = stream(&[(SOL_IPV6, crate::cmsg::IPV6_2292DSTOPTS, opts(0)),
        (SOL_IPV6, crate::cmsg::IPV6_2292RTHDR, rthdr2())]).unwrap();
    assert_eq!(old.dst_before_routing, Some(opts(0)));
    assert_eq!(old.dst_after_routing, None);
    let modern = stream(&[(SOL_IPV6, crate::cmsg::IPV6_DSTOPTS, opts(0)),
        (SOL_IPV6, crate::cmsg::IPV6_RTHDR, rthdr2())]).unwrap();
    assert_eq!(modern.dst_before_routing, None);
    assert_eq!(modern.dst_after_routing, Some(opts(0)));
}

// A stream carries the type-2 routing header, NOT the segment-routing form the
// sticky `IPV6_RTHDR` write admits. The two paths disagree on purpose.
#[test]
fn only_the_type_two_routing_header_is_admitted_by_a_stream() {
    let mut srh = alloc::vec![0u8; 24];
    srh[1] = 2; srh[2] = 4; srh[3] = 1;
    assert_eq!(stream(&[(SOL_IPV6, crate::cmsg::IPV6_RTHDR, srh)]), Err(Errno::Einval));
    let mut wrong_len = rthdr2();
    wrong_len[1] = 4;
    assert_eq!(stream(&[(SOL_IPV6, crate::cmsg::IPV6_RTHDR, wrong_len)]), Err(Errno::Einval));
    let mut wrong_segs = rthdr2();
    wrong_segs[3] = 0;
    assert_eq!(stream(&[(SOL_IPV6, crate::cmsg::IPV6_RTHDR, wrong_segs)]), Err(Errno::Einval));
}

// Constructing an options header is privileged; a routing header is not.
#[test]
fn the_options_headers_are_privileged_and_the_routing_header_is_not() {
    let unprivileged = |kind, data: Vec<u8>| admit_stream(
        core::iter::once((SOL_IPV6, kind, data.as_slice())), none());
    assert_eq!(unprivileged(crate::cmsg::IPV6_HOPOPTS, opts(0)), Err(Errno::Eperm));
    assert_eq!(unprivileged(crate::cmsg::IPV6_DSTOPTS, opts(0)), Err(Errno::Eperm));
    assert_eq!(unprivileged(IPV6_RTHDRDSTOPTS_CMSG, opts(0)), Err(Errno::Eperm));
    assert!(unprivileged(crate::cmsg::IPV6_RTHDR, rthdr2()).is_ok());
}

// The shape screen runs BEFORE the privilege one: a malformed header is EINVAL
// even to a caller that could never have installed a well-formed one.
#[test]
fn a_malformed_options_header_is_refused_before_the_privilege_check() {
    let short = alloc::vec![0u8, 4];
    assert_eq!(admit_stream(core::iter::once(
        (SOL_IPV6, crate::cmsg::IPV6_HOPOPTS, short.as_slice())), none()), Err(Errno::Einval));
    assert_eq!(admit_stream(core::iter::once(
        (SOL_IPV6, crate::cmsg::IPV6_HOPOPTS, [0u8].as_slice())), none()), Err(Errno::Einval));
}

// The per-datagram scalars are validated and then dropped: they name state one
// send carries, and this write installs no send.
#[test]
fn the_scalar_messages_are_screened_and_then_discarded() {
    let int = |v: i32| Vec::from(v.to_ne_bytes());
    for kind in [IPV6_HOPLIMIT, IPV6_2292HOPLIMIT, IPV6_TCLASS] {
        assert_eq!(stream(&[(SOL_IPV6, kind, int(-1))]).unwrap(), Slots::default());
        assert_eq!(stream(&[(SOL_IPV6, kind, int(255))]).unwrap(), Slots::default());
        assert_eq!(stream(&[(SOL_IPV6, kind, int(256))]), Err(Errno::Einval));
        assert_eq!(stream(&[(SOL_IPV6, kind, int(-2))]), Err(Errno::Einval));
        // These are the messages screened for an EXACT `int`, never a longer one.
        assert_eq!(stream(&[(SOL_IPV6, kind, alloc::vec![0u8; 8])]), Err(Errno::Einval));
    }
    assert_eq!(stream(&[(SOL_IPV6, IPV6_DONTFRAG_CMSG, int(1))]).unwrap(), Slots::default());
    assert_eq!(stream(&[(SOL_IPV6, IPV6_DONTFRAG_CMSG, int(2))]), Err(Errno::Einval));
    assert_eq!(stream(&[(SOL_IPV6, IPV6_PKTINFO, alloc::vec![0u8; 20])]).unwrap(),
        Slots::default());
    assert_eq!(stream(&[(SOL_IPV6, IPV6_PKTINFO, alloc::vec![0u8; 19])]), Err(Errno::Einval));
    assert_eq!(stream(&[(SOL_IPV6, IPV6_FLOWINFO, alloc::vec![0u8; 4])]).unwrap(),
        Slots::default());
    assert_eq!(stream(&[(SOL_IPV6, IPV6_FLOWINFO, alloc::vec![0u8; 3])]), Err(Errno::Einval));
}

// Another level's message is stepped over; an unknown type at THIS level fails
// the whole write.
#[test]
fn other_levels_are_stepped_over_and_an_unknown_own_type_fails() {
    assert_eq!(stream(&[(SOL_SOCKET, 1, alloc::vec![0u8; 4]),
        (0, 8, alloc::vec![0u8; 12])]).unwrap(), Slots::default());
    assert_eq!(stream(&[(SOL_IPV6, 999, alloc::vec![0u8; 4])]), Err(Errno::Einval));
}

// ----------------------------------------------------------------- read side

const STICKY: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const PEER: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

fn state() -> Published {
    Published { sticky_addr: STICKY, sticky_ifindex: 3, daddr: PEER, mcast_hops: 7,
        rcv_flowinfo: 0x0a1_2345, ..Default::default() }
}

fn kinds(msgs: &[Msg]) -> Vec<i32> { msgs.iter().map(|m| m.kind).collect() }

#[test]
fn a_socket_that_enabled_no_receive_option_publishes_nothing() {
    assert!(published(&Published::default()).is_empty());
    assert!(published(&state()).is_empty());
}

// Each field rides under its OWN message number, gated by its OWN receive bit:
// the modern numbering for three of them, the RFC 2292 numbering for the two it
// renumbered, and the single flow-label number.
#[test]
fn each_receive_bit_gates_exactly_one_message_number() {
    let one = |set: fn(&mut Published)| {
        let mut s = state(); set(&mut s); kinds(&published(&s))
    };
    assert_eq!(one(|s| s.rxinfo = true), alloc::vec![IPV6_PKTINFO]);
    assert_eq!(one(|s| s.rxhlim = true), alloc::vec![IPV6_HOPLIMIT]);
    assert_eq!(one(|s| s.rxtclass = true), alloc::vec![IPV6_TCLASS]);
    assert_eq!(one(|s| s.rxoinfo = true), alloc::vec![IPV6_2292PKTINFO]);
    assert_eq!(one(|s| s.rxohlim = true), alloc::vec![IPV6_2292HOPLIMIT]);
    assert_eq!(one(|s| s.rxflow = true), alloc::vec![IPV6_FLOWINFO]);
}

#[test]
fn both_personalities_publish_in_one_fixed_order() {
    let all = Published { rxinfo: true, rxhlim: true, rxtclass: true, rxoinfo: true,
        rxohlim: true, rxflow: true, ..state() };
    assert_eq!(kinds(&published(&all)), alloc::vec![IPV6_PKTINFO, IPV6_HOPLIMIT,
        IPV6_TCLASS, IPV6_2292PKTINFO, IPV6_2292HOPLIMIT, IPV6_FLOWINFO]);
}

// With no multicast interface named, the packet info reports the socket's own
// sticky choice; with one, it reports that interface and the connected peer.
#[test]
fn the_multicast_interface_outranks_the_sticky_packet_info_in_both_fields() {
    let sticky = Published { rxinfo: true, ..state() };
    let msgs = published(&sticky);
    assert_eq!(&msgs[0].bytes[..16], &STICKY);
    assert_eq!(&msgs[0].bytes[16..20], &3i32.to_ne_bytes());

    let mcast = Published { rxinfo: true, mcast_oif: 11, ..state() };
    let msgs = published(&mcast);
    assert_eq!(&msgs[0].bytes[..16], &PEER);
    assert_eq!(&msgs[0].bytes[16..20], &11i32.to_ne_bytes());
}

#[test]
fn both_packet_info_numbers_carry_the_identical_payload() {
    let s = Published { rxinfo: true, rxoinfo: true, mcast_oif: 11, ..state() };
    let msgs = published(&s);
    assert_eq!(msgs[0].bytes, msgs[1].bytes);
}

// The hop limit published here is the MULTICAST one, and the traffic class is
// carved out of the received flow-info word rather than stored on its own.
#[test]
fn the_hop_limit_and_traffic_class_come_from_the_sockets_own_state() {
    let s = Published { rxhlim: true, rxohlim: true, rxtclass: true, ..state() };
    let msgs = published(&s);
    assert_eq!(msgs[0].bytes, Vec::from(7i32.to_ne_bytes()));
    assert_eq!(msgs[1].bytes, Vec::from(tclass_of(0x0a1_2345).to_ne_bytes()));
    assert_eq!(msgs[2].bytes, Vec::from(7i32.to_ne_bytes()));
    assert_eq!(tclass_of(0x0ff0_0000), 255);
    assert_eq!(tclass_of(0x000f_ffff), 0);
}

// The flow label rides back in network order, unlike every scalar beside it.
#[test]
fn the_flow_label_is_published_in_network_order() {
    let s = Published { rxflow: true, ..state() };
    assert_eq!(published(&s)[0].bytes, Vec::from(0x0a1_2345u32.to_be_bytes()));
}

// `IP_CHECKSUM`: the whole-datagram checksum a validating UDP/IPv4 receive
// retains, and the ancillary message that publishes it.
//
// The option is a receive-side request, not a transmit knob: setting it asks
// the receive path to keep the sum it already computed while validating, so a
// reader can re-verify the bytes it was handed. A datagram whose sender
// suppressed the checksum leaves nothing to keep, and publishes nothing.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicI32;
use sync::{Spinlock, Socket as StackLockClass};

use crate::cmsg::{plan, RxMeta, Want};
use crate::ipv4::{fold_ones, ip_checksum, ones_sub, ones_sum};
use crate::udp::{parse_rx, UdpError, UdpHdr, UDP_HDR_LEN};
use crate::{Ipv4Addr, NetStack, SocketError};

const SRC: Ipv4Addr = Ipv4Addr::LOOPBACK;
const DST: Ipv4Addr = Ipv4Addr::LOOPBACK;
const SPORT: u16 = 41_101;
const DPORT: u16 = 49_101;
const BODY: &[u8] = b"whole-datagram checksum";

/// The pseudo-header sum a reader combines with the published value.
fn pseudo(len: usize, src: Ipv4Addr, dst: Ipv4Addr) -> u32 {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&src.octets());
    buf[4..8].copy_from_slice(&dst.octets());
    buf[9] = crate::addr::IpProto::Udp as u8;
    buf[10..12].copy_from_slice(&(len as u16).to_be_bytes());
    ones_sum(&buf)
}

/// One UDP/IPv4 message on the wire, checksum computed or suppressed.
fn datagram(body: &[u8], no_check: bool) -> Vec<u8> {
    let mut out = alloc::vec![0u8; UDP_HDR_LEN + body.len()];
    UdpHdr::build_into_opts(SPORT, DPORT, SRC, DST, body, &mut out, no_check);
    out
}

// ---------------------------------------------------------------- arithmetic

#[test]
fn partial_sums_add_before_folding_and_the_checksum_is_their_complement() {
    let header = [0x45u8, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
                  127, 0, 0, 1, 127, 0, 0, 1];
    // Summing a buffer whole and summing it in two even-aligned halves must
    // fold to the same sixteen bits, which is what lets a pseudo-header and a
    // message body be summed independently and combined.
    let (front, back) = header.split_at(8);
    assert_eq!(fold_ones(ones_sum(&header)),
        fold_ones(ones_sum(front) + ones_sum(back)));
    assert_eq!(ip_checksum(&header), !fold_ones(ones_sum(&header)));
    // An odd trailing byte lands in the high half of its word.
    assert_eq!(ones_sum(&[0x12u8]), 0x1200);
}

#[test]
fn removing_a_word_from_a_sum_is_adding_its_complement() {
    let buf = [0x12u8, 0x34, 0xab, 0xcd, 0x00, 0x07];
    let word = 0xabcdu16;
    assert_eq!(fold_ones(ones_sub(ones_sum(&buf), word)),
        fold_ones(ones_sum(&[0x12u8, 0x34, 0x00, 0x07])));
}

// ------------------------------------------------------------------ retention

#[test]
fn a_checksummed_datagram_retains_a_sum_that_closes_against_the_pseudo_header() {
    let wire = datagram(BODY, false);
    let rx = parse_rx(&wire, SRC, DST).unwrap();
    let complete = rx.complete.expect("a datagram carrying a checksum retains one");
    // The published value is the sum over the message alone. Combined with the
    // pseudo-header it folds to all-ones, which is how a reader re-verifies.
    assert_eq!(fold_ones(complete + pseudo(wire.len(), SRC, DST)), 0xFFFF);
    // It covers the datagram exactly as it arrived, checksum field included.
    assert_eq!(complete, ones_sum(&wire));
    assert_eq!(rx.hdr.src_port, SPORT);
    assert_eq!(rx.hdr.dst_port, DPORT);
}

#[test]
fn a_suppressed_checksum_leaves_nothing_to_retain() {
    let wire = datagram(BODY, true);
    assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0);
    assert_eq!(parse_rx(&wire, SRC, DST).unwrap().complete, None);
}

#[test]
fn a_corrupt_datagram_is_refused_before_any_sum_is_retained() {
    let mut wire = datagram(BODY, false);
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    assert_eq!(parse_rx(&wire, SRC, DST), Err(UdpError::BadChecksum));
    // The same message under the wrong pseudo-header is equally refused: the
    // addresses are part of what the checksum covers.
    let wire = datagram(BODY, false);
    assert_eq!(parse_rx(&wire, Ipv4Addr::new(198, 51, 100, 9), DST),
        Err(UdpError::BadChecksum));
}

#[test]
fn an_all_ones_checksum_field_is_a_computed_zero_and_still_retains_a_sum() {
    // A body whose checksum computes to zero goes on the wire as all-ones,
    // since zero is reserved for "suppressed". Such a datagram still carries a
    // checksum and must still retain a sum.
    for fill in 0u8..=255 {
        let wire = datagram(&[fill, fill, fill, fill], false);
        if u16::from_be_bytes([wire[6], wire[7]]) != crate::udp::UDP_CSUM_MANGLED_ZERO {
            continue;
        }
        let rx = parse_rx(&wire, SRC, DST).unwrap();
        assert!(rx.complete.is_some(), "an all-ones field is a checksum, not a suppression");
        return;
    }
}

// -------------------------------------------------------------- the message

#[test]
fn the_checksum_message_needs_both_the_option_and_a_retained_sum() {
    const IP_CHECKSUM: i32 = 23;
    const SOL_IP: i32 = 0;
    let retained = RxMeta { checksum: Some(0x0001_2345), ..Default::default() };

    let asked = plan(&Want { checksum: true, ..Default::default() }, &retained);
    assert_eq!(asked.len(), 1);
    assert_eq!((asked[0].level, asked[0].kind), (SOL_IP, IP_CHECKSUM));
    // The value is published as a four-byte word, native order.
    assert_eq!(asked[0].bytes, 0x0001_2345u32.to_ne_bytes());

    // The option alone publishes nothing when the receive retained no sum.
    assert!(plan(&Want { checksum: true, ..Default::default() }, &RxMeta::default()).is_empty());
    // A retained sum alone publishes nothing when the socket never asked.
    assert!(plan(&Want::default(), &retained).is_empty());
}

#[test]
fn the_projection_to_the_planner_carries_every_captured_field() {
    use crate::addr::NetIfaceId;
    let rcv = crate::recv_result::Received {
        peer: Some((Ipv4Addr::new(198, 51, 100, 7), SPORT)),
        pktinfo: Some((DST, NetIfaceId::from_raw(3))),
        ttl: Some(64), tos: Some(0x28), dport: DPORT, frag_max: 1500,
        checksum: Some(0x0001_2345), gro: Some(1200),
        hoplimit: Some(63), tclass: Some(0x30), flowinfo: 0x9_ABCD,
        peer6: Some((crate::Ipv6Addr::LOOPBACK, SPORT, 7)),
        pktinfo6: Some((crate::Ipv6Addr::LOOPBACK, NetIfaceId::from_raw(4))),
        ext_headers: alloc::vec![(60u8, alloc::vec![0u8; 8])],
        ..Default::default()
    };
    let meta = rcv.rx_meta(Some(b"label".to_vec()));

    // Each captured field must arrive; a field the projection forgets reaches
    // no reader and nothing else would notice.
    assert_eq!(meta.src, [198, 51, 100, 7]);
    assert_eq!(meta.dst, Some((DST.octets(), 3)));
    assert_eq!(meta.ttl, Some(64));
    assert_eq!(meta.tos, Some(0x28));
    assert_eq!(meta.dport, DPORT);
    assert_eq!(meta.frag_max, 1500);
    assert_eq!(meta.checksum, Some(0x0001_2345));
    assert_eq!(meta.gro, Some(1200));
    assert_eq!(meta.security.as_deref(), Some(&b"label"[..]));
    assert_eq!(meta.hoplimit, Some(63));
    assert_eq!(meta.tclass, Some(0x30));
    assert_eq!(meta.flowinfo, 0x9_ABCD);
    assert_eq!(meta.scope_id, 7);
    assert_eq!(meta.dst6, Some((crate::Ipv6Addr::LOOPBACK.0, 4)));
    assert_eq!(meta.ext_headers.len(), 1);
    // A receive that captured nothing projects to the planner's own default,
    // which is the shape that publishes no ancillary message at all.
    assert_eq!(crate::recv_result::Received::default().rx_meta(None), RxMeta::default());
}

// ------------------------------------------------------------- through the stack

fn bind(stack: &NetStack, port: u16) -> Arc<crate::UdpRxQueue> {
    stack.bind_udp_socket(
        Ipv4Addr::LOOPBACK, port, None, Arc::new(SocketError::new()),
        Arc::new(AtomicI32::new(0)), Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 0,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap()
}

#[test]
fn a_delivered_datagram_carries_its_whole_datagram_checksum_to_the_reader() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let queue = bind(&stack, DPORT);

    stack.send_udp_to(Ipv4Addr::LOOPBACK, SPORT, Ipv4Addr::LOOPBACK, DPORT, BODY).unwrap();
    stack.drain_loopback(iface, &loopback);

    let got = queue.recv(false).expect("a delivered datagram");
    assert_eq!(got.payload, BODY);
    let complete = got.checksum.expect("the receive pass retained a checksum");
    assert_eq!(fold_ones(complete + pseudo(UDP_HDR_LEN + BODY.len(), SRC, DST)), 0xFFFF);
}

#[test]
fn a_coalesced_receive_publishes_no_whole_datagram_checksum() {
    use crate::stack::{UdpDatagram, UdpRxQueue};
    let _domain = crate::hosted_fixture::init_net_domain();
    let queue = UdpRxQueue::new(DST, DPORT);
    queue.gro.store(1, core::sync::atomic::Ordering::Release);

    let one = |fill: u8| UdpDatagram {
        src: SRC, sport: SPORT, dst: DST, dport: DPORT,
        iface: crate::addr::NetIfaceId::from_raw(1),
        ttl: 64, tos: 0, options: Default::default(), frag_max: 0, dont_fragment: false,
        checksum: Some(0x4321), payload: alloc::vec![fill; 100],
    };
    // A lone datagram publishes the sum the receive retained.
    assert!(queue.enqueue_gro(one(1), false, true));
    // A second datagram of the same flow coalesces into it. The retained sum
    // described the head alone, so it can no longer be published.
    assert!(queue.enqueue_gro(one(2), false, true));

    let got = queue.recv(false).expect("a coalesced receive");
    assert_eq!(got.payload.len(), 200);
    assert_eq!(got.checksum, None);
}

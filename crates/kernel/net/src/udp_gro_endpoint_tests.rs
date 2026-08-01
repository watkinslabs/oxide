// `UDP_GRO` end to end at the socket endpoint: what a reader actually gets
// back once the delivery path runs the coalescing rule.

use core::sync::atomic::Ordering;

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::stack::UdpRxQueue;
use crate::stack_ipv6::Udp6RxQueue;

const SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const SPORT: u16 = 4_000;
const DPORT: u16 = 5_000;
const TTL: u8 = 64;

fn iface(n: u32) -> NetIfaceId { NetIfaceId::from_raw(n) }

fn queue(gro: bool) -> UdpRxQueue {
    let q = UdpRxQueue::new(DST, DPORT);
    q.gro.store(i32::from(gro), Ordering::Release);
    q
}

fn deliver(q: &UdpRxQueue, len: usize, fill: u8) -> bool {
    deliver_from(q, SRC, SPORT, iface(1), TTL, len, fill)
}

fn deliver_from(q: &UdpRxQueue, src: Ipv4Addr, sport: u16, dev: NetIfaceId, ttl: u8,
    len: usize, fill: u8) -> bool
{
    q.enqueue_gro((src, sport, DST, dev, ttl, alloc::vec![fill; len]), false)
}

#[test]
fn coalescing_off_delivers_every_datagram_separately() {
    let q = queue(false);
    for i in 0..3 { assert!(deliver(&q, 100, i)); }
    assert_eq!(q.queued_len(), 3);
    for i in 0..3u8 {
        let (datagram, seg) = q.recv_gro(false).expect("queued");
        assert_eq!(datagram.5.len(), 100);
        assert_eq!(datagram.5[0], i);
        assert_eq!(seg, None, "an uncoalesced receive reports no segment size");
    }
}

#[test]
fn one_flow_of_equal_datagrams_becomes_one_receive() {
    let q = queue(true);
    for i in 0..4 { assert!(deliver(&q, 100, i)); }
    assert_eq!(q.queued_len(), 1, "four datagrams, one receive");
    let (datagram, seg) = q.recv_gro(false).expect("queued");
    assert_eq!(datagram.5.len(), 400);
    assert_eq!(seg, Some(100), "the reader is told how to split it back");
    // The bytes arrive in order, each segment intact.
    for i in 0..4usize { assert!(datagram.5[i * 100..(i + 1) * 100].iter().all(|b| *b == i as u8)); }
    assert!(q.recv_gro(false).is_none());
}

#[test]
fn a_short_final_datagram_joins_and_ends_the_receive() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    assert!(deliver(&q, 100, 2));
    assert!(deliver(&q, 40, 3));
    // The short segment is absorbed; anything after it starts a new receive.
    assert!(deliver(&q, 100, 4));
    assert_eq!(q.queued_len(), 2);
    let (first, seg) = q.recv_gro(false).expect("queued");
    assert_eq!(first.5.len(), 240);
    assert_eq!(seg, Some(100), "the size stays the full segment, not the short tail");
    let (second, seg) = q.recv_gro(false).expect("queued");
    assert_eq!(second.5.len(), 100);
    assert_eq!(seg, None);
}

#[test]
fn a_longer_datagram_ends_the_run_instead_of_joining_it() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    assert!(deliver(&q, 200, 2));
    assert_eq!(q.queued_len(), 2);
    assert_eq!(q.recv_gro(false).expect("queued").0.5.len(), 100);
    // ...and the longer one heads a run of its own.
    assert!(deliver(&q, 200, 3));
    assert_eq!(q.queued_len(), 1);
    let (datagram, seg) = q.recv_gro(false).expect("queued");
    assert_eq!(datagram.5.len(), 400);
    assert_eq!(seg, Some(200));
}

#[test]
fn a_run_never_spans_two_flows() {
    let other_src = Ipv4Addr::new(203, 0, 113, 9);
    for (label, src, sport, dev, ttl) in [
        ("source address", other_src, SPORT, iface(1), TTL),
        ("source port", SRC, SPORT + 1, iface(1), TTL),
        ("ingress interface", SRC, SPORT, iface(2), TTL),
        ("received hop count", SRC, SPORT, iface(1), TTL - 1),
    ] {
        let q = queue(true);
        assert!(deliver(&q, 100, 1));
        assert!(deliver_from(&q, src, sport, dev, ttl, 100, 2));
        assert_eq!(q.queued_len(), 2, "{label} must break the run");
    }
}

#[test]
fn a_run_stops_at_the_segment_cap_and_the_next_datagram_starts_another() {
    let q = queue(true);
    for _ in 0..crate::udp_gro::UDP_GRO_CNT_MAX { assert!(deliver(&q, 10, 1)); }
    assert_eq!(q.queued_len(), 1);
    assert!(deliver(&q, 10, 2));
    assert_eq!(q.queued_len(), 2);
    let (first, seg) = q.recv_gro(false).expect("queued");
    assert_eq!(first.5.len(), 10 * crate::udp_gro::UDP_GRO_CNT_MAX);
    assert_eq!(seg, Some(10));
}

#[test]
fn a_suppressed_checksum_datagram_is_delivered_alone() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    // Neither joins the run...
    assert!(q.enqueue_gro((SRC, SPORT, DST, iface(1), TTL, alloc::vec![2; 100]), true));
    // ...nor heads one.
    assert!(deliver(&q, 100, 3));
    assert_eq!(q.queued_len(), 3);
    for _ in 0..3 { assert_eq!(q.recv_gro(false).expect("queued").1, None); }
}

#[test]
fn an_empty_datagram_is_delivered_alone_and_breaks_the_run() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    assert!(deliver(&q, 0, 0));
    assert!(deliver(&q, 100, 2));
    assert_eq!(q.queued_len(), 3);
}

#[test]
fn peeking_a_coalesced_receive_reports_the_same_segment_size() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    assert!(deliver(&q, 100, 2));
    let (peeked, seg) = q.recv_gro(true).expect("queued");
    assert_eq!((peeked.5.len(), seg), (200, Some(100)));
    assert_eq!(q.queued_len(), 1, "a peek consumes nothing");
    let (popped, seg) = q.recv_gro(false).expect("queued");
    assert_eq!((popped.5.len(), seg), (200, Some(100)));
}

#[test]
fn coalescing_charges_the_receive_queue_the_full_byte_count() {
    let q = queue(true);
    for i in 0..3 { assert!(deliver(&q, 100, i)); }
    assert_eq!(q.queued_bytes(), 300, "merged bytes are still charged");
}

#[test]
fn a_datagram_after_a_drained_run_starts_a_fresh_one() {
    let q = queue(true);
    assert!(deliver(&q, 100, 1));
    assert!(deliver(&q, 100, 2));
    assert_eq!(q.recv_gro(false).expect("queued").0.5.len(), 200);
    assert!(deliver(&q, 100, 3));
    assert!(deliver(&q, 100, 4));
    let (datagram, seg) = q.recv_gro(false).expect("queued");
    assert_eq!((datagram.5.len(), seg), (200, Some(100)));
}

#[test]
fn the_ipv6_endpoint_coalesces_by_the_same_rule() {
    let q = Udp6RxQueue::new(Ipv6Addr::LOOPBACK, DPORT);
    q.gro.store(1, Ordering::Release);
    let deliver6 = |len: usize, fill: u8, class: u8| {
        q.enqueue_gro((Ipv6Addr::LOOPBACK, SPORT, Ipv6Addr::LOOPBACK, iface(1), 64, class,
            alloc::vec![fill; len]), false)
    };
    assert!(deliver6(100, 1, 0));
    assert!(deliver6(100, 2, 0));
    assert_eq!(q.queued_len(), 1);
    // A traffic-class change is a different flow.
    assert!(deliver6(100, 3, 8));
    assert_eq!(q.queued_len(), 2);
    let (datagram, seg) = q.recv_gro(false).expect("queued");
    assert_eq!((datagram.6.len(), seg), (200, Some(100)));
}

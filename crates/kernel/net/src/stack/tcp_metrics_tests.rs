// That the delivery path is WIRED to the per-destination metrics cache: a
// connection that completes a handshake reads the cache, and one that closes
// writes back to it.
//
// The seed and the write-back are decided in ungated `crate::tcp_metrics` and
// tested there. What can only be asserted here is that the two moments happen
// at all — before this, nothing in the tree consulted the cache, so a listener
// under a flood could vouch for no returning peer and every connection
// rediscovered a path the last one had already measured.

use super::*;
use crate::tcp_hdr::flags;
use crate::tcp_metrics::ids;
use super::tcp_syncookies_tests::{child, deliver, drain, sent, head, syn_options, CLIENT_SEQ,
    SERVER};

const CLIENT: IpAddr = IpAddr::V4(crate::Ipv4Addr::LOOPBACK);

/// Drive a full three-way handshake and return the child it produced.
fn handshake(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
             lo: &crate::loopback::LoopbackDev) -> Option<Arc<TcpEntry>>
{
    deliver(stack, iface, port, client_port, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let segment = sent(lo)?;
    let synack = head(&segment);
    drain(lo);
    deliver(stack, iface, port, client_port, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), syn_options());
    child(stack, port, client_port)
}

#[test]
fn a_completed_handshake_reads_the_destination_cache() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let _listener = stack.tcp_listen(SERVER, 7_601, true).expect("listen");

    // A destination this host remembers a slow path to.
    let mut pinned = [None; ids::COUNT];
    pinned[ids::RTT] = Some(400_000);
    pinned[ids::REORDERING] = Some(9);
    crate::tcp_metrics::pin_in(0, IpAddr::V4(SERVER), CLIENT, 0, pinned);

    let child = handshake(&stack, iface, 7_601, 40_101, &lo).expect("the handshake completed");
    let conn = child.conn.lock();
    assert_eq!(conn.reordering, 9, "the remembered reordering degree reached the connection");
    // 400 ms remembered: one round trip plus twice its own.
    assert_eq!(conn.rto_ns, 1_200_000_000,
        "the first retransmit timeout came from the cache, not from the handshake");
}

#[test]
fn a_closing_connection_writes_back_and_proves_the_peer() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let _listener = stack.tcp_listen(SERVER, 7_602, true).expect("listen");
    assert!(!crate::listen_queue::peer_is_proven(0, IpAddr::V4(SERVER), CLIENT),
        "a peer this host has never completed a handshake with vouches for nothing");

    let child = handshake(&stack, iface, 7_602, 40_102, &lo).expect("the handshake completed");
    {
        // Give the connection something to have measured; a handshake alone
        // leaves no round-trip sample on this path.
        let mut conn = child.conn.lock();
        conn.srtt_ns = 20_000_000;
        conn.rttvar_ns = 2_000_000;
        conn.rto_ns = conn.rto_min_ns;
    }
    stack.tcp_close(&child).expect("close");

    let held = crate::tcp_metrics::cached_in(0, IpAddr::V4(SERVER), CLIENT);
    assert_eq!(held.get(ids::RTT), 20_000, "the round trip it measured, in microseconds");
    assert!(crate::listen_queue::peer_is_proven(0, IpAddr::V4(SERVER), CLIENT),
        "a completed connection is what proves a peer reachable");
    // The reserve a listener holds under a flood is what consumes that answer.
    assert!(crate::listen_queue::admit_unproven_request(1_000, 128, false,
        crate::listen_queue::peer_is_proven(0, IpAddr::V4(SERVER), CLIENT)),
        "a proven peer takes a slot the reserve would have refused");
}

#[test]
fn a_namespace_that_refuses_to_remember_learns_nothing_from_a_close() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let _listener = stack.tcp_listen(SERVER, 7_603, true).expect("listen");
    crate::tcp_metrics::forget_all_in(0);
    crate::sysctl::set_value_in(0, crate::net_ns::NetSysctlKey::TcpNoMetricsSave, 1)
        .expect("the namespace carries the knob");

    let child = handshake(&stack, iface, 7_603, 40_103, &lo).expect("the handshake completed");
    {
        let mut conn = child.conn.lock();
        conn.srtt_ns = 20_000_000;
        conn.rttvar_ns = 2_000_000;
        conn.rto_ns = conn.rto_min_ns;
    }
    stack.tcp_close(&child).expect("close");

    assert!(crate::tcp_metrics::cached_in(0, IpAddr::V4(SERVER), CLIENT).is_empty());
    crate::sysctl::set_value_in(0, crate::net_ns::NetSysctlKey::TcpNoMetricsSave, 0)
        .expect("the namespace carries the knob");
}

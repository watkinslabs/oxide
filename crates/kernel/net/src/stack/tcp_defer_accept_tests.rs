// `TCP_DEFER_ACCEPT` end to end, over real segments on the loopback path: a
// deferred connection stays a half-open request, the peer's bare
// acknowledgement is dropped rather than completing the handshake, and only
// data — or the acknowledgement the end of the deferring period solicits —
// promotes it into the accept queue.
//
// The rules these exercise are unit-tested on their own in
// `tcp_conn/reqsk_tests.rs`; what is asserted here is that the delivery path
// and the request timer are wired to them.

use super::*;
use crate::tcp_conn::reqsk;
use crate::tcp_state::TcpState;
use ::core::sync::atomic::Ordering;

const CLIENT_PORT: u16 = 50_600;

fn defer_count(seconds: i32) -> u8 {
    crate::sock_opts::sol_tcp::secs_to_retrans(seconds,
        crate::sock_opts::sol_tcp::TCP_TIMEOUT_INIT_S,
        crate::sock_opts::sol_tcp::TCP_RTO_MAX_SEC)
}

/// A listener on the loopback deferring for `seconds`, and the loopback the
/// handshake is driven over. `0` seconds = no deferral.
fn fixture(stack: &NetStack, port: u16, seconds: i32)
    -> (NetIfaceId, Arc<LoopbackDev>, Arc<TcpListenEntry>)
{
    let (iface, lo_dev) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, port, true).expect("listen");
    if seconds > 0 {
        listener.defer_accept.store(defer_count(seconds), Ordering::Release);
    }
    (iface, lo_dev, listener)
}

/// The server-side entry for a client connecting from `client_port`.
fn server_side(stack: &NetStack, port: u16, client_port: u16) -> Arc<TcpEntry> {
    let key = TcpKey {
        local_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), local_port: port,
        remote_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), remote_port: client_port,
    };
    stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
        .expect("the SYN reached the listener")
}

fn handshake(stack: &NetStack, iface: NetIfaceId, lo_dev: &Arc<LoopbackDev>,
             port: u16, client_port: u16) -> (Arc<TcpEntry>, Arc<TcpEntry>)
{
    let client = stack.tcp_connect(Ipv4Addr::LOOPBACK, client_port,
        Ipv4Addr::LOOPBACK, port).expect("connect");
    for _ in 0..3 { stack.drain_loopback(iface, lo_dev); }
    (client, server_side(stack, port, client_port))
}

#[test]
fn a_listener_that_did_not_defer_completes_on_the_bare_acknowledgement() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev, listener) = fixture(&stack, 601, 0);
    let (_client, server) = handshake(&stack, iface, &lo_dev, 601, CLIENT_PORT);
    assert_eq!(server.conn.lock().state, TcpState::Established);
    let accepted = stack.tcp_accept(&listener).expect("the third ACK completes the connection");
    assert!(Arc::ptr_eq(&accepted, &server));
}

#[test]
fn a_deferring_listener_leaves_the_bare_acknowledgement_uncompleted() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev, listener) = fixture(&stack, 602, 30);
    let (client, server) = handshake(&stack, iface, &lo_dev, 602, CLIENT_PORT + 2);

    let c = server.conn.lock();
    assert_eq!(c.state, TcpState::SynRecv, "the connection is still a request");
    assert!(c.rsk.acked, "the peer's acknowledgement was seen, and dropped");
    assert!(c.rsk.armed(), "the request keeps its own retransmit timer");
    assert_eq!(c.retx_q.len(), 1, "the SYN-ACK is still unacknowledged");
    drop(c);

    assert!(listener.accept_q.lock().is_empty(),
        "a request is not a queued child: nothing was published to accept");
    assert!(stack.tcp_accept(&listener).is_none());
    assert_eq!(listener.syn_backlog_used.load(Ordering::Acquire), 1,
        "the request holds a SYN backlog slot, not an accept one");
    assert_eq!(listener.accept_backlog_used.load(Ordering::Acquire), 0);
    // The peer completed its own half of the handshake, which is exactly the
    // asymmetry the deferral produces.
    assert_eq!(client.conn.lock().state, TcpState::Established);
}

#[test]
fn data_promotes_a_deferred_request_and_the_bytes_it_carried_survive() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev, listener) = fixture(&stack, 603, 30);
    let (client, server) = handshake(&stack, iface, &lo_dev, 603, CLIENT_PORT + 3);
    assert_eq!(server.conn.lock().state, TcpState::SynRecv);

    assert_eq!(stack.tcp_send(&client, b"GET /", crate::sock::TCP_SNDBUF_DEFAULT as usize,
        true, false), Ok(5));
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }

    assert_eq!(server.conn.lock().state, TcpState::Established,
        "the data the listener was waiting for completes the request");
    let accepted = stack.tcp_accept(&listener).expect("the connection is acceptable now");
    assert!(Arc::ptr_eq(&accepted, &server));
    // The segment that promoted the request is applied to the connection it
    // created, so the request itself is the first thing the server reads.
    assert_eq!(stack.tcp_recv(&accepted, 64), b"GET /");
    assert_eq!(listener.syn_backlog_used.load(Ordering::Acquire), 0,
        "the request slot is handed over with the connection");
}

#[test]
fn a_deferred_request_retransmits_nothing_while_it_waits_for_data() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev, _listener) = fixture(&stack, 604, 30);
    let (_client, server) = handshake(&stack, iface, &lo_dev, 604, CLIENT_PORT + 4);
    let count = defer_count(30);

    let mut now = server.conn.lock().rsk.expires_ns;
    for fired in 1..count {
        stack.tcp_reqsk_tick_at(now);
        let c = server.conn.lock();
        assert_eq!(c.state, TcpState::SynRecv, "the request outlives the firing");
        assert_eq!(c.rsk.num_timeout, fired, "the firing is counted");
        assert_eq!(c.retx_q.front().expect("SYN-ACK held").retries, 0,
            "an acknowledged request waiting for data retransmits nothing");
        now = c.rsk.expires_ns;
    }
    // The last firing of the deferring period solicits the acknowledgement
    // that will complete the connection.
    stack.tcp_reqsk_tick_at(now);
    let c = server.conn.lock();
    assert_eq!(c.rsk.num_timeout, count);
    assert_eq!(c.retx_q.front().expect("SYN-ACK held").retries, 1,
        "one SYN-ACK goes out as the deferring period ends");
}

#[test]
fn the_end_of_the_deferring_period_completes_the_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev, listener) = fixture(&stack, 605, 30);
    let (_client, server) = handshake(&stack, iface, &lo_dev, 605, CLIENT_PORT + 5);
    let count = defer_count(30);

    for _ in 0..count {
        let now = server.conn.lock().rsk.expires_ns;
        stack.tcp_reqsk_tick_at(now);
        for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    }
    // The peer answered the solicited SYN-ACK, and by then the deferral no
    // longer drops that acknowledgement: the connection is handed over with
    // nothing received, rather than being lost.
    assert_eq!(server.conn.lock().state, TcpState::Established);
    let accepted = stack.tcp_accept(&listener).expect("the deferring period has run out");
    assert!(Arc::ptr_eq(&accepted, &server));
    assert!(accepted.conn.lock().recv_buf.is_empty());
}

#[test]
fn an_unanswered_request_is_abandoned_at_the_retransmit_ceiling() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo_dev, listener) = fixture(&stack, 606, 0);
    // A SYN with nothing behind it: the SYN-ACK is queued on the loopback and
    // never drained, so it is never acknowledged.
    let key = syn_only(&stack, iface, 606, CLIENT_PORT + 6);
    let server = stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
        .expect("the SYN opened a request");
    assert_eq!(listener.syn_backlog_used.load(Ordering::Acquire), 1);

    for fired in 1..=reqsk::SYNACK_RETRIES_DEFAULT {
        let now = server.conn.lock().rsk.expires_ns;
        stack.tcp_reqsk_tick_at(now);
        let c = server.conn.lock();
        assert_eq!(c.rsk.num_timeout, fired);
        assert_eq!(c.retx_q.front().expect("SYN-ACK held").retries, fired as u32,
            "every firing of an unanswered request retransmits the SYN-ACK");
    }
    // The next firing finds the ceiling reached.
    let now = server.conn.lock().rsk.expires_ns;
    stack.tcp_reqsk_tick_at(now);
    assert_eq!(server.conn.lock().state, TcpState::Closed,
        "the request is abandoned once it runs out of retransmits");
    assert!(stack.inet_tables(0).tcp_conns.lock().get(&key).is_none(),
        "an abandoned request is unhooked from the connection table");
    assert_eq!(listener.syn_backlog_used.load(Ordering::Acquire), 0,
        "and gives its backlog slot back");
}

/// Deliver a bare SYN from a peer that will never answer the SYN-ACK.
fn syn_only(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16) -> TcpKey {
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: client_port, dst_port: port,
        seq: 0x1000_0000, ack: 0, data_offset: 5,
        flags: crate::tcp_hdr::flags::SYN,
        window: 65_535, checksum: 0, urg_ptr: 0,
    };
    let peer = IpAddr::V4(Ipv4Addr::LOOPBACK);
    hdr.build_into(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, &mut buf);
    stack.deliver_tcp_packet(0, iface, peer, IpAddr::V4(Ipv4Addr::LOOPBACK), &buf, &buf)
        .expect("deliver SYN");
    TcpKey {
        local_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), local_port: port,
        remote_ip: peer, remote_port: client_port,
    }
}

#[test]
fn the_window_the_listener_defers_for_is_the_one_the_option_reports() {
    // The count the option stores is the count the deferral counts firings
    // against, so what `getsockopt` reports and what the request waits are the
    // same number in the same unit.
    for requested in [1, 5, 30] {
        let stored = defer_count(requested);
        let reported = crate::sock_opts::sol_tcp::retrans_to_secs(stored,
            crate::sock_opts::sol_tcp::TCP_TIMEOUT_INIT_S,
            crate::sock_opts::sol_tcp::TCP_RTO_MAX_SEC);
        assert!(reported >= requested, "the deferral must cover what was asked for");
        // A request survives exactly `stored` firings before its
        // acknowledgement is accepted.
        let mut r = reqsk::ReqSock { acked: true, ..Default::default() };
        let mut waited = 0u64;
        while r.defers_bare_ack(stored, true) {
            waited += r.timeout_ns(crate::tcp_conn::RTO_MAX_DEFAULT_NS);
            r.on_timeout(waited, crate::tcp_conn::RTO_MAX_DEFAULT_NS);
        }
        assert_eq!(r.num_timeout, stored);
        assert_eq!(waited, reported as u64 * crate::sock_opts::sol_tcp::NS_PER_S,
            "the firings the deferral counts span the seconds it reports");
    }
}

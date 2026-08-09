// SYN cookies end to end, over real segments on the delivery path.
//
// The construction itself is unit-tested in `syncookies/tests.rs` and the
// rebuild in `tcp_conn/syncookie_tests.rs`; what is asserted here is that the
// delivery path is WIRED to both — that a SYN the queue cannot hold produces a
// cookie SYN-ACK and no state at all, that the acknowledgement carrying that
// cookie back produces an accepted connection, and that the sysctl this all
// hangs off is actually read. Before this, `net.ipv4.tcp_syncookies` was
// stored and never consulted anywhere, and a full SYN queue simply dropped.

use super::*;
use crate::tcp_conn::syn_opts::SynOptions;
use crate::tcp_hdr::flags;
use crate::tcp_state::TcpState;

const SERVER: Ipv4Addr = Ipv4Addr::LOOPBACK;
const CLIENT_SEQ: u32 = 0x2000_0000;

/// A listener whose SYN queue holds exactly one request.
fn fixture(stack: &NetStack, port: u16) -> (NetIfaceId, Arc<crate::loopback::LoopbackDev>,
                                            Arc<TcpListenEntry>)
{
    let (iface, lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, port, true).expect("listen");
    listener.backlog.store(1, ::core::sync::atomic::Ordering::Release);
    (iface, lo, listener)
}

/// Deliver one segment built from `flags`, `seq` and `ack`, offering the
/// options a modern client offers.
fn deliver(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
           flag_bits: u8, seq: u32, ack: u32, opts: SynOptions)
{
    let opt_len = opts.encoded_len();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len];
    opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: client_port, dst_port: port, seq, ack,
        data_offset: opts.data_offset(), flags: flag_bits,
        window: 65_535, checksum: 0, urg_ptr: 0,
    };
    hdr.build_into(SERVER, SERVER, &mut buf);
    stack.deliver_tcp_packet(0, iface, IpAddr::V4(SERVER), IpAddr::V4(SERVER), &buf, &buf)
        .expect("deliver");
}

pub(super) fn syn_options() -> SynOptions {
    SynOptions { mss: Some(1460), timestamp: Some((0x1111_2222, 0)), sack_perm: true,
                 wscale: Some(7), fastopen: None }
}

/// A bare SYN offering only an MSS.
fn plain_syn_options() -> SynOptions {
    SynOptions { mss: Some(1460), ..SynOptions::default() }
}

fn child(stack: &NetStack, port: u16, client_port: u16) -> Option<Arc<TcpEntry>> {
    let key = TcpKey {
        local_ip: IpAddr::V4(SERVER), local_port: port,
        remote_ip: IpAddr::V4(SERVER), remote_port: client_port,
    };
    stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
}

/// The next TCP segment this stack transmitted, lifted out of its IPv4 packet.
pub(super) fn sent(lo: &crate::loopback::LoopbackDev) -> Option<alloc::vec::Vec<u8>> {
    let packet = lo.rx_pop()?;
    let data = packet.data();
    // Either family, since the cookie path is shared: an IPv6 packet carries
    // a fixed 40-byte header and no extension headers here.
    let at = if data.first()? >> 4 == 6 { crate::ipv6::IPV6_HDR_LEN }
        else { ((crate::ipv4::Ipv4Hdr::parse(data).ok()?.version_ihl & 0x0f) as usize) * 4 };
    Some(data[at..].to_vec())
}

/// The header of a segment this stack transmitted.
pub(super) fn head(segment: &[u8]) -> crate::tcp_hdr::TcpHdr {
    crate::tcp_hdr::parse_prevalidated(segment).expect("a well-formed segment")
}

/// The timestamp value a transmitted SYN-ACK offered, which the client echoes
/// back and which is where the option negotiation actually travels.
pub(super) fn tsval(segment: &[u8]) -> u32 {
    crate::tcp_hdr::parse_ts_option(segment).expect("a cookie SYN-ACK carries a timestamp").0
}

pub(super) fn drain(lo: &crate::loopback::LoopbackDev) { while lo.rx_pop().is_some() {} }

/// Fill the listener's single SYN-queue slot with a real half-open request.
fn fill_syn_queue(stack: &NetStack, iface: NetIfaceId, port: u16, lo: &crate::loopback::LoopbackDev) {
    deliver(stack, iface, port, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());
    assert!(child(stack, port, 40_001).is_some(), "the first SYN takes the one slot");
    drain(lo);
}

#[test]
fn a_full_syn_queue_answers_with_a_cookie_and_stores_nothing() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_401);
    fill_syn_queue(&stack, iface, 7_401, &lo);

    deliver(&stack, iface, 7_401, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());

    // The whole point: the request was answered and NOTHING was kept.
    assert!(child(&stack, 7_401, 40_002).is_none(), "a cookie handshake stores no child");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1,
        "the cookie took no backlog slot");
    let segment = sent(&lo).expect("the SYN was answered, not dropped");
    let synack = head(&segment);
    assert_eq!(synack.flags & (flags::SYN | flags::ACK), flags::SYN | flags::ACK);
    assert_eq!(synack.dst_port, 40_002);
    assert_eq!(synack.ack, CLIENT_SEQ.wrapping_add(1));
}

#[test]
fn the_acknowledgement_carrying_the_cookie_back_opens_the_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_402);
    fill_syn_queue(&stack, iface, 7_402, &lo);
    deliver(&stack, iface, 7_402, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let segment = sent(&lo).expect("cookie SYN-ACK");
    let synack = head(&segment);
    drain(&lo);

    // The client acknowledges the cookie, echoing the timestamp it was given.
    let echo = SynOptions { timestamp: Some((0x1111_3333, tsval(&segment))), ..SynOptions::default() };
    deliver(&stack, iface, 7_402, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), echo);

    let opened = child(&stack, 7_402, 40_002).expect("the cookie rebuilt the connection");
    let conn = opened.conn.lock();
    assert_eq!(conn.state, TcpState::Established);
    // The MSS came back out of the cookie, rounded down to the table.
    assert_eq!(conn.peer_mss, crate::syncookies::MSSTAB_V4[3]);
    // ... and so did the options, out of the timestamp echo.
    assert!(conn.wscale_ok);
    assert_eq!(conn.rcv_wscale, 7);
    assert!(conn.sack_ok);
    drop(conn);
    assert_eq!(listener.accept_q.lock().len(), 1, "the program can accept it");
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    // The rebuilt child never held a SYN-RECV slot, so the one real request
    // still in the queue must be the only occupant.
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
}

#[test]
fn a_forged_acknowledgement_opens_nothing() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_403);
    fill_syn_queue(&stack, iface, 7_403, &lo);
    deliver(&stack, iface, 7_403, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("cookie SYN-ACK"));
    drain(&lo);

    // Off by one in the cookie, and in the peer sequence the cookie binds.
    deliver(&stack, iface, 7_403, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(2), SynOptions::default());
    assert!(child(&stack, 7_403, 40_002).is_none(), "a wrong cookie opens nothing");
    deliver(&stack, iface, 7_403, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(9),
        synack.seq.wrapping_add(1), SynOptions::default());
    assert!(child(&stack, 7_403, 40_002).is_none(), "a replayed cookie opens nothing");
    // A cookie minted for one port is not a cookie for another.
    deliver(&stack, iface, 7_403, 40_003, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), SynOptions::default());
    assert!(child(&stack, 7_403, 40_003).is_none(), "a cookie does not travel between tuples");
}

#[test]
fn a_listener_that_never_overflowed_ignores_an_acknowledgement() {
    // Every listener would otherwise spend a keyed hash on every stray
    // acknowledgement it receives.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo, _listener) = fixture(&stack, 7_404);
    deliver(&stack, iface, 7_404, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        0x1234_5678, SynOptions::default());
    assert!(child(&stack, 7_404, 40_002).is_none());
}

#[test]
fn a_reset_reaching_a_listener_is_not_a_cookie() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_405);
    fill_syn_queue(&stack, iface, 7_405, &lo);
    deliver(&stack, iface, 7_405, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("cookie SYN-ACK"));
    drain(&lo);
    deliver(&stack, iface, 7_405, 40_002, flags::ACK | flags::RST, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), SynOptions::default());
    assert!(child(&stack, 7_405, 40_002).is_none(), "a reset never opens a connection");
}

#[test]
fn a_handshake_that_offered_no_options_rebuilds_with_none() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_406);
    fill_syn_queue(&stack, iface, 7_406, &lo);
    deliver(&stack, iface, 7_406, 40_002, flags::SYN, CLIENT_SEQ, 0, plain_syn_options());
    let synack = head(&sent(&lo).expect("cookie SYN-ACK"));
    drain(&lo);
    deliver(&stack, iface, 7_406, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), SynOptions::default());
    let opened = child(&stack, 7_406, 40_002).expect("rebuilt");
    let conn = opened.conn.lock();
    assert_eq!(conn.state, TcpState::Established);
    assert!(!conn.ts_enabled);
    assert!(!conn.wscale_ok);
    assert!(!conn.sack_ok);
}

#[test]
fn a_syn_queue_with_room_still_stores_a_request() {
    // Mode 1 falls back only when the queue is full; it must not replace the
    // ordinary passive open.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_407);
    deliver(&stack, iface, 7_407, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());
    assert!(child(&stack, 7_407, 40_001).is_some(), "a request with room is stored");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert!(listener.no_recent_synq_overflow(crate::tcp_conn::ka_now_ns()),
        "an ordinary passive open is not an overflow");
    drain(&lo);
}

/// The IPv6 half runs the SAME wiring — only the hash record and the MSS table
/// differ — so what this pins is that the family reaches both of them.
mod ipv6 {
    use super::*;

    const SERVER6: Ipv6Addr = Ipv6Addr::LOOPBACK;

    fn deliver6(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
                flag_bits: u8, seq: u32, ack: u32, opts: SynOptions)
    {
        let opt_len = opts.encoded_len();
        let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len];
        opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
        let mut hdr = crate::tcp_hdr::TcpHdr {
            src_port: client_port, dst_port: port, seq, ack,
            data_offset: opts.data_offset(), flags: flag_bits,
            window: 65_535, checksum: 0, urg_ptr: 0,
        };
        let peer = IpAddr::V6(SERVER6);
        hdr.build_into_ip(peer, peer, &mut buf);
        stack.deliver_tcp_packet(0, iface, peer, peer, &buf, &buf).expect("deliver");
    }

    fn child6(stack: &NetStack, port: u16, client_port: u16) -> Option<Arc<TcpEntry>> {
        let key = TcpKey {
            local_ip: IpAddr::V6(SERVER6), local_port: port,
            remote_ip: IpAddr::V6(SERVER6), remote_port: client_port,
        };
        stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
    }

    #[test]
    fn a_full_ipv6_syn_queue_answers_with_a_cookie_and_the_v6_table() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (iface, lo) = stack.register_loopback();
        let listener = stack.tcp_listen_ip(IpAddr::V6(SERVER6), 7_408, true).expect("listen");
        listener.backlog.store(1, ::core::sync::atomic::Ordering::Release);
        deliver6(&stack, iface, 7_408, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());
        assert!(child6(&stack, 7_408, 40_001).is_some(), "the first SYN takes the one slot");
        drain(&lo);

        deliver6(&stack, iface, 7_408, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
        assert!(child6(&stack, 7_408, 40_002).is_none(), "a cookie handshake stores no child");
        let segment = sent(&lo).expect("the SYN was answered, not dropped");
        let synack = head(&segment);
        assert_eq!(synack.flags & (flags::SYN | flags::ACK), flags::SYN | flags::ACK);
        drain(&lo);

        let echo = SynOptions { timestamp: Some((0x1111_3333, tsval(&segment))),
                                ..SynOptions::default() };
        deliver6(&stack, iface, 7_408, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
            synack.seq.wrapping_add(1), echo);
        let opened = child6(&stack, 7_408, 40_002).expect("the cookie rebuilt the connection");
        let conn = opened.conn.lock();
        assert_eq!(conn.state, TcpState::Established);
        // 1460 rounds down into the IPv6 table, not the IPv4 one.
        assert_eq!(conn.peer_mss, crate::syncookies::MSSTAB_V6[2]);
        assert!(conn.sack_ok);
        assert_eq!(conn.rcv_wscale, 7);
    }
}

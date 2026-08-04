// Passive fast open end to end, over real segments on the delivery path: the
// cookie a client asks for arrives on the SYN-ACK, presenting it back puts the
// SYN's data straight into an accepted connection, and every way of getting it
// wrong leaves an ordinary handshake behind.
//
// The ladder itself is unit-tested in `tcp_fastopen/server_tests.rs`; what is
// asserted here is that the passive-open path is wired to it — that the
// decision reaches the SYN-ACK's option area, that the payload is delivered
// before the acknowledgement covering it is built, and that the accept queue
// and the fast-open bound are accounted the way the decision said.

use super::*;
use crate::tcp_conn::fastopen::{Cookie, FastOpen};
use crate::tcp_conn::syn_opts::SynOptions;
use crate::tcp_fastopen::{TFO_DEFAULT, TFO_SERVER_ENABLE};
use crate::tcp_state::TcpState;
use ::core::sync::atomic::Ordering;

const SERVER: Ipv4Addr = Ipv4Addr::LOOPBACK;
const CLIENT_SEQ: u32 = 0x2000_0000;

/// A listener with passive fast open enabled, a bound of `max_qlen`, and a
/// drawn namespace key.
fn fixture(stack: &NetStack, port: u16, max_qlen: i32)
    -> (NetIfaceId, Arc<TcpListenEntry>)
{
    let (iface, _lo_dev) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, port, true).expect("listen");
    let namespace = &listener.owner.net_namespace;
    crate::net_ns::materialize_state(namespace);
    crate::sysctl::set_value(namespace, crate::net_ns::NetSysctlKey::TcpFastopen,
        (TFO_DEFAULT | TFO_SERVER_ENABLE) as i64).expect("enable the server half");
    crate::tcp_fastopen::init_key_once(namespace);
    listener.fastopen.set_max_qlen(max_qlen);
    (iface, listener)
}

/// Deliver one SYN carrying `option` and `payload`. Returns the child it
/// opened, if the SYN reached the listener at all.
fn syn(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
       option: Option<Cookie>, payload: &[u8]) -> Option<Arc<TcpEntry>>
{
    syn_flags(stack, iface, port, client_port, option, payload, crate::tcp_hdr::flags::SYN)
}

/// Deliver one SYN with an explicit control-flag set. # C: O(segment)
fn syn_flags(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
             option: Option<Cookie>, payload: &[u8], flags: u8) -> Option<Arc<TcpEntry>>
{
    let opts = SynOptions { mss: Some(1460), fastopen: option, ..SynOptions::default() };
    let opt_len = opts.encoded_len();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len + payload.len()];
    opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
    let at = crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len;
    buf[at..].copy_from_slice(payload);
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: client_port, dst_port: port,
        seq: CLIENT_SEQ, ack: 0, data_offset: opts.data_offset(),
        flags,
        window: 65_535, checksum: 0, urg_ptr: 0,
    };
    hdr.build_into(SERVER, SERVER, &mut buf);
    let peer = IpAddr::V4(SERVER);
    stack.deliver_tcp_packet(0, iface, peer, IpAddr::V4(SERVER), &buf, &buf)
        .expect("deliver SYN");
    let key = TcpKey {
        local_ip: IpAddr::V4(SERVER), local_port: port,
        remote_ip: peer, remote_port: client_port,
    };
    stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
}

/// The fast-open option of the SYN-ACK this child sent, read back off the
/// segment the retransmit queue holds — the same bytes that went to the wire.
fn synack_option(server: &Arc<TcpEntry>) -> FastOpen {
    let c = server.conn.lock();
    let front = c.retx_q.front().expect("the SYN-ACK is held for retransmit");
    let segment = c.build_retx(front);
    crate::tcp_conn::fastopen::parse(&segment, true)
}

/// The acknowledgement number the SYN-ACK carries.
fn synack_ack(server: &Arc<TcpEntry>) -> u32 {
    let c = server.conn.lock();
    let front = c.retx_q.front().expect("the SYN-ACK is held for retransmit");
    let segment = c.build_retx(front);
    crate::tcp_hdr::parse_prevalidated(&segment).expect("a well-formed SYN-ACK").ack
}

/// Ask for a cookie and read the one the SYN-ACK offers.
fn obtain_cookie(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16) -> Cookie {
    let server = syn(stack, iface, port, client_port, Some(Cookie::request(false)), b"")
        .expect("the SYN opened a request");
    let FastOpen::Cookie(c) = synack_option(&server)
        else { unreachable!("a cookie request is answered on the SYN-ACK") };
    c
}

#[test]
fn a_loopback_fast_open_success_does_not_clear_the_blackhole_recurrence() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (_iface, _lo) = stack.register_loopback();
    let entry = TcpEntry::new(TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(SERVER), port: 40_001 },
        Endpoint { ip: IpAddr::V4(SERVER), port: 40_002 }, 1));
    assert!(super::confirmed_on_loopback(&stack, &entry));
}

#[test]
fn an_absent_egress_is_not_treated_as_loopback_for_blackhole_reset() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let entry = TcpEntry::new(TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(SERVER), port: 40_003 },
        Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port: 40_004 }, 1));
    assert!(!super::confirmed_on_loopback(&stack, &entry));
}

#[test]
fn a_cookie_request_is_answered_on_the_syn_ack_without_completing_anything() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 701, 4);
    let server = syn(&stack, iface, 701, 50_701, Some(Cookie::request(false)), b"")
        .expect("the SYN opened a request");

    let FastOpen::Cookie(c) = synack_option(&server)
        else { unreachable!("a cookie request is answered on the SYN-ACK") };
    assert_eq!(c.len(), crate::tcp_conn::fastopen::COOKIE_SIZE);
    assert_eq!(server.conn.lock().state, TcpState::SynRecv,
        "asking for a cookie opens an ordinary handshake");
    assert!(listener.accept_q.lock().is_empty(), "and publishes nothing to accept");
    assert_eq!(listener.fastopen.qlen(), 0, "and charges nothing against the bound");
}

#[test]
fn presenting_the_cookie_delivers_the_syns_data_into_an_accepted_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 702, 4);
    let cookie = obtain_cookie(&stack, iface, 702, 50_702);

    let server = syn(&stack, iface, 702, 50_703, Some(cookie), b"GET /")
        .expect("the SYN opened a child");
    let accepted = stack.tcp_accept(&listener)
        .expect("a fast-open child is acceptable at its SYN");
    assert!(Arc::ptr_eq(&accepted, &server));
    assert_eq!(stack.tcp_recv(&accepted, 64), b"GET /",
        "the data the SYN carried is readable before the handshake finishes");
    let conn = server.conn.lock();
    assert_eq!(conn.state, TcpState::SynRecv,
        "the acknowledgement completing the handshake is still outstanding");
    assert_eq!(conn.data_segs_in, 1);
    assert_eq!(conn.bytes_received, b"GET /".len() as u64);
    drop(conn);
    assert_eq!(listener.fastopen.qlen(), 1, "the request is charged against the bound");
}

#[test]
fn a_fast_open_syn_fin_delivers_data_then_enters_close_wait() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 716, 4);
    let cookie = obtain_cookie(&stack, iface, 716, 50_716);
    let payload = b"GET /";
    let server = syn_flags(&stack, iface, 716, 50_717, Some(cookie), payload,
        crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::FIN).expect("a child");

    let accepted = stack.tcp_accept(&listener).expect("a fast-open child is acceptable at its SYN");
    assert!(Arc::ptr_eq(&accepted, &server));
    assert_eq!(stack.tcp_recv(&accepted, 64), payload);
    let (state, rcv_nxt) = { let conn = server.conn.lock(); (conn.state, conn.rcv_nxt) };
    assert_eq!(state, TcpState::CloseWait);
    assert_eq!(rcv_nxt, CLIENT_SEQ.wrapping_add(1 + payload.len() as u32 + 1));
    assert_eq!(synack_ack(&server), rcv_nxt);
}

#[test]
fn the_syn_ack_acknowledges_the_data_it_took() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 703, 4);
    let cookie = obtain_cookie(&stack, iface, 703, 50_704);
    let server = syn(&stack, iface, 703, 50_705, Some(cookie), b"GET /").expect("a child");
    // Without this the peer retransmits bytes the program has already been
    // handed, which is the whole cost the feature exists to avoid.
    assert_eq!(synack_ack(&server), CLIENT_SEQ.wrapping_add(1 + 5),
        "the SYN-ACK covers the SYN and the five bytes behind it");
    assert_eq!(synack_option(&server), FastOpen::Absent,
        "a cookie that is still current is not handed back");
}

#[test]
fn a_forged_cookie_gets_a_fresh_one_and_an_ordinary_handshake() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 704, 4);
    let forged = Cookie::new(&[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef], false)
        .expect("a permitted length");
    let server = syn(&stack, iface, 704, 50_706, Some(forged), b"GET /")
        .expect("the SYN opened a request");

    assert_eq!(server.conn.lock().state, TcpState::SynRecv);
    assert!(listener.accept_q.lock().is_empty(), "nothing is published to accept");
    assert!(server.conn.lock().recv_buf.is_empty(),
        "the data is not delivered: nothing proved the peer's address");
    assert_eq!(synack_ack(&server), CLIENT_SEQ.wrapping_add(1),
        "so the SYN-ACK covers the SYN alone and the peer will retransmit");
    assert!(matches!(synack_option(&server), FastOpen::Cookie(_)),
        "the client is handed a usable cookie so the next connection can fast open");
    assert_eq!(listener.fastopen.qlen(), 0);
}

#[test]
fn a_listener_with_no_bound_answers_a_cookie_request_with_nothing() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 705, 0);
    let server = syn(&stack, iface, 705, 50_707, Some(Cookie::request(false)), b"")
        .expect("the SYN opened a request");
    assert_eq!(synack_option(&server), FastOpen::Absent,
        "a listener that admits no fast open mints no cookie either");
    assert_eq!(listener.fastopen.qlen(), 0);
}

#[test]
fn a_full_bound_falls_back_to_an_ordinary_handshake() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 706, 1);
    let cookie = obtain_cookie(&stack, iface, 706, 50_708);
    let first = syn(&stack, iface, 706, 50_709, Some(cookie), b"one").expect("a child");
    assert_eq!(listener.fastopen.qlen(), 1);

    let second = syn(&stack, iface, 706, 50_710, Some(cookie), b"two")
        .expect("the SYN still opens a request");
    assert_eq!(second.conn.lock().state, TcpState::SynRecv);
    assert!(second.conn.lock().recv_buf.is_empty(),
        "a full bound declines the data rather than the connection");
    assert_eq!(synack_option(&second), FastOpen::Absent,
        "and spends no hash on a cookie it would not have used");
    assert_eq!(listener.fastopen.qlen(), 1);
    assert!(Arc::ptr_eq(&stack.tcp_accept(&listener).expect("the first child"), &first));
}

#[test]
fn data_in_a_syn_that_presented_nothing_is_not_taken() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 707, 4);
    let server = syn(&stack, iface, 707, 50_711, None, b"GET /")
        .expect("the SYN opened a request");
    assert!(server.conn.lock().recv_buf.is_empty());
    assert_eq!(synack_option(&server), FastOpen::Absent);
    assert!(listener.accept_q.lock().is_empty());
    assert_eq!(listener.fastopen.qlen(), 0);
}

#[test]
fn the_server_half_of_the_sysctl_gates_the_whole_path() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 708, 4);
    let cookie = obtain_cookie(&stack, iface, 708, 50_712);
    crate::sysctl::set_value(&listener.owner.net_namespace,
        crate::net_ns::NetSysctlKey::TcpFastopen, TFO_DEFAULT as i64).expect("clear it");

    let server = syn(&stack, iface, 708, 50_713, Some(cookie), b"GET /")
        .expect("the SYN opened a request");
    assert_eq!(synack_option(&server), FastOpen::Absent);
    assert!(server.conn.lock().recv_buf.is_empty());
    assert!(listener.accept_q.lock().is_empty());
}

#[test]
fn a_waived_cookie_takes_the_data_from_a_syn_that_presented_none() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 709, 4);
    listener.fastopen_no_cookie.store(true, Ordering::Release);

    let server = syn(&stack, iface, 709, 50_714, None, b"GET /").expect("a child");
    let accepted = stack.tcp_accept(&listener).expect("acceptable at its SYN");
    assert!(Arc::ptr_eq(&accepted, &server));
    assert_eq!(stack.tcp_recv(&accepted, 64), b"GET /");
    assert_eq!(synack_option(&server), FastOpen::Absent, "no cookie is minted for a waiver");
    assert_eq!(listener.fastopen.qlen(), 1);
}

#[test]
fn a_listener_key_displaces_the_namespaces_for_that_listener() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 710, 4);
    let from_namespace = obtain_cookie(&stack, iface, 710, 50_715);
    listener.fastopen.set_keys(crate::tcp_fastopen::KeyCtx::new(
        crate::tcp_fastopen::Key::new([0x77; crate::tcp_fastopen::KEY_LEN]), None));
    let from_listener = obtain_cookie(&stack, iface, 710, 50_716);
    assert_ne!(from_namespace.as_bytes(), from_listener.as_bytes());

    // And the namespace's cookie no longer opens this listener.
    let server = syn(&stack, iface, 710, 50_717, Some(from_namespace), b"GET /")
        .expect("a request");
    assert!(server.conn.lock().recv_buf.is_empty());
    assert_eq!(listener.fastopen.qlen(), 0);
}

#[test]
fn a_cookie_minted_under_the_retired_key_is_honoured_and_upgraded() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 711, 4);
    let old = obtain_cookie(&stack, iface, 711, 50_718);
    // Rotate: the drawn key becomes the backup, a new one becomes primary.
    let drawn = crate::tcp_fastopen::ns_keys(&listener.owner.net_namespace).expect("drawn");
    listener.fastopen.set_keys(crate::tcp_fastopen::KeyCtx::new(
        crate::tcp_fastopen::Key::new([0x31; crate::tcp_fastopen::KEY_LEN]),
        Some(drawn.primary)));

    let server = syn(&stack, iface, 711, 50_719, Some(old), b"GET /").expect("a child");
    let accepted = stack.tcp_accept(&listener).expect("the rotation did not break it");
    assert!(Arc::ptr_eq(&accepted, &server));
    assert_eq!(stack.tcp_recv(&accepted, 64), b"GET /");
    let FastOpen::Cookie(fresh) = synack_option(&server)
        else { unreachable!("a backup-key match hands back a current cookie") };
    assert_ne!(fresh.as_bytes(), old.as_bytes(), "the client is moved to the current key");
}

#[test]
fn the_experimental_kind_is_answered_under_the_experimental_kind() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 712, 4);
    let server = syn(&stack, iface, 712, 50_720, Some(Cookie::request(true)), b"")
        .expect("a request");
    let FastOpen::Cookie(c) = synack_option(&server)
        else { unreachable!("a cookie request is answered on the SYN-ACK") };
    assert!(c.exp, "a peer that speaks only the experimental kind must \
        recognise the reply");
}

#[test]
fn a_fast_open_child_is_published_once_and_gives_its_charge_back_on_completion() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 713, 4);
    listener.defer_accept.store(4, Ordering::Release);
    let cookie = obtain_cookie(&stack, iface, 713, 50_721);
    let server = syn(&stack, iface, 713, 50_722, Some(cookie), b"GET /").expect("a child");
    let accepted = stack.tcp_accept(&listener).expect("acceptable at its SYN");
    assert_eq!(listener.fastopen.qlen(), 1);

    // A fast-open child is already acceptable; unlike an ordinary request,
    // TCP_DEFER_ACCEPT must not drop the acknowledgement that finishes it.
    let snd_nxt = server.conn.lock().snd_nxt;
    let rcv_nxt = server.conn.lock().rcv_nxt;
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: 50_722, dst_port: 713, seq: rcv_nxt, ack: snd_nxt, data_offset: 5,
        flags: crate::tcp_hdr::flags::ACK, window: 65_535, checksum: 0, urg_ptr: 0,
    };
    hdr.build_into(SERVER, SERVER, &mut buf);
    stack.deliver_tcp_packet(0, iface, IpAddr::V4(SERVER), IpAddr::V4(SERVER), &buf, &buf)
        .expect("deliver the acknowledgement");

    assert_eq!(server.conn.lock().state, TcpState::Established);
    assert_eq!(listener.fastopen.qlen(), 0, "the finished handshake frees its slot");
    assert!(stack.tcp_accept(&listener).is_none(),
        "the child was published at its SYN and must not be published again");
    assert!(Arc::ptr_eq(&accepted, &server));
}

/// A real client connection whose SYN is built by the client mechanism and
/// delivered to a real listener, so both halves of the ladder run against one
/// another over the same bytes.
fn client_conn(client_port: u16, port: u16) -> crate::tcp_conn::TcpConn {
    crate::tcp_conn::TcpConn::new_client(
        crate::tcp_conn::Endpoint { ip: IpAddr::V4(SERVER), port: client_port },
        crate::tcp_conn::Endpoint { ip: IpAddr::V4(SERVER), port }, CLIENT_SEQ)
}

/// Deliver a segment the client built, and return the listener's child.
fn deliver_client(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
                  seg: &[u8]) -> Option<Arc<TcpEntry>>
{
    stack.deliver_tcp_packet(0, iface, IpAddr::V4(SERVER), IpAddr::V4(SERVER), seg, seg)
        .expect("deliver the client SYN");
    let key = TcpKey {
        local_ip: IpAddr::V4(SERVER), local_port: port,
        remote_ip: IpAddr::V4(SERVER), remote_port: client_port,
    };
    stack.inet_tables(0).tcp_conns.lock().get(&key).cloned()
}

#[test]
fn a_client_request_and_a_server_offer_meet_over_real_segments() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 730, 4);
    let mut client = client_conn(50_730, 730);

    // The client asks for a cookie the way a cache miss does.
    let (syn_seg, carried) = client.active_open_fastopen(Some(Cookie::request(false)), b"GET /")
        .expect("the open");
    let server = deliver_client(&stack, iface, 730, 50_730, &syn_seg).expect("a request");
    assert_eq!(carried, 5);

    // The listener declined the data — no cookie was presented — and offered
    // one instead. The client learns it and still owes its bytes.
    let FastOpen::Cookie(offered) = synack_option(&server)
        else { unreachable!("a cookie request is answered") };
    let synack = { let c = server.conn.lock(); let front = c.retx_q.front().unwrap();
        c.build_retx(front) };
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert_eq!(client.state, TcpState::Established, "the connection opened either way");
    let learned = client.fastopen_learned.expect("the answer was read");
    assert_eq!(learned.cookie, Some(offered));
    assert!(learned.failed, "the listener took none of the data, so it is still owed");
    assert_eq!(client.retx_q.iter().map(|s| s.payload.len()).sum::<usize>(), 5);
}

#[test]
fn a_client_presenting_the_offered_cookie_has_its_data_taken_and_acknowledged() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 731, 4);
    let offered = obtain_cookie(&stack, iface, 731, 50_731);

    let mut client = client_conn(50_732, 731);
    let (syn_seg, carried) = client.active_open_fastopen(Some(offered), b"GET /")
        .expect("the open");
    assert_eq!(carried, 5);
    let server = deliver_client(&stack, iface, 731, 50_732, &syn_seg).expect("a child");
    assert!(stack.tcp_accept(&listener).is_some(), "the child is acceptable at its SYN");

    let synack = { let c = server.conn.lock(); let front = c.retx_q.front().unwrap();
        c.build_retx(front) };
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert!(client.syn_data_acked, "the data rode the SYN and was acknowledged with it");
    assert!(client.retx_q.is_empty(), "nothing is owed");
    assert!(!client.fastopen_learned.expect("the answer was read").failed);
}

#[test]
fn a_client_whose_cookie_the_listener_rejects_still_gets_a_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 732, 4);
    let mut client = client_conn(50_733, 732);
    // A cookie from some other server: it cannot verify here.
    let (syn_seg, _) = client.active_open_fastopen(Some(Cookie::minted([0xee; 8], false)), b"GET /")
        .expect("the open");
    let server = deliver_client(&stack, iface, 732, 50_733, &syn_seg).expect("a request");

    let synack = { let c = server.conn.lock(); let front = c.retx_q.front().unwrap();
        c.build_retx(front) };
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert_eq!(client.state, TcpState::Established);
    let learned = client.fastopen_learned.expect("the answer was read");
    assert!(learned.cookie.is_some(),
        "the listener hands back a usable cookie rather than punishing the client");
    assert!(learned.failed, "and the data is retransmitted on the ordinary path");
}

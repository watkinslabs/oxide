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
    let opts = SynOptions { mss: Some(1460), fastopen: option, ..SynOptions::default() };
    let opt_len = opts.encoded_len();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len + payload.len()];
    opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
    let at = crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len;
    buf[at..].copy_from_slice(payload);
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: client_port, dst_port: port,
        seq: CLIENT_SEQ, ack: 0, data_offset: opts.data_offset(),
        flags: crate::tcp_hdr::flags::SYN,
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
    assert_eq!(server.conn.lock().state, TcpState::SynRecv,
        "the acknowledgement completing the handshake is still outstanding");
    assert_eq!(listener.fastopen.qlen(), 1, "the request is charged against the bound");
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
    let cookie = obtain_cookie(&stack, iface, 713, 50_721);
    let server = syn(&stack, iface, 713, 50_722, Some(cookie), b"GET /").expect("a child");
    let accepted = stack.tcp_accept(&listener).expect("acceptable at its SYN");
    assert_eq!(listener.fastopen.qlen(), 1);

    // The acknowledgement that finishes the handshake.
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

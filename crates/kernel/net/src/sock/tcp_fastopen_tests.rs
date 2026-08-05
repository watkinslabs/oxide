// The socket-layer hop: that the ladder is fed this socket's and this
// namespace's real state, and that its answer reaches the open.

use super::*;
use network_namespace::NetworkNamespaceRef;
use crate::addr::Ipv4Addr;
use crate::tcp_conn::fastopen::Cookie;
use crate::tcp_fastopen::{self, Open, Source, TFO_CLIENT_ENABLE, TFO_CLIENT_NO_COOKIE, TFO_DEFAULT,
    TFO_SERVER_ENABLE};
use crate::sock_opts::sol_tcp::apply::Effects;

fn src() -> IpAddr { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)) }
fn dst() -> IpAddr { IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)) }
fn cookie() -> Cookie { Cookie::minted([6; 8], false) }

fn socket() -> alloc::sync::Arc<InetSocket> {
    let namespace = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&namespace);
    socket_in(namespace)
}

fn socket_in(namespace: NetworkNamespaceRef) -> alloc::sync::Arc<InetSocket> {
    crate::net_ns::materialize_state(&namespace);
    alloc::sync::Arc::new(InetSocket::new_tcp_in(namespace))
}

#[test]
fn setsockopt_uses_its_socket_namespace_for_bits_and_key_initialization() {
    let first = crate::net_ns::test_support::allocate_namespace();
    let second = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&first);
    crate::net_ns::materialize_state(&second);
    crate::sysctl::set_value(&first, crate::net_ns::NetSysctlKey::TcpFastopen,
        (TFO_CLIENT_ENABLE | TFO_SERVER_ENABLE) as i64).expect("the first namespace write");
    let first_sock = socket_in(first.clone());
    let second_sock = socket_in(second.clone());

    assert_eq!(setsockopt_bits(&first_sock), TFO_CLIENT_ENABLE | TFO_SERVER_ENABLE);
    assert_eq!(setsockopt_bits(&second_sock), TFO_DEFAULT);
    complete_setsockopt(&first_sock, &Effects { fastopen_keys: true, ..Effects::default() });
    assert!(crate::tcp_fastopen::ns_keys(&first).is_some());
    assert_eq!(crate::tcp_fastopen::ns_keys(&second), None);
    complete_setsockopt(&second_sock, &Effects::default());
    assert_eq!(crate::tcp_fastopen::ns_keys(&second), None);
}

fn cache(sock: &InetSocket, cookie: Option<Cookie>) {
    // The same clock the plan reads it back with; the cache ages entries
    // against that clock and a stamp from any other one reads as stale.
    tcp_fastopen::cache_learned(&sock.owner.net_namespace, src(), dst(),
        crate::tcp_conn::ka_now_ns(), 1460,
        &tcp_fastopen::Learned { cookie, syn_lost: false, try_exp: tcp_fastopen::TRY_EXP_NONE,
            failed: false, data_acked: true, client_fail: tcp_fastopen::TFO_STATUS_NONE });
}

#[test]
fn a_socket_with_no_cached_cookie_asks_for_one_from_either_call() {
    let sock = socket();
    for source in [Source::Connect, Source::Write] {
        assert_eq!(plan(&sock, src(), dst(), source), Open::Request { exp: false });
    }
}

#[test]
fn a_cached_cookie_defers_a_connect_and_carries_a_write() {
    let sock = socket();
    cache(&sock, Some(cookie()));
    assert_eq!(plan(&sock, src(), dst(), Source::Connect), Open::Defer);
    assert_eq!(plan(&sock, src(), dst(), Source::Write), Open::Data { cookie: Some(cookie()) });
}

#[test]
fn the_cookie_consulted_is_the_one_for_this_address_pair() {
    let sock = socket();
    cache(&sock, Some(cookie()));
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    assert_eq!(plan(&sock, src(), elsewhere, Source::Connect), Open::Request { exp: false });
    assert_eq!(plan(&sock, elsewhere, dst(), Source::Connect), Open::Request { exp: false });
}

#[test]
fn the_socket_option_licenses_a_no_cookie_open_on_its_own() {
    let sock = socket();
    sock.opts.tcp.fastopen_no_cookie.store(true, ::core::sync::atomic::Ordering::Release);
    assert_eq!(plan(&sock, src(), dst(), Source::Write), Open::Data { cookie: None });
}

#[test]
fn the_namespace_bit_licenses_it_too_and_is_read_live() {
    let sock = socket();
    assert_eq!(plan(&sock, src(), dst(), Source::Write), Open::Request { exp: false });
    crate::sysctl::set_value(&sock.owner.net_namespace,
        crate::net_ns::NetSysctlKey::TcpFastopen,
        (tcp_fastopen::TFO_DEFAULT | TFO_CLIENT_NO_COOKIE) as i64).expect("the write");
    assert_eq!(plan(&sock, src(), dst(), Source::Write), Open::Data { cookie: None });
}

#[test]
fn a_paused_namespace_downgrades_every_open_in_it_to_a_bare_syn() {
    let sock = socket();
    cache(&sock, Some(cookie()));
    crate::sysctl::set_value(&sock.owner.net_namespace,
        crate::net_ns::NetSysctlKey::TcpFastopenBlackholeTimeout, 3600).expect("the write");
    tcp_fastopen::blackhole_disable(&sock.owner.net_namespace, crate::tcp_conn::ka_now_ns());
    assert_eq!(plan(&sock, src(), dst(), Source::Connect), Open::Plain);
    assert_eq!(plan(&sock, src(), dst(), Source::Write), Open::Plain);
    assert!(!confirming(&sock), "the pause is still running, so there is nothing to confirm");
}

#[test]
fn the_pause_is_read_from_the_sockets_own_namespace() {
    let paused = socket();
    let other = socket();
    for sock in [&paused, &other] {
        cache(sock, Some(cookie()));
        crate::sysctl::set_value(&sock.owner.net_namespace,
            crate::net_ns::NetSysctlKey::TcpFastopenBlackholeTimeout, 3600).expect("the write");
    }
    tcp_fastopen::blackhole_disable(&paused.owner.net_namespace, crate::tcp_conn::ka_now_ns());
    assert_eq!(plan(&paused, src(), dst(), Source::Write), Open::Plain);
    assert_eq!(plan(&other, src(), dst(), Source::Write), Open::Data { cookie: Some(cookie()) });
}

#[test]
fn what_the_decision_leaves_for_the_syn_is_the_option_and_the_payload() {
    assert_eq!(ActiveOpen::from(Open::Plain), ActiveOpen { option: None, with_data: false });
    assert_eq!(ActiveOpen::from(Open::Defer), ActiveOpen { option: None, with_data: false });
    assert_eq!(ActiveOpen::from(Open::Request { exp: true }),
        ActiveOpen { option: Some(Cookie::request(true)), with_data: false });
    assert_eq!(ActiveOpen::from(Open::Data { cookie: Some(cookie()) }),
        ActiveOpen { option: Some(cookie()), with_data: true });
    assert_eq!(ActiveOpen::from(Open::Data { cookie: None }),
        ActiveOpen { option: None, with_data: true });
    assert_eq!(ActiveOpen::from(Open::Request { exp: false }).payload(b"hi"), b"",
        "an open that is not carrying data must not put any in the SYN");
    assert_eq!(ActiveOpen::from(Open::Data { cookie: None }).payload(b"hi"), b"hi");
}

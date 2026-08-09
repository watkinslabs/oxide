// `TCP_SAVE_SYN` decides whether a half-open request carries a heap copy of
// the packet that opened it.
//
// A listener that never asked used to get one anyway, on every request, and
// the copy was thrown away at `accept`. That is the cost a SYN flood is
// trying to impose: with a full backlog of half-opens it is an allocation and
// up to `SAVED_SYN_MAX` bytes each, for bytes nobody can ever read. The
// reference records the packet only when the listening socket asked.

use super::*;
use crate::tcp_hdr::flags;
use super::tcp_syncookies_tests::{child, deliver, syn_options, CLIENT_SEQ, SERVER};

/// Send one SYN and report whether the request it created recorded the packet.
fn request_recorded_syn(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16)
    -> bool
{
    deliver(stack, iface, port, client_port, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let request = child(stack, port, client_port).expect("the SYN created a request");
    let recorded = request.conn.lock().syn_bytes.is_some();
    recorded
}

#[test]
fn a_listener_that_never_asked_records_nothing_for_its_requests() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, 7_701, true).expect("listen");
    assert_eq!(listener.save_syn.load(::core::sync::atomic::Ordering::Acquire), 0,
        "no socket asked");
    assert!(!request_recorded_syn(&stack, iface, 7_701, 40_201),
        "an unasked-for record is an allocation per half-open that nobody reads");
}

#[test]
fn a_listener_that_asked_records_the_opening_packet() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, 7_702, true).expect("listen");
    // Through the projection the option write uses, not by writing the
    // listener's copy directly: the projection is the only thing that carries
    // a socket option to the receive path.
    let opts = crate::sock::SockOpts::default();
    opts.tcp.save_syn.store(1, ::core::sync::atomic::Ordering::Release);
    crate::sock_opts::sol_tcp::apply::to_listener(&opts, &listener);
    assert_eq!(listener.save_syn.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert!(request_recorded_syn(&stack, iface, 7_702, 40_202));

    // Withdrawing it stops the next request recording anything.
    opts.tcp.save_syn.store(0, ::core::sync::atomic::Ordering::Release);
    crate::sock_opts::sol_tcp::apply::to_listener(&opts, &listener);
    assert!(!request_recorded_syn(&stack, iface, 7_702, 40_204));
}

#[test]
fn the_record_never_exceeds_the_headers_the_option_publishes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, 7_703, true).expect("listen");
    listener.save_syn.store(1, ::core::sync::atomic::Ordering::Release);
    deliver(&stack, iface, 7_703, 40_203, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let request = child(&stack, 7_703, 40_203).expect("the SYN created a request");
    let recorded = request.conn.lock().syn_bytes.clone().expect("the listener asked");
    assert!(recorded.len() <= crate::stack::SAVED_SYN_MAX,
        "a maximal network header plus a maximal TCP header, and no payload");
}

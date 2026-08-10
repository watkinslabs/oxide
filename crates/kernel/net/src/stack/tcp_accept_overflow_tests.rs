// What a listener does when its ACCEPT queue, not its SYN queue, is the one
// with no room — over real segments on the delivery path.
//
// The unit decisions live in `crate::listen_queue`; what is asserted here is
// that the delivery path is WIRED to them. Before this, a completed handshake
// the accept queue could not hold was DESTROYED: the peer, which had already
// seen the SYN-ACK and sent its acknowledgement, believed the connection was
// established and kept believing it until its own retransmits timed out. That
// is neither of the two behaviours the reference offers, so a program that
// simply had not called `accept` yet turned a transient backlog into a stalled
// connection.

use super::*;
use crate::tcp_hdr::flags;

use super::tcp_syncookies_tests::{child, deliver, drain, sent, head, syn_options, CLIENT_SEQ,
    SERVER};

/// A listener on the shared initial namespace with a materialised sysctl state,
/// so `tcp_abort_on_overflow` can be written for the run.
fn fixture(stack: &NetStack, port: u16, backlog: usize)
    -> (NetIfaceId, Arc<crate::loopback::LoopbackDev>, Arc<TcpListenEntry>)
{
    let (iface, lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, port, true).expect("listen");
    listener.backlog.store(backlog, ::core::sync::atomic::Ordering::Release);
    (iface, lo, listener)
}

/// Drive a full three-way handshake from `client_port` and leave the child in
/// whatever state the listener put it in.
fn handshake(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
             lo: &crate::loopback::LoopbackDev)
{
    deliver(stack, iface, port, client_port, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let Some(segment) = sent(lo) else { return };
    let synack = head(&segment);
    drain(lo);
    deliver(stack, iface, port, client_port, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), syn_options());
}

/// The rung that runs BEFORE a request is allocated. A listener whose program
/// has stopped accepting should not complete handshakes it can never hand
/// over, so the SYN is dropped where it arrives.
#[test]
fn a_syn_arriving_at_a_full_accept_queue_is_dropped_before_a_request_exists() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    // A backlog of zero holds exactly one child, which the first handshake
    // takes; the second SYN therefore meets a full accept queue.
    let (iface, lo, listener) = fixture(&stack, 7_501, 0);
    handshake(&stack, iface, 7_501, 40_001, &lo);
    assert_eq!(listener.accept_q.lock().len(), 1, "the first handshake was accepted");
    drain(&lo);

    deliver(&stack, iface, 7_501, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());

    assert!(child(&stack, 7_501, 40_002).is_none(),
        "a SYN meeting a full accept queue allocates no request");
    assert!(sent(&lo).is_none(), "and is answered with nothing at all");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0,
        "the reservation the dropped SYN took was given back");
}

/// The default: hold the request. The peer believes the connection is
/// established, so tearing it down here strands the peer; keeping the request
/// lets the handshake complete once the program drains its queue.
#[test]
fn a_completed_handshake_the_accept_queue_cannot_hold_keeps_its_request() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    // Backlog one, so two requests fit. Both handshakes start, the first
    // completes, and the backlog is then lowered under the second.
    let (iface, lo, listener) = fixture(&stack, 7_502, 1);
    deliver(&stack, iface, 7_502, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let first = head(&sent(&lo).expect("SYN-ACK for the first request"));
    drain(&lo);
    deliver(&stack, iface, 7_502, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let second = head(&sent(&lo).expect("SYN-ACK for the second request"));
    drain(&lo);

    deliver(&stack, iface, 7_502, 40_001, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        first.seq.wrapping_add(1), syn_options());
    assert_eq!(listener.accept_q.lock().len(), 1);
    // Now there is no room for the second child.
    listener.backlog.store(0, ::core::sync::atomic::Ordering::Release);
    assert!(listener.accept_queue_full(), "the accept queue is the one with no room");

    deliver(&stack, iface, 7_502, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        second.seq.wrapping_add(1), syn_options());

    assert!(super::tcp_syncookies_tests::request(&stack, 7_502, 40_002).is_some(),
        "the request was KEPT, not destroyed, and is still a request");
    assert_eq!(listener.accept_q.lock().len(), 1, "and was not queued for accept");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1,
        "it still holds its SYN-queue slot, so its SYN-ACK can retransmit");
    assert!(sent(&lo).is_none(), "nothing is sent: the peer's own retransmit drives the retry");
}

/// `tcp_abort_on_overflow=1` asks for the other behaviour — tell the peer at
/// once instead of leaving it to retry.
#[test]
fn abort_on_overflow_resets_the_completed_handshake_instead() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_503, 1);
    crate::net_ns::materialize_state(&network_namespace::initial());
    crate::sysctl::set_value_in(0, crate::net_ns::NetSysctlKey::TcpAbortOnOverflow, 1)
        .expect("the initial namespace has materialised state");

    deliver(&stack, iface, 7_503, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let first = head(&sent(&lo).expect("SYN-ACK for the first request"));
    drain(&lo);
    deliver(&stack, iface, 7_503, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let second = head(&sent(&lo).expect("SYN-ACK for the second request"));
    drain(&lo);
    deliver(&stack, iface, 7_503, 40_001, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        first.seq.wrapping_add(1), syn_options());
    listener.backlog.store(0, ::core::sync::atomic::Ordering::Release);

    deliver(&stack, iface, 7_503, 40_002, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        second.seq.wrapping_add(1), syn_options());

    assert!(child(&stack, 7_503, 40_002).is_none(), "the request was torn down");
    let reset = head(&sent(&lo).expect("the peer was told at once"));
    assert_ne!(reset.flags & flags::RST, 0, "and told with a reset");
    assert_eq!(reset.dst_port, 40_002);
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0,
        "the torn-down request gave its SYN-queue slot back");

    crate::sysctl::set_value_in(0, crate::net_ns::NetSysctlKey::TcpAbortOnOverflow, 0).ok();
}

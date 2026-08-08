// A DATAGRAM socketpair end and a supplied destination.
//
// A socketpair end is unbound and unpublished, but it still runs the datagram
// send: a supplied name is resolved by the ordinary lookup and outranks the
// peer the pair was created with. Before this the whole `UnixMsgPair` family
// was treated as the stream kind for the name rule, so the destination was
// dropped and the message went to the peer regardless of where it was
// addressed. A SEQPACKET pair keeps the peer, because its send discards
// `msg_namelen` before the datagram send ever sees it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::*;
use crate::control::{UnixScm, prepare_unix, send_unix_once};
use crate::test_support::unpoliced;

const AF_UNIX: u16 = 1;
const SNDBUF: usize = 64 * 1024;

fn task(pid: u32) -> sched::Task {
    sched::Task::new(pid, "send", sched::SchedClass::Normal { weight: 1024 })
}

/// An abstract `sockaddr_un`: family, then a leading NUL and the name bytes.
fn abstract_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&AF_UNIX.to_ne_bytes());
    out.push(0);
    out.extend_from_slice(name);
    out
}

/// Publish one datagram queue under an abstract name in the socket's namespace.
fn publish(socket: &Arc<net::sock::InetSocket>, name: &[u8]) -> Arc<net::UnixDgramQueue> {
    let mut path = Vec::new();
    path.push(0u8);
    path.extend_from_slice(name);
    let addr = net::UnixAddr::from_sockaddr_path(path);
    let queue = net::UnixDgramQueue::new();
    net::net_ns::unix_registry_for_addr_in(&socket.net_namespace, &addr)
        .dgram_bind_addr(addr, queue.clone()).unwrap();
    queue
}

fn pair_socket(kind: Arc<net::UnixMsgPair>) -> Arc<net::sock::InetSocket> {
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    *socket.kind.lock() = net::sock::SockKind::UnixMsgPair(kind, net::UnixEnd::A);
    socket
}

fn message(name: Option<Vec<u8>>, payload: &[u8]) -> Message {
    Message { payload: payload.to_vec(), requested_len: payload.len(), name,
        ..Message::default() }
}

#[test]
fn a_datagram_socketpair_resolves_a_supplied_destination_by_name() {
    let _policy = unpoliced();
    let task = task(620);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    let queue = publish(&socket, b"b1962-dgram-pair-named");
    let message = message(Some(abstract_name(b"b1962-dgram-pair-named")), b"named");

    let scm = prepare_unix(&ctx, &socket, &message, 0).unwrap().unwrap();
    assert!(matches!(scm, UnixScm::Datagram { .. }), "a named send resolves a destination queue");
    assert_eq!(send_unix_once(&ctx, &socket, &message, &scm, SNDBUF, 0, message.payload.len(),
        false), Ok(5));
    // The destination named on the message received it; the pair's own peer,
    // which a name-ignoring send would have used, saw nothing.
    assert_eq!(queue.pop().map(|dgram| dgram.payload), Some(b"named".to_vec()));
    let net::sock::SockKind::UnixMsgPair(pair, end) = &*socket.kind.lock() else { unreachable!() };
    assert_eq!(pair.recv(end.other(), SNDBUF), None);
}

#[test]
fn a_datagram_socketpair_with_no_destination_keeps_its_peer() {
    let _policy = unpoliced();
    let task = task(621);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    let message = message(None, b"peer");

    let scm = prepare_unix(&ctx, &socket, &message, 0).unwrap().unwrap();
    assert!(matches!(scm, UnixScm::Stream(_)), "an unnamed send keeps the pair");
    assert_eq!(send_unix_once(&ctx, &socket, &message, &scm, SNDBUF, 0, message.payload.len(),
        false), Ok(4));
    let net::sock::SockKind::UnixMsgPair(pair, end) = &*socket.kind.lock() else { unreachable!() };
    assert_eq!(pair.recv(end.other(), SNDBUF), Some(b"peer".to_vec()));
}

#[test]
fn a_seqpacket_socketpair_discards_a_supplied_destination() {
    let _policy = unpoliced();
    let task = task(622);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new());
    let queue = publish(&socket, b"b1962-seqpacket-pair-named");
    let message = message(Some(abstract_name(b"b1962-seqpacket-pair-named")), b"seq");

    let scm = prepare_unix(&ctx, &socket, &message, 0).unwrap().unwrap();
    assert!(matches!(scm, UnixScm::Stream(_)), "a seqpacket send never looks at the name");
    assert_eq!(send_unix_once(&ctx, &socket, &message, &scm, SNDBUF, 0, message.payload.len(),
        false), Ok(3));
    assert!(queue.pop().is_none());
    let net::sock::SockKind::UnixMsgPair(pair, end) = &*socket.kind.lock() else { unreachable!() };
    assert_eq!(pair.recv(end.other(), SNDBUF), Some(b"seq".to_vec()));
}

#[test]
fn a_datagram_socketpair_naming_an_unpublished_destination_is_refused() {
    let _policy = unpoliced();
    let task = task(623);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    let message = message(Some(abstract_name(b"b1962-dgram-pair-absent")), b"x");
    assert!(matches!(prepare_unix(&ctx, &socket, &message, 0), Some(Err(Error::Econnrefused))));
}

#[test]
fn a_shut_down_datagram_socketpair_reports_a_broken_pipe() {
    let _policy = unpoliced();
    let task = task(624);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    socket.write_shut.store(true, core::sync::atomic::Ordering::Release);
    let message = message(None, b"x");
    assert!(matches!(prepare_unix(&ctx, &socket, &message, 0), Some(Err(Error::Epipe))));
}

// --- who may address a connected datagram destination -----------------------
//
// A datagram socket that is connected accepts traffic from its connected peer
// alone: any other sender is refused with EPERM. The relation is by SOCKET
// identity, not by name — the destination's stored peer IS the sender, or the
// destination has no peer at all. Checked when a datagram socket connects and
// again on every individual send, and it sits after the destination has been
// resolved but before ANY of that destination's own state (its receive
// shutdown, its receive-queue bound) is consulted. This kernel had no such
// refusal on any datagram send path.

/// A published datagram socket and its receive queue, bound to an abstract name.
fn dgram_socket(name: &[u8]) -> (Arc<net::sock::InetSocket>, Arc<net::UnixDgramQueue>) {
    let socket = Arc::new(net::sock::InetSocket::new_unix_dgram());
    let queue = { let kind = socket.kind.lock();
        let net::sock::SockKind::UnixDgram(queue) = &*kind else { unreachable!() };
        queue.clone() };
    let mut path = Vec::new();
    path.push(0u8);
    path.extend_from_slice(name);
    let addr = net::UnixAddr::from_sockaddr_path(path);
    queue.set_bound(addr.clone());
    net::net_ns::unix_registry_for_addr_in(&socket.net_namespace, &addr)
        .dgram_bind_addr(addr, queue.clone()).unwrap();
    (socket, queue)
}

/// An unpublished, unbound datagram socket: it owns a queue, but no name.
fn unbound_dgram_socket() -> (Arc<net::sock::InetSocket>, Arc<net::UnixDgramQueue>) {
    let socket = Arc::new(net::sock::InetSocket::new_unix_dgram());
    let queue = { let kind = socket.kind.lock();
        let net::sock::SockKind::UnixDgram(queue) = &*kind else { unreachable!() };
        queue.clone() };
    (socket, queue)
}

/// Record `to` as `queue`'s connected peer, exactly as a connect would.
fn connect_to(queue: &Arc<net::UnixDgramQueue>, name: &[u8], to: &Arc<net::UnixDgramQueue>) {
    let mut path = Vec::new();
    path.push(0u8);
    path.extend_from_slice(name);
    queue.set_peer(net::UnixAddr::from_sockaddr_path(path), to.id());
}

#[test]
fn a_destination_connected_to_a_third_party_refuses_every_other_sender() {
    let _policy = unpoliced();
    let task = task(630);
    let ctx = SendContext::new(&task);
    let (sender, _sq) = dgram_socket(b"b1980-third-sender");
    let (_dest, dq) = dgram_socket(b"b1980-third-dest");
    let (_third, tq) = dgram_socket(b"b1980-third-party");
    connect_to(&dq, b"b1980-third-party", &tq);

    let message = message(Some(abstract_name(b"b1980-third-dest")), b"x");
    assert!(matches!(prepare_unix(&ctx, &sender, &message, 0), Some(Err(Error::Eperm))));
}

#[test]
fn a_destination_connected_back_to_the_sender_is_allowed_and_symmetric() {
    let _policy = unpoliced();
    let task = task(631);
    let ctx = SendContext::new(&task);
    let (sender, sq) = dgram_socket(b"b1980-sym-sender");
    let (_dest, dq) = dgram_socket(b"b1980-sym-dest");
    connect_to(&dq, b"b1980-sym-sender", &sq);

    let message = message(Some(abstract_name(b"b1980-sym-dest")), b"ok");
    let scm = prepare_unix(&ctx, &sender, &message, 0).unwrap().unwrap();
    let UnixScm::Datagram { symmetric, .. } = &scm else { panic!("a named datagram send") };
    assert!(*symmetric, "the destination's peer is the sender: no receive-queue bound applies");
    assert_eq!(send_unix_once(&ctx, &sender, &message, &scm, SNDBUF, 0, 2, false), Ok(2));
}

#[test]
fn an_unconnected_destination_accepts_any_sender() {
    let _policy = unpoliced();
    let task = task(632);
    let ctx = SendContext::new(&task);
    let (sender, _sq) = dgram_socket(b"b1980-open-sender");
    let (_dest, dq) = dgram_socket(b"b1980-open-dest");

    let message = message(Some(abstract_name(b"b1980-open-dest")), b"hi");
    let scm = prepare_unix(&ctx, &sender, &message, 0).unwrap().unwrap();
    let UnixScm::Datagram { symmetric, .. } = &scm else { panic!("a named datagram send") };
    assert!(!*symmetric, "an unconnected destination is not a symmetric pair");
    assert_eq!(send_unix_once(&ctx, &sender, &message, &scm, SNDBUF, 0, 2, false), Ok(2));
    assert_eq!(dq.pop().map(|dgram| dgram.payload), Some(b"hi".to_vec()));
}

#[test]
fn an_unbound_sender_the_destination_connected_to_is_recognised_as_symmetric() {
    let _policy = unpoliced();
    let task = task(633);
    let ctx = SendContext::new(&task);
    // The sender never bound a name, so a name-keyed comparison has nothing to
    // compare and reports "not symmetric" — while the destination's peer IS
    // this socket. Identity settles it.
    let (sender, sq) = unbound_dgram_socket();
    let (_dest, dq) = dgram_socket(b"b1980-unbound-dest");
    connect_to(&dq, b"b1980-unbound-sender-name", &sq);
    assert!(sq.bound().is_none());

    let message = message(Some(abstract_name(b"b1980-unbound-dest")), b"u");
    let scm = prepare_unix(&ctx, &sender, &message, 0).unwrap().unwrap();
    let UnixScm::Datagram { symmetric, .. } = &scm else { panic!("a named datagram send") };
    assert!(*symmetric, "the destination's peer is this queue, whatever it is named");
    assert_eq!(send_unix_once(&ctx, &sender, &message, &scm, SNDBUF, 0, 1, false), Ok(1));
}

#[test]
fn the_refusal_outranks_the_destinations_receive_shutdown() {
    let _policy = unpoliced();
    let task = task(634);
    let ctx = SendContext::new(&task);
    let (sender, _sq) = dgram_socket(b"b1980-order-sender");
    let (_dest, dq) = dgram_socket(b"b1980-order-dest");
    let (_third, tq) = dgram_socket(b"b1980-order-third");
    dq.shutdown_reader();
    let message = message(Some(abstract_name(b"b1980-order-dest")), b"o");

    // Destination unconnected: its own shut-down receive half decides, and it
    // only decides once the send is committed.
    let scm = prepare_unix(&ctx, &sender, &message, 0).unwrap().unwrap();
    assert_eq!(send_unix_once(&ctx, &sender, &message, &scm, SNDBUF, 0, 1, false),
        Err(Error::Epipe));

    // Same destination, now connected to a third party: the refusal lands
    // first, before that state is ever consulted.
    connect_to(&dq, b"b1980-order-third", &tq);
    assert!(matches!(prepare_unix(&ctx, &sender, &message, 0), Some(Err(Error::Eperm))));
}

#[test]
fn the_senders_own_shut_down_write_half_outranks_the_refusal() {
    let _policy = unpoliced();
    let task = task(635);
    let ctx = SendContext::new(&task);
    let (sender, _sq) = dgram_socket(b"b1980-wshut-sender");
    let (_dest, dq) = dgram_socket(b"b1980-wshut-dest");
    let (_third, tq) = dgram_socket(b"b1980-wshut-third");
    connect_to(&dq, b"b1980-wshut-third", &tq);
    sender.write_shut.store(true, core::sync::atomic::Ordering::Release);

    let message = message(Some(abstract_name(b"b1980-wshut-dest")), b"w");
    assert!(matches!(prepare_unix(&ctx, &sender, &message, 0), Some(Err(Error::Epipe))));
}

#[test]
fn a_datagram_socketpair_may_not_address_a_connected_destination() {
    let _policy = unpoliced();
    let task = task(636);
    let ctx = SendContext::new(&task);
    // Nothing can ever be connected to a socketpair end — it publishes no
    // name — so it is never the destination's peer, and a destination that
    // has one refuses it.
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    let (_third, tq) = dgram_socket(b"b1980-pair-third");
    let queue = publish(&socket, b"b1980-pair-dest");
    connect_to(&queue, b"b1980-pair-third", &tq);

    let message = message(Some(abstract_name(b"b1980-pair-dest")), b"p");
    assert!(matches!(prepare_unix(&ctx, &socket, &message, 0), Some(Err(Error::Eperm))));
}

#[test]
fn a_datagram_socketpair_may_address_an_unconnected_destination() {
    let _policy = unpoliced();
    let task = task(637);
    let ctx = SendContext::new(&task);
    let socket = pair_socket(net::UnixMsgPair::new_datagram());
    let queue = publish(&socket, b"b1980-pair-open");

    let message = message(Some(abstract_name(b"b1980-pair-open")), b"p");
    let scm = prepare_unix(&ctx, &socket, &message, 0).unwrap().unwrap();
    assert_eq!(send_unix_once(&ctx, &socket, &message, &scm, SNDBUF, 0, 1, false), Ok(1));
    assert_eq!(queue.pop().map(|dgram| dgram.payload), Some(b"p".to_vec()));
}

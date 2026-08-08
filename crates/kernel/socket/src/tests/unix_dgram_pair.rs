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

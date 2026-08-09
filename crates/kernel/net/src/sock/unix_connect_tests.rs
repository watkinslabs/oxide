// AF_UNIX stream connect against a real listener — the ladder and the
// backlog wait, exercised through the socket sleep queue rather than
// described in a comment. `connect` here is the same work function the ABI
// shim calls; nothing is stubbed.

use alloc::sync::Arc;

use super::{bind, connect, listen, BoundAddr, InetSocket, RemoteAddr, SockKind};
use crate::NetError;

fn listener_on(name: &[u8]) -> Arc<InetSocket> {
    let sock = Arc::new(InetSocket::new_unix_in(network_namespace::initial()));
    let addr = crate::UnixAddr::from_sockaddr_path(name.to_vec());
    bind(&sock, BoundAddr::UnixListener(addr)).expect("bind");
    sock
}

fn client() -> Arc<InetSocket> {
    Arc::new(InetSocket::new_unix_in(network_namespace::initial()))
}

#[test]
fn connect_to_an_unpublished_name_is_refused() {
    let sock = client();
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-absent".to_vec());
    assert_eq!(connect(&sock, RemoteAddr::Unix(addr), true), Err(NetError::Econnrefused));
}

#[test]
fn connect_to_a_bound_but_unlistening_name_is_refused() {
    let _l = listener_on(b"\0b2040-bound-only");
    let sock = client();
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-bound-only".to_vec());
    assert_eq!(connect(&sock, RemoteAddr::Unix(addr), true), Err(NetError::Econnrefused));
}

#[test]
fn connect_to_a_listener_establishes_and_queues_for_accept() {
    let l = listener_on(b"\0b2040-accepting");
    listen(&l, 4).expect("listen");
    let sock = client();
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-accepting".to_vec());
    connect(&sock, RemoteAddr::Unix(addr), true).expect("connect");
    assert!(matches!(*sock.kind.lock(), SockKind::Unix(_, _)));
    super::accept(&l).expect("the connect must be acceptable");
}

#[test]
fn a_second_connect_on_an_established_stream_returns_eisconn() {
    let l = listener_on(b"\0b2040-eisconn");
    listen(&l, 4).expect("listen");
    let sock = client();
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-eisconn".to_vec());
    connect(&sock, RemoteAddr::Unix(addr.clone()), true).expect("connect");
    assert_eq!(connect(&sock, RemoteAddr::Unix(addr), true), Err(NetError::Eisconn));
}

#[test]
fn connect_on_a_listening_socket_is_invalid() {
    let l = listener_on(b"\0b2040-listener-connect");
    listen(&l, 4).expect("listen");
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-listener-connect".to_vec());
    assert_eq!(connect(&l, RemoteAddr::Unix(addr), true), Err(NetError::Einval));
}

#[test]
fn a_nonblocking_connect_to_a_full_backlog_reports_would_block() {
    let l = listener_on(b"\0b2040-full-nonblock");
    listen(&l, 0).expect("listen");
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-full-nonblock".to_vec());
    // A `listen(0)` queue holds exactly one pending connection, so the
    // second connect finds no room.
    connect(&client(), RemoteAddr::Unix(addr.clone()), true).expect("connect into backlog");
    assert_eq!(connect(&client(), RemoteAddr::Unix(addr), true), Err(NetError::Eagain));
}

#[test]
fn a_timed_connect_to_a_full_backlog_gives_up_when_the_deadline_passes() {
    let l = listener_on(b"\0b2040-full-timeo");
    listen(&l, 0).expect("listen");
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-full-timeo".to_vec());
    connect(&client(), RemoteAddr::Unix(addr.clone()), true).expect("connect into backlog");
    let sock = client();
    sock.opts.base.sndtimeo_ns.store(20_000_000, core::sync::atomic::Ordering::Release);
    assert_eq!(connect(&sock, RemoteAddr::Unix(addr), false), Err(NetError::Eagain));
}

#[test]
fn a_blocking_connect_parks_on_the_backlog_and_completes_when_accept_frees_a_slot() {
    let l = listener_on(b"\0b2040-park-and-wake");
    listen(&l, 0).expect("listen");
    let addr = crate::UnixAddr::from_sockaddr_path(b"\0b2040-park-and-wake".to_vec());
    connect(&client(), RemoteAddr::Unix(addr.clone()), true).expect("connect into backlog");

    let sock = client();
    let waiter = sock.clone();
    let waiter_addr = addr.clone();
    let finished = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let signal = finished.clone();
    let joiner = std::thread::spawn(move || {
        let r = connect(&waiter, RemoteAddr::Unix(waiter_addr), false);
        signal.store(true, core::sync::atomic::Ordering::Release);
        r
    });

    // The blocking connect must be parked on the socket's sleep queue before
    // anything drains the backlog — otherwise this test would pass on a
    // connect that never waited at all.
    let deadline = crate::sock_clock::monotonic_ns_safe() + 5_000_000_000;
    while !sock.connect_waiters.has_waiters() {
        assert!(crate::sock_clock::monotonic_ns_safe() < deadline,
            "blocking connect never parked on the socket sleep queue");
        sync::relax();
    }

    super::accept(&l).expect("drain one queued connection");
    // Bounded, so a wake that never lands fails here instead of hanging the run.
    let wake_deadline = crate::sock_clock::monotonic_ns_safe() + 5_000_000_000;
    while !finished.load(core::sync::atomic::Ordering::Acquire) {
        assert!(crate::sock_clock::monotonic_ns_safe() < wake_deadline,
            "freeing a backlog slot never roused the parked connect");
        sync::relax();
    }
    joiner.join().expect("connect thread").expect("connect must complete once a slot frees");
    assert!(matches!(*sock.kind.lock(), SockKind::Unix(_, _)));
}

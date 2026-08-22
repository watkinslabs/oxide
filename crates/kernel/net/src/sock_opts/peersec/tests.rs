// The whole `SO_PEERSEC` chain, driven through the real connect path: a
// labelling module installs, a connection forms, and both ends read the other's
// label back. Nothing here calls the syscall shim — the shim only moves bytes.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::recorded_peer_label;
use crate::sock::{InetSocket, SockKind};
use crate::unix_sock::{UnixAddr, UnixEnd, UnixRegistry};
use crate::UnixPair;

const SERVER: u32 = 0x51;
const CLIENT: u32 = 0x11;
const CREATED: u32 = 0x77;
const UNLABELED: u32 = 3;

/// The label the next socket created will take. Settable so one test can give
/// the listener and the client DIFFERENT labels — with one constant for both,
/// a test cannot tell an end reading its peer's label from an end reading its
/// own.
static NEXT_LABEL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(CREATED);
static CLASS_LABEL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn create(class: security::network::SocketClass) -> u32 {
    if CLASS_LABEL.load(core::sync::atomic::Ordering::Acquire) { return class as u32 + 1; }
    NEXT_LABEL.load(core::sync::atomic::Ordering::Acquire)
}

fn creating_with<T>(label: u32, f: impl FnOnce() -> T) -> T {
    NEXT_LABEL.store(label, core::sync::atomic::Ordering::Release);
    let made = f();
    NEXT_LABEL.store(CREATED, core::sync::atomic::Ordering::Release);
    made
}
fn server_end(listener: u32, client: u32) -> u32 { (listener << 8) | (client & 0xff) }

fn context(label: u32) -> Result<Vec<u8>, syscall::errno::Errno> {
    if label == security::network::NO_LABEL { return Err(syscall::errno::Errno::Einval); }
    let mut out = Vec::from(&b"label:"[..]);
    out.push(b'0' + (label % 10) as u8);
    Ok(out)
}

fn ops() -> security::network::SocketLabelOps {
    security::network::SocketLabelOps { create, unlabeled: UNLABELED, context, server_end }
}

/// The labelling module is ONE process-wide slot and socket creation reads it,
/// so these tests must not overlap each other or any other test that creates a
/// socket expecting no labelling.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Installed(std::sync::MutexGuard<'static, ()>);

impl Installed {
    fn new() -> Self {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = security::network::remove_socket_label();
        assert!(security::network::install_socket_label(ops()));
        Self(guard)
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        CLASS_LABEL.store(false, core::sync::atomic::Ordering::Release);
        let _ = security::network::remove_socket_label();
    }
}

#[test]
fn every_production_constructor_supplies_its_exact_socket_class() {
    use security::network::SocketClass;
    let _installed = Installed::new();
    let _domain = crate::hosted_fixture::init_net_domain();
    CLASS_LABEL.store(true, core::sync::atomic::Ordering::Release);
    let label = |class: SocketClass| class as u32 + 1;

    assert_eq!(InetSocket::new_tcp().security_label(), label(SocketClass::Tcp));
    assert_eq!(InetSocket::new_udp().security_label(), label(SocketClass::Udp));
    assert_eq!(InetSocket::new_raw4(crate::addr::IpProto::Udp as u8).security_label(),
        label(SocketClass::RawIp));
    assert_eq!(InetSocket::new_ping4_in(network_namespace::initial()).security_label(),
        label(SocketClass::Icmp));
    assert_eq!(InetSocket::new_packet(crate::eth_p::ALL, crate::socket_args::SOCK_RAW as u8)
        .security_label(), label(SocketClass::Packet));
    assert_eq!(InetSocket::new_unix().security_label(), label(SocketClass::UnixStream));
    assert_eq!(InetSocket::new_unix_dgram().security_label(), label(SocketClass::UnixDgram));
}

/// The whole chain, through the SAME work functions the syscall shims call:
/// bind, listen, connect, accept on real sockets, then each side reads the
/// other's label back.
///
/// This is the wiring proof, and it has to drive the real `connect` — every
/// piece of this mechanism existed and was unit-tested before, and `SO_PEERSEC`
/// still answered `ENOPROTOOPT` on every running kernel, because no connect ever
/// recorded anything. A test that stamps the labels onto a pair itself and then
/// checks they are there would have passed against that kernel too.
#[test]
fn a_real_connect_records_both_ends_and_each_reads_the_others_label() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let name = b"\0b2262-peersec-connect";

    let server = creating_with(SERVER, || {
        let sock = Arc::new(InetSocket::new_unix_in(network_namespace::initial()));
        crate::sock::bind(&sock, crate::sock::BoundAddr::UnixListener(
            crate::UnixAddr::from_sockaddr_path(name.to_vec()))).expect("bind");
        sock
    });
    assert_eq!(server.security_label(), SERVER);
    crate::sock::listen(&server, 4).expect("listen");

    let client = creating_with(CLIENT, ||
        Arc::new(InetSocket::new_unix_in(network_namespace::initial())));
    assert_eq!(client.security_label(), CLIENT);
    // Before it connects, the client has recorded no peer and reports the
    // module's "unlabelled".
    assert_eq!(recorded_peer_label(&client), Some(UNLABELED));

    crate::sock::connect(&client, crate::sock::RemoteAddr::Unix(
        crate::UnixAddr::from_sockaddr_path(name.to_vec())), true).expect("connect");
    let accepted = crate::sock::accept(&server).expect("accept").new_sock;

    // The accepted server socket reads the CONNECTING socket's own label.
    assert_eq!(recorded_peer_label(&accepted), Some(CLIENT));
    // The client reads the server end's label, derived from BOTH ends — not the
    // listener's alone, and not the client's own.
    assert_eq!(recorded_peer_label(&client), Some(server_end(SERVER, CLIENT)));
    assert_ne!(recorded_peer_label(&client), Some(SERVER));
    assert_ne!(recorded_peer_label(&client), Some(CLIENT));
    // The two ends report DIFFERENT things, which is the whole point.
    assert_ne!(recorded_peer_label(&client), recorded_peer_label(&accepted));

    // And each renders to a context, which is what the option copies out.
    for sock in [&client, &accepted] {
        let label = recorded_peer_label(sock).expect("a reporting class");
        let bytes = security::network::socket_label_context(label)
            .expect("the render succeeds").expect("a context");
        assert_eq!(bytes.last(), Some(&0), "the copied value is a C string");
    }
}

/// The pair-level record, driven through the listener's other commit path — the
/// one a connect that queues without a socket takes.
#[test]
fn a_queued_connection_records_the_server_ends_label() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let registry = UnixRegistry::new();
    let addr = UnixAddr::from_abstract_or_test_path(String::from("\0b2262-peersec-queued"));
    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen_with_cred(0, crate::sysctl::DEFAULT_SOMAXCONN, None, None, Some(SERVER));

    let client = UnixPair::new();
    client.set_end_sid(UnixEnd::B, CLIENT);
    assert_eq!(client.peer_sid(UnixEnd::B), security::network::NO_LABEL);

    registry.connect_pair_addr(&addr, client.clone()).unwrap();
    let (accepted, _pin) = listener.accept().unwrap();
    assert!(Arc::ptr_eq(&accepted, &client));

    assert_eq!(accepted.peer_sid(UnixEnd::A), CLIENT);
    assert_eq!(accepted.peer_sid(UnixEnd::B), server_end(SERVER, CLIENT));
    assert_ne!(accepted.peer_sid(UnixEnd::B), SERVER);
}

/// The read side: a socket bound to a connected pair end reports the OPPOSITE
/// end's label, so the two ends of one connection report different things.
#[test]
fn each_end_of_a_pair_reports_the_other_ends_label() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let pair = UnixPair::new();
    pair.set_end_sid(UnixEnd::A, SERVER);
    pair.set_end_sid(UnixEnd::B, CLIENT);
    let ns = crate::net_ns::current_namespace();
    let a = InetSocket::new_unix_pair_end_in(ns.clone(), pair.clone(), UnixEnd::A);
    let b = InetSocket::new_unix_pair_end_in(ns, pair, UnixEnd::B);
    assert_eq!(recorded_peer_label(&a), Some(CLIENT));
    assert_eq!(recorded_peer_label(&b), Some(SERVER));
    assert_ne!(recorded_peer_label(&a), recorded_peer_label(&b));
}

/// A socket that recorded nothing reports "unlabelled" — a real label. A stream
/// socket answering nothing at all would be indistinguishable from one on a
/// kernel where nothing labels sockets.
#[test]
fn a_socket_that_recorded_nothing_reports_unlabeled_not_nothing() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let listening = InetSocket::new_tcp_in(crate::net_ns::current_namespace());
    assert_eq!(recorded_peer_label(&listening), Some(UNLABELED));
    assert_ne!(recorded_peer_label(&listening), None);
    assert_ne!(recorded_peer_label(&listening), Some(security::network::NO_LABEL));
}

/// The socket's CLASS decides whether a peer label is reportable, not whether
/// one was recorded. A datagram pair records both labels and still reports none.
#[test]
fn a_datagram_socket_reports_no_peer_label_even_having_recorded_one() {
    use core::sync::atomic::Ordering;
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let msg = crate::UnixMsgPair::new_datagram();
    msg.set_end_sid(UnixEnd::A, SERVER);
    msg.set_end_sid(UnixEnd::B, CLIENT);
    assert_eq!(msg.peer_sid(UnixEnd::A), CLIENT, "the label IS recorded");

    let sock = InetSocket::new_unix_dgram_in(crate::net_ns::current_namespace());
    *sock.kind.lock() = SockKind::UnixMsgPair(msg.clone(), UnixEnd::A);
    // Socket creation records the type it was asked for, and a datagram pair is
    // not a reporting class.
    sock.opts.so_type.store(crate::socket_args::SOCK_DGRAM as u8, Ordering::Release);
    assert_eq!(recorded_peer_label(&sock), None);

    // The SAME recorded pair on a SEQPACKET socket IS a reporting class, which
    // proves the refusal above came from the class and not from the recording.
    let seq = InetSocket::new_unix_dgram_in(crate::net_ns::current_namespace());
    *seq.kind.lock() = SockKind::UnixMsgPair(msg, UnixEnd::A);
    seq.opts.so_type.store(crate::socket_args::SOCK_SEQPACKET as u8, Ordering::Release);
    assert_eq!(recorded_peer_label(&seq), Some(CLIENT));
}

/// A socket created while a module is installed carries that module's label, and
/// that label is what a peer records for it. This is the create hook's only
/// observable effect.
#[test]
fn a_socket_created_under_a_module_carries_its_label() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let sock = InetSocket::new_tcp_in(crate::net_ns::current_namespace());
    assert_eq!(sock.security_label(), CREATED);
}

/// With no module installed nothing is labelled and every socket reports no peer
/// label, whatever its class — the state every kernel without the module is in.
#[test]
fn with_no_module_installed_no_socket_reports_a_peer_label() {
    let _serial_slot = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = security::network::remove_socket_label();
    let _serial = crate::unix_sock::test_support::guard();
    let sock = InetSocket::new_tcp_in(crate::net_ns::current_namespace());
    assert_eq!(sock.security_label(), security::network::NO_LABEL);
    // The class still reports, but the label it reports is the absent one, which
    // the shim above turns into `ENOPROTOOPT`.
    assert_eq!(recorded_peer_label(&sock), Some(security::network::NO_LABEL));
    assert_eq!(security::network::socket_label_context(security::network::NO_LABEL), Ok(None));
}

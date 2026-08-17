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

fn create() -> u32 { CREATED }
fn server_end(listener: u32, client: u32) -> u32 { (listener << 8) | (client & 0xff) }

fn context(label: u32) -> Option<Vec<u8>> {
    if label == security::network::NO_LABEL { return None; }
    let mut out = Vec::from(&b"label:"[..]);
    out.push(b'0' + (label % 10) as u8);
    Some(out)
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
    fn drop(&mut self) { let _ = security::network::remove_socket_label(); }
}

/// The record side, through the real listen/connect/accept path: both ends of an
/// established connection carry the other's label afterwards.
///
/// This is the wiring proof. Every piece of this mechanism existed and was
/// tested before, and `SO_PEERSEC` still answered `ENOPROTOOPT` on every running
/// kernel, because no connect ever recorded anything.
#[test]
fn an_established_connection_records_both_ends_labels() {
    let _installed = Installed::new();
    let _serial = crate::unix_sock::test_support::guard();
    let registry = UnixRegistry::new();
    let addr = UnixAddr::from_abstract_or_test_path(String::from("\0peersec-record"));
    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen_with_cred(0, crate::sysctl::DEFAULT_SOMAXCONN, None, None, Some(SERVER));

    let client = UnixPair::new();
    client.set_end_sid(UnixEnd::B, CLIENT);
    // Before the connection forms, neither end has recorded the other.
    assert_eq!(client.peer_sid(UnixEnd::B), security::network::NO_LABEL);

    registry.connect_pair_addr(&addr, client.clone()).unwrap();
    let (accepted, _pin) = listener.accept().unwrap();
    assert!(Arc::ptr_eq(&accepted, &client));

    // The server end reads the connecting socket's own label.
    assert_eq!(accepted.peer_sid(UnixEnd::A), CLIENT);
    // The client reads the server end's, which is derived from BOTH ends — not
    // the listener's label alone.
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
    assert_eq!(security::network::socket_label_context(security::network::NO_LABEL), None);
}

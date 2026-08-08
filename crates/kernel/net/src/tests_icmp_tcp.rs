// What an ICMP error does to a TCP connection, end to end through the stack.
//
// A connection that is up survives it: the report is kept, the connection is
// not torn down, and the option read is where it surfaces. A connection still
// handshaking dies of it.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::{Ipv4Addr, IpProto, NetStack};
use crate::stack::TcpEntry;
use crate::tcp_state::TcpState;

const LISTENER_PORT: u16 = 1_235;
const CLIENT_PORT: u16 = 50_001;
const DRAINS: usize = 8;

struct Fixture {
    stack: NetStack,
    iface: crate::NetIfaceId,
    client: Arc<TcpEntry>,
}

impl Fixture {
    /// One established loopback connection plus the interface its errors
    /// arrive on. # C: O(DRAINS)
    fn established() -> Self {
        let stack = NetStack::new();
        let (iface, loopback) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, LISTENER_PORT, true).unwrap();
        let client = stack.tcp_connect(Ipv4Addr::LOOPBACK, CLIENT_PORT,
            Ipv4Addr::LOOPBACK, LISTENER_PORT).unwrap();
        for _ in 0..DRAINS { stack.drain_loopback(iface, &loopback); }
        let _server = stack.tcp_accept(&listener).expect("accepted child");
        assert_eq!(client.conn.lock().state, TcpState::Established);
        Self { stack, iface, client }
    }

    /// One handshaking connection: no listener answers, so it stays in the
    /// state that cannot survive an error. # C: O(1)
    fn handshaking() -> Self {
        let stack = NetStack::new();
        let (iface, _loopback) = stack.register_loopback();
        // Nothing is drained, so the handshake never completes.
        let client = stack.tcp_connect(Ipv4Addr::LOOPBACK, CLIENT_PORT,
            Ipv4Addr::LOOPBACK, LISTENER_PORT).unwrap();
        assert_eq!(client.conn.lock().state, TcpState::SynSent);
        Self { stack, iface, client }
    }
}

/// The quoted datagram an ICMP error carries: the header this side sent, so
/// the error resolves to this connection. # C: O(1)
fn quote(remote: Ipv4Addr) -> alloc::vec::Vec<u8> {
    let tcp_len = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    let mut out = alloc::vec![0u8; 8 + crate::ipv4::IPV4_HDR_LEN + tcp_len];
    let hdr = crate::Ipv4Hdr::build(Ipv4Addr::LOOPBACK, remote, IpProto::Tcp, tcp_len as u16, 1);
    hdr.write_to(&mut out[8..8 + crate::ipv4::IPV4_HDR_LEN]);
    let tcp = 8 + crate::ipv4::IPV4_HDR_LEN;
    out[tcp..tcp + 2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    out[tcp + 2..tcp + 4].copy_from_slice(&LISTENER_PORT.to_be_bytes());
    out
}

/// Host-unreachable, the classic non-fatal report. # C: O(1)
fn report(fixture: &Fixture, remote: Ipv4Addr) {
    crate::stack_icmp::handle_error(&fixture.stack, fixture.iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 1, &quote(remote));
}

#[test]
fn an_established_connection_survives_the_error_and_reports_it_only_to_the_option_read() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let fixture = Fixture::established();
    report(&fixture, Ipv4Addr::LOOPBACK);
    assert_eq!(fixture.client.conn.lock().state, TcpState::Established,
        "an ICMP report must not tear down a connection that is up");
    // The receive path's own check never sees it.
    assert_eq!(fixture.client.error_snapshot(), 0);
    // The option read does, once.
    assert_eq!(fixture.client.take_reported_error(), Errno::Ehostunreach as i32);
    assert_eq!(fixture.client.take_reported_error(), 0);
}

#[test]
fn extended_error_delivery_promotes_the_same_report_without_closing_the_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let fixture = Fixture::established();
    fixture.client.set_extended_errors4(true);
    report(&fixture, Ipv4Addr::LOOPBACK);
    assert_eq!(fixture.client.conn.lock().state, TcpState::Established);
    assert_eq!(fixture.client.error_snapshot(), Errno::Ehostunreach as i32);
}

#[test]
fn a_handshaking_connection_dies_of_the_error() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let fixture = Fixture::handshaking();
    report(&fixture, Ipv4Addr::LOOPBACK);
    assert_eq!(fixture.client.conn.lock().state, TcpState::Closed);
    assert_eq!(fixture.client.take_reported_error(), Errno::Ehostunreach as i32);
}

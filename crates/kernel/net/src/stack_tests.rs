use crate::stack::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::{icmp, IpProto, Ipv4Addr, Ipv4Hdr, MacAddr, NetDev, NetError, NetResult, Pkt, IPV4_HDR_LEN};

struct CountDev {
    tx: AtomicUsize,
}

impl CountDev {
    fn new() -> Self { Self { tx: AtomicUsize::new(0) } }
}

impl NetDev for CountDev {
    fn name(&self) -> &str { "eth0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> {
        self.tx.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn loopback_udp_round_trip() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    stack.bind_udp(Ipv4Addr::LOOPBACK, 4242).unwrap();
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 5000,
        Ipv4Addr::LOOPBACK, 4242,
        b"hello-net",
    ).unwrap();
    stack.drain_loopback(id, &lo);
    let (src, src_port, payload) = stack.recv_udp(4242).unwrap();
    assert_eq!(src, Ipv4Addr::LOOPBACK);
    assert_eq!(src_port, 5000);
    assert_eq!(payload, b"hello-net");
}

#[test]
fn icmp_echo_round_trip_via_loopback() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let payload = b"oxide-icmp";
    let mut req = alloc::vec![0u8; icmp::ICMP_HDR_LEN + payload.len()];
    let mut hdr = icmp::IcmpEcho {
        typ: icmp::ICMP_TYPE_ECHO_REQUEST, code: 0,
        checksum: 0, id: 0xBEEF, seq: 1,
    };
    hdr.build_into(payload, &mut req);
    let total = IPV4_HDR_LEN + req.len();
    let mut frame = alloc::vec![0u8; total];
    let ip = Ipv4Hdr::build(
        Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Icmp, req.len() as u16, 1,
    );
    ip.write_to(&mut frame[..IPV4_HDR_LEN]);
    frame[IPV4_HDR_LEN..].copy_from_slice(&req);
    stack.deliver_rx(id, &frame).unwrap();
    let reply = lo.rx_pop().unwrap();
    let parsed_ip = Ipv4Hdr::parse(reply.data()).unwrap();
    assert_eq!(parsed_ip.proto, IpProto::Icmp as u8);
    let icmp_payload = &reply.data()[IPV4_HDR_LEN .. parsed_ip.total_len as usize];
    let echo = icmp::IcmpEcho::parse(icmp_payload).unwrap();
    assert_eq!(echo.typ, icmp::ICMP_TYPE_ECHO_REPLY);
    assert_eq!(echo.id, 0xBEEF);
}

#[test]
fn unbound_port_drops_silently() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 9999, b"x",
    ).unwrap();
    stack.drain_loopback(id, &lo);
    assert!(stack.recv_udp(9999).is_none());
}

#[test]
fn double_bind_fails() {
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    stack.bind_udp(Ipv4Addr::LOOPBACK, 100).unwrap();
    assert_eq!(stack.bind_udp(Ipv4Addr::LOOPBACK, 100).err().unwrap(),
               NetError::Eaddrinuse);
}

#[test]
fn tcp_handshake_via_loopback() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234, true).unwrap();
    let client = stack.tcp_connect(
        Ipv4Addr::LOOPBACK, 50000,
        Ipv4Addr::LOOPBACK, 1234,
    ).unwrap();
    for _ in 0..3 { stack.drain_loopback(id, &lo); }
    let server = stack.tcp_accept(&listener).expect("accepted");
    assert_eq!(client.conn.lock().state, crate::tcp_state::TcpState::Established);
    assert_eq!(server.conn.lock().state, crate::tcp_state::TcpState::Established);
}

#[test]
fn tcp_data_round_trip_via_loopback() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234, true).unwrap();
    let client = stack.tcp_connect(
        Ipv4Addr::LOOPBACK, 50000,
        Ipv4Addr::LOOPBACK, 1234,
    ).unwrap();
    for _ in 0..3 { stack.drain_loopback(id, &lo); }
    let server = stack.tcp_accept(&listener).unwrap();
    stack.tcp_send(&client, b"oxide-tcp-payload", 65536, true).unwrap();
    for _ in 0..3 { stack.drain_loopback(id, &lo); }
    let got = stack.tcp_recv(&server, 1024);
    assert_eq!(&got[..], b"oxide-tcp-payload");
}

#[test]
fn route_miss_is_enetunreach() {
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    assert_eq!(
        stack.send_udp_to(Ipv4Addr::LOOPBACK, 1, Ipv4Addr::new(8, 8, 8, 8), 1, b"x")
             .err().unwrap(),
        NetError::Enetunreach,
    );
}

#[test]
fn bound_udp_send_uses_requested_iface() {
    let stack = NetStack::new();
    let (_lo_id, lo) = stack.register_loopback();
    let eth = Arc::new(CountDev::new());
    let eth_id = stack.ifaces.register(eth.clone());
    stack.send_udp_to_bound(
        Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 2, b"x", Some(eth_id),
    ).unwrap();
    assert_eq!(lo.rx_len(), 0);
    assert_eq!(eth.tx.load(Ordering::Relaxed), 1);
}

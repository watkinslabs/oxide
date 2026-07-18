use crate::stack::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
use crate::{icmp, IpAddr, IpProto, Ipv4Addr, Ipv4Hdr, Ipv6Addr, MacAddr, NetDev, NetError, NetResult, Pkt, Route6Entry, RouteEntry, IPV4_HDR_LEN};

// Module manifest: forwarding owns IPv4 transit and namespace teardown tests.
mod forwarding;

struct CountDev {
    tx: AtomicUsize,
    mtu: u32,
    id0: AtomicUsize,
    id1: AtomicUsize,
    id2: AtomicUsize,
    flags0: AtomicUsize,
    flags1: AtomicUsize,
    flags2: AtomicUsize,
    len0: AtomicUsize,
    len1: AtomicUsize,
    len2: AtomicUsize,
    tos0: AtomicUsize,
    ttl0: AtomicUsize,
    icmp_type0: AtomicUsize,
    icmp_code0: AtomicUsize,
}

impl CountDev {
    fn new() -> Self { Self::with_mtu(1500) }
    fn with_mtu(mtu: u32) -> Self {
        Self {
            tx: AtomicUsize::new(0),
            mtu,
            id0: AtomicUsize::new(0),
            id1: AtomicUsize::new(0),
            id2: AtomicUsize::new(0),
            flags0: AtomicUsize::new(0),
            flags1: AtomicUsize::new(0),
            flags2: AtomicUsize::new(0),
            len0: AtomicUsize::new(0),
            len1: AtomicUsize::new(0),
            len2: AtomicUsize::new(0),
            tos0: AtomicUsize::new(0),
            ttl0: AtomicUsize::new(0),
            icmp_type0: AtomicUsize::new(usize::MAX),
            icmp_code0: AtomicUsize::new(usize::MAX),
        }
    }

    fn store_hdr(&self, idx: usize, hdr: Ipv4Hdr) {
        let (id, flags, len) = match idx {
            0 => (&self.id0, &self.flags0, &self.len0),
            1 => (&self.id1, &self.flags1, &self.len1),
            2 => (&self.id2, &self.flags2, &self.len2),
            _ => return,
        };
        id.store(hdr.id as usize, Ordering::Relaxed);
        flags.store(hdr.flags_frag as usize, Ordering::Relaxed);
        len.store(hdr.total_len as usize, Ordering::Relaxed);
        if idx == 0 {
            self.tos0.store(hdr.tos as usize, Ordering::Relaxed);
            self.ttl0.store(hdr.ttl as usize, Ordering::Relaxed);
        }
    }
}

impl NetDev for CountDev {
    fn name(&self) -> &str { "eth0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, pkt: Pkt) -> NetResult<()> {
        let idx = self.tx.fetch_add(1, Ordering::Relaxed);
        if pkt.data().first().map(|b| b >> 4) == Some(4) {
            let hdr = Ipv4Hdr::parse(pkt.data()).unwrap();
            self.store_hdr(idx, hdr);
            let off = hdr.ihl_bytes();
            if idx == 0 && hdr.proto == IpProto::Icmp as u8 && pkt.data().len() >= off + 2 {
                self.icmp_type0.store(pkt.data()[off] as usize, Ordering::Relaxed);
                self.icmp_code0.store(pkt.data()[off + 1] as usize, Ordering::Relaxed);
            }
        } else if pkt.data().first().map(|b| b >> 4) == Some(6) {
            let hdr = Ipv6Hdr::parse(pkt.data()).unwrap();
            let (id, flags, len) = match idx {
                0 => (&self.id0, &self.flags0, &self.len0),
                1 => (&self.id1, &self.flags1, &self.len1),
                2 => (&self.id2, &self.flags2, &self.len2),
                _ => return Ok(()),
            };
            len.store(IPV6_HDR_LEN + hdr.payload_length as usize, Ordering::Relaxed);
            if hdr.next_header == IpProto::Fragment as u8 && pkt.data().len() >= IPV6_HDR_LEN + 8 {
                let frag = &pkt.data()[IPV6_HDR_LEN..IPV6_HDR_LEN + 8];
                flags.store(u16::from_be_bytes([frag[2], frag[3]]) as usize, Ordering::Relaxed);
                id.store(u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]) as usize, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

struct EstablishedLoopbackTcp {
    stack: NetStack,
    iface: crate::NetIfaceId,
    loopback: Arc<crate::LoopbackDev>,
    client: Arc<TcpEntry>,
    server: Arc<TcpEntry>,
}

impl EstablishedLoopbackTcp {
    fn new() -> Self {
        let stack = NetStack::new();
        let (iface, loopback) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234, true).unwrap();
        let client = stack.tcp_connect(Ipv4Addr::LOOPBACK, 50000,
            Ipv4Addr::LOOPBACK, 1234).unwrap();
        for _ in 0..3 { stack.drain_loopback(iface, &loopback); }
        let server = stack.tcp_accept(&listener).expect("accepted TCP child");
        Self { stack, iface, loopback, client, server }
    }

    fn drain(&self) {
        for _ in 0..3 { self.stack.drain_loopback(self.iface, &self.loopback); }
    }
}

#[test]
fn loopback_udp_round_trip() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, 4242).unwrap();
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 5000,
        Ipv4Addr::LOOPBACK, 4242,
        b"hello-net",
    ).unwrap();
    stack.drain_loopback(id, &lo);
    let (src, src_port, _, _, _, payload) = endpoint.recv(false).unwrap();
    assert_eq!(src, Ipv4Addr::LOOPBACK);
    assert_eq!(src_port, 5000);
    assert_eq!(payload, b"hello-net");
}

#[test]
fn udp_recv_peek_leaves_datagram_queued() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, 4243).unwrap();
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 5001,
        Ipv4Addr::LOOPBACK, 4243,
        b"peek-me",
    ).unwrap();
    stack.drain_loopback(id, &lo);
    let (_, _, _, _, _, peeked) = endpoint.recv(true).unwrap();
    assert_eq!(peeked, b"peek-me");
    let (_, _, _, _, _, popped) = endpoint.recv(false).unwrap();
    assert_eq!(popped, b"peek-me");
    assert!(endpoint.recv(false).is_none());
}

#[test]
fn icmp_echo_round_trip_via_loopback() {
    let _domain = crate::hosted_fixture::init_net_domain();
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
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 9999, b"x",
    ).unwrap();
    stack.drain_loopback(id, &lo);
    assert!(stack.udp_demux(Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 9999, id).is_empty());
}

#[test]
fn double_bind_fails() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    stack.bind_udp(Ipv4Addr::LOOPBACK, 100).unwrap();
    assert_eq!(stack.bind_udp(Ipv4Addr::LOOPBACK, 100).err().unwrap(),
               NetError::Eaddrinuse);
}

#[test]
fn tcp_handshake_via_loopback() {
    let _domain = crate::hosted_fixture::init_net_domain();
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
    let _domain = crate::hosted_fixture::init_net_domain();
    let pair = EstablishedLoopbackTcp::new();
    pair.stack.tcp_send(&pair.client, b"oxide-tcp-payload", 65536, true, false).unwrap();
    pair.drain();
    let got = pair.stack.tcp_recv(&pair.server, 1024);
    assert_eq!(&got[..], b"oxide-tcp-payload");
}

#[test]
fn established_tcp_packet_fixture_drives_bidirectional_input_and_output() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let pair = EstablishedLoopbackTcp::new();

    pair.stack.tcp_send(&pair.client, b"client-to-server", 65536, true, false).unwrap();
    pair.drain();
    assert_eq!(pair.stack.tcp_recv(&pair.server, 1024), b"client-to-server");

    pair.stack.tcp_send(&pair.server, b"server-to-client", 65536, true, false).unwrap();
    pair.drain();
    assert_eq!(pair.stack.tcp_recv(&pair.client, 1024), b"server-to-client");
    assert!(pair.loopback.rx_len() == 0, "fixture must drain every emitted packet");
}

#[test]
fn route_miss_is_enetunreach() {
    let _domain = crate::hosted_fixture::init_net_domain();
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
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (_lo_id, lo) = stack.register_loopback();
    let eth = Arc::new(CountDev::new());
    let eth_id = stack.ifaces.register(eth.clone());
    stack.routes.add(RouteEntry::main(Ipv4Addr::LOOPBACK, 32, eth_id, None,
        Some(Ipv4Addr::LOOPBACK)));
    stack.send_udp_to_bound(
        Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 2, b"x", Some(eth_id),
    ).unwrap();
    assert_eq!(lo.rx_len(), 0);
    assert_eq!(eth.tx.load(Ordering::Relaxed), 1);
}

#[test]
fn udp_send_can_stamp_ipv4_tos_and_ttl() {
    let stack = NetStack::new();
    let eth = Arc::new(CountDev::new());
    let eth_id = stack.ifaces.register(eth.clone());
    stack.routes.add(RouteEntry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv4Addr::new(10, 0, 0, 0),
        prefix_len: 24,
        iface: eth_id,
        gateway: None,
        src_hint: Some(Ipv4Addr::new(10, 0, 0, 1)),
    });

    stack.send_udp_to_bound_opts(
        Ipv4Addr::new(10, 0, 0, 1),
        1234,
        Ipv4Addr::new(10, 0, 0, 2),
        4321,
        b"payload",
        None,
        0xb8,
        37,
    ).unwrap();

    assert_eq!(eth.tx.load(Ordering::Relaxed), 1);
    assert_eq!(eth.tos0.load(Ordering::Relaxed), 0xb8);
    assert_eq!(eth.ttl0.load(Ordering::Relaxed), 37);
}

#[test]
fn ipv4_l4_send_fragments_to_iface_mtu() {
    let stack = NetStack::new();
    let eth = Arc::new(CountDev::with_mtu(68));
    let eth_id = stack.ifaces.register(eth.clone());
    stack.routes.add(RouteEntry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv4Addr::new(10, 0, 0, 0),
        prefix_len: 24,
        iface: eth_id,
        gateway: None,
        src_hint: Some(Ipv4Addr::new(10, 0, 0, 1)),
    });

    let l4 = [0x5au8; 100];
    stack.send_l4_over_ipv4_pub(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        &l4,
    ).unwrap();

    assert_eq!(eth.tx.load(Ordering::Relaxed), 3);
    assert_eq!(eth.len0.load(Ordering::Relaxed), 68);
    assert_eq!(eth.len1.load(Ordering::Relaxed), 68);
    assert_eq!(eth.len2.load(Ordering::Relaxed), 24);
    assert_eq!(eth.flags0.load(Ordering::Relaxed), 0x2000);
    assert_eq!(eth.flags1.load(Ordering::Relaxed), 0x2006);
    assert_eq!(eth.flags2.load(Ordering::Relaxed), 0x000c);
    assert_eq!(eth.id0.load(Ordering::Relaxed), eth.id1.load(Ordering::Relaxed));
    assert_eq!(eth.id1.load(Ordering::Relaxed), eth.id2.load(Ordering::Relaxed));
}

#[test]
fn ipv6_l4_send_uses_route_table_iface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let eth = Arc::new(CountDev::with_mtu(1400));
    let eth_id = stack.ifaces.register(eth.clone());
    let src = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 2]);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0]),
        prefix_len: 48,
        iface: eth_id,
        gateway: None,
        src_hint: Some(src),
        origin: crate::route6::Route6Origin::Static,
    });

    stack.send_l4_over_ipv6(src, dst, IpProto::Udp, b"hello6").unwrap();

    assert_eq!(eth.tx.load(Ordering::Relaxed), 1);
    assert_eq!(stack.mss_for_dst(IpAddr::V6(dst)), 1340);
}

#[test]
fn ipv6_l4_send_fragments_to_iface_mtu() {
    let stack = NetStack::new();
    let eth = Arc::new(CountDev::with_mtu(1280));
    let eth_id = stack.ifaces.register(eth.clone());
    let src = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 1]);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 2]);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 0]),
        prefix_len: 48,
        iface: eth_id,
        gateway: None,
        src_hint: Some(src),
        origin: crate::route6::Route6Origin::Static,
    });

    let l4 = [0x6au8; 2000];
    stack.send_l4_over_ipv6(src, dst, IpProto::Udp, &l4).unwrap();

    assert_eq!(eth.tx.load(Ordering::Relaxed), 2);
    assert_eq!(eth.len0.load(Ordering::Relaxed), 1280);
    assert_eq!(eth.len1.load(Ordering::Relaxed), 816);
    assert_eq!(eth.flags0.load(Ordering::Relaxed), 0x0001);
    assert_eq!(eth.flags1.load(Ordering::Relaxed), 154 << 3);
    assert_eq!(eth.id0.load(Ordering::Relaxed), eth.id1.load(Ordering::Relaxed));
}

#[test]
fn ipv6_udp_send_fragments_to_iface_mtu() {
    let stack = NetStack::new();
    let eth = Arc::new(CountDev::with_mtu(1280));
    let eth_id = stack.ifaces.register(eth.clone());
    let src = Ipv6Addr::from_segments([0x2001, 0xdb8, 3, 0, 0, 0, 0, 1]);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 3, 0, 0, 0, 0, 2]);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::from_segments([0x2001, 0xdb8, 3, 0, 0, 0, 0, 0]),
        prefix_len: 48,
        iface: eth_id,
        gateway: None,
        src_hint: Some(src),
        origin: crate::route6::Route6Origin::Static,
    });

    let payload = [0x7bu8; 2000];
    stack.send_udp6_to_bound(src, 10000, dst, 10001, &payload, None).unwrap();

    assert_eq!(eth.tx.load(Ordering::Relaxed), 2);
    assert_eq!(eth.len0.load(Ordering::Relaxed), 1280);
    assert_eq!(eth.len1.load(Ordering::Relaxed), 824);
    assert_eq!(eth.flags0.load(Ordering::Relaxed), 0x0001);
    assert_eq!(eth.flags1.load(Ordering::Relaxed), 154 << 3);
    assert_eq!(eth.id0.load(Ordering::Relaxed), eth.id1.load(Ordering::Relaxed));
}

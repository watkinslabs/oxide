// B1376: IPV6_TCLASS (sticky outbound traffic class) + IPV6_RECVTCLASS
// (received traffic class ancillary) — non-hollow proof that the option
// value reaches the on-wire IPv6 header (TX) and is captured off the wire
// into the recvmsg-facing `Received.tclass` (RX). Twin of the hop-limit pair.

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::{IpProto, Ipv6Addr, NetIfaceId, NetStack};

const LOCAL_PORT: u16 = 44_100;
const REMOTE_PORT: u16 = 53;
const TCLASS: u8 = 0x28;

/// Egress device that records every emitted frame verbatim so the test can
/// inspect the on-wire IPv6 header the stack actually produced.
struct CaptureDev { frames: Mutex<Vec<Vec<u8>>> }

impl crate::NetDev for CaptureDev {
    fn name(&self) -> &str { "capture6" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1_500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: crate::Pkt) -> crate::NetResult<()> {
        self.frames.lock().unwrap().push(packet.data().to_vec());
        Ok(())
    }
}

fn emitted_tclass(dev: &CaptureDev) -> u8 {
    let frames = dev.frames.lock().unwrap();
    let frame = frames.last().expect("a frame was emitted");
    crate::ipv6::Ipv6Hdr::parse(frame).expect("valid IPv6 header").traffic_class
}

// TX: the sticky IPV6_TCLASS value threaded through the UDP/IPv6 send path
// lands in the on-wire header's traffic-class field (bits 4..12 of word 0).
#[test]
fn sticky_tclass_reaches_ipv6_udp_wire() {
    let stack = NetStack::new();
    let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 0x76, 0, 0, 0, 0, 1]);
    let dev = Arc::new(CaptureDev { frames: Mutex::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone());

    // Requested traffic class reaches the wire.
    stack.send_udp6_pmtu_to_bound_opts(
        Ipv6Addr::LOOPBACK, LOCAL_PORT, remote, REMOTE_PORT, b"tc", Some(iface),
        crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, TCLASS, crate::uapi::IPV6_PMTUDISC_WANT,
    ).unwrap();
    assert_eq!(emitted_tclass(&dev), TCLASS, "sticky IPV6_TCLASS must reach the wire");

    // Unset (default 0) yields a zero traffic-class byte, not stale bits.
    stack.send_udp6_pmtu_to_bound_opts(
        Ipv6Addr::LOOPBACK, LOCAL_PORT, remote, REMOTE_PORT, b"tc", Some(iface),
        crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0, crate::uapi::IPV6_PMTUDISC_WANT,
    ).unwrap();
    assert_eq!(emitted_tclass(&dev), 0, "default traffic class is 0 on the wire");
}

// RX ingest: the real IPv6 receive path parses the header traffic class and
// carries it into the queued datagram tuple (index 5), proving the value is
// preserved from the wire through demux to the receive queue.
#[test]
fn ingest_preserves_header_traffic_class() {
    const T: u8 = 0x2e;
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    let lo = Ipv6Addr::LOOPBACK;
    let queue = stack.bind_udp6(lo, LOCAL_PORT).unwrap();

    let l4_len = crate::udp::UDP_HDR_LEN + 2;
    let mut frame = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + l4_len];
    crate::udp::build_into_v6(4_000, LOCAL_PORT, lo, lo, b"hi",
        &mut frame[crate::ipv6::IPV6_HDR_LEN..]);
    let mut hdr = crate::ipv6::Ipv6Hdr::build(lo, lo, IpProto::Udp, l4_len as u16);
    hdr.traffic_class = T;
    hdr.write_to(&mut frame[..crate::ipv6::IPV6_HDR_LEN]);
    stack.deliver_rx_ipv6(iface, &frame).unwrap();

    let (_, _, _, _, _hop, tclass, _body) = queue.recv(false).expect("datagram queued");
    assert_eq!(tclass, T, "ingested datagram must retain the header traffic class");
}

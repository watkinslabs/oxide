// `NetStack` — top-level glue. Owns the iface registry + routing
// table + a UDP-port socket map. Provides:
//   - register_iface
//   - add_route
//   - bind_udp(port) → returns a handle that the kernel uses for
//     recv (callbacks deferred to the syscall layer)
//   - send_udp_to(src_port, src_ip, dst_ip, dst_port, payload):
//     builds UDP+IPv4, looks up route, hands packet to iface
//   - deliver_rx(iface_id, &[u8] of L3 starting at IP header):
//     parses IPv4, demuxes to UDP / ICMP, dispatches reply (ICMP
//     echo) or queues to bound socket
//
// Hosted-testable on a LoopbackDev: send_udp_to writes to lo's
// xmit; the test calls drain_loopback() which pops from lo.rx and
// feeds back through deliver_rx.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{IpProto, Ipv4Addr, NetIfaceId};
use crate::icmp::{self, ICMP_TYPE_ECHO_REQUEST};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN, push_ipv4_header};
use crate::loopback::LoopbackDev;
use crate::netdev::{IfaceRegistry, NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::RouteTable;
use crate::udp::UdpHdr;

/// Per-port UDP rx queue. The bind-syscall reads from here.
pub struct UdpRxQueue {
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader. Each entry is
    /// (src_ip, src_port, payload bytes).
    pub q: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
}

pub struct NetStack {
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    udp:        Spinlock<BTreeMap<u16, UdpRxQueue>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    next_ip_id: Spinlock<u16, StackLockClass>,
}

impl NetStack {
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            udp:    Spinlock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
        }
    }

    /// Boot-time wiring: create + register a loopback netdev,
    /// add the canonical 127.0.0.0/8 route through it. Returns
    /// the assigned iface id.
    /// # C: O(1)
    pub fn register_loopback(&self) -> (NetIfaceId, Arc<LoopbackDev>) {
        let lo = Arc::new(LoopbackDev::new());
        let id = self.ifaces.register(lo.clone() as Arc<dyn NetDev>);
        self.routes.add(crate::route::RouteEntry {
            dst:        Ipv4Addr::new(127, 0, 0, 0),
            prefix_len: 8,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv4Addr::LOOPBACK),
        });
        (id, lo)
    }

    /// Reserve `port` for incoming UDP datagrams to `bind_ip`.
    /// `Eaddrinuse` if already bound.
    /// # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<()> {
        let mut g = self.udp.lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        g.insert(port, UdpRxQueue {
            bound_ip: bind_ip, bound_port: port, q: VecDeque::new(),
        });
        Ok(())
    }

    /// Pop one queued datagram for `port`, blocking-style: returns
    /// `None` immediately if nothing is queued.
    /// # C: O(log N)
    pub fn recv_udp(&self, port: u16) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let mut g = self.udp.lock();
        g.get_mut(&port)?.q.pop_front()
    }

    /// Build + transmit a UDP datagram. Looks up the route to
    /// `dst_ip`; if the route's iface is loopback (no L2), hand
    /// the IP packet straight to xmit.
    /// # C: O(payload + route lookup)
    pub fn send_udp_to(&self, src_ip: Ipv4Addr, src_port: u16,
                        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        let route = self.routes.lookup(dst_ip).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let total = IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = {
            let mut s = self.next_ip_id.lock();
            *s = s.wrapping_add(1);
            *s
        };
        push_ipv4_header(&mut p, src_ip, dst_ip, IpProto::Udp, id)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(route.iface);
        iface.xmit(p)
    }

    /// Deliver an L3 frame (starting at the IPv4 header) up the
    /// stack: parse IP, demux to ICMP / UDP, dispatch.
    /// # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let payload = &l3[hdr.ihl_bytes() .. total];
        match hdr.proto {
            p if p == IpProto::Icmp as u8 => {
                let echo = match icmp::IcmpEcho::parse(payload) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                if echo.typ == ICMP_TYPE_ECHO_REQUEST {
                    // Build reply, ship back via the same iface.
                    let reply = match icmp::build_echo_reply(payload) {
                        Ok(r) => r, Err(_) => return Ok(()),
                    };
                    let total = IPV4_HDR_LEN + reply.len();
                    let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
                    p.put(reply.len()).map_err(|_| NetError::Enobufs)?
                        .copy_from_slice(&reply);
                    let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
                    push_ipv4_header(&mut p, hdr.dst, hdr.src, IpProto::Icmp, id)
                        .map_err(|_| NetError::Enobufs)?;
                    p.proto = crate::addr::eth_p::IPV4;
                    p.iface = Some(iface);
                    let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
                    dev.xmit(p)?;
                }
            }
            p if p == IpProto::Udp as u8 => {
                let udp = UdpHdr::parse(payload, hdr.src, hdr.dst)
                    .map_err(|_| NetError::Einval)?;
                let mut g = self.udp.lock();
                if let Some(q) = g.get_mut(&udp.dst_port) {
                    let body = &payload[crate::udp::UDP_HDR_LEN..];
                    q.q.push_back((hdr.src, udp.src_port, body.to_vec()));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Test/boot-trace helper: drain `lo`'s xmit queue and feed
    /// each packet back through `deliver_rx` as if the wire round-
    /// tripped them. Real soft-IRQ NET_RX is the eventual driver
    /// for this.
    /// # C: O(N pending)
    pub fn drain_loopback(&self, iface: NetIfaceId, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() {
            let _ = self.deliver_rx(iface, p.data());
        }
    }
}

impl Default for NetStack { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

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
        // Build an Echo Request and hand it to the stack as a
        // received frame on lo. Stack should respond with an
        // Echo Reply on lo's xmit, which we then drain.
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
        // lo has the reply; drain + verify.
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
    fn route_miss_is_enetunreach() {
        let stack = NetStack::new();
        let _ = stack.register_loopback();
        // 8.8.8.8 has no route — expect Enetunreach.
        assert_eq!(
            stack.send_udp_to(Ipv4Addr::LOOPBACK, 1, Ipv4Addr::new(8,8,8,8), 1, b"x")
                 .err().unwrap(),
            NetError::Enetunreach,
        );
    }
}

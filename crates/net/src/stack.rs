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
use crate::tcp_hdr::{TcpHdr, flags as tcp_flags, TCP_HDR_MIN_LEN};
use crate::tcp_conn::{TcpConn, Endpoint};

/// Per-port UDP rx queue. The bind-syscall reads from here.
pub struct UdpRxQueue {
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader. Each entry is
    /// (src_ip, src_port, payload bytes).
    pub q: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
}

/// Connection 4-tuple key for TCP demultiplexing.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TcpKey {
    pub local_ip:    Ipv4Addr,
    pub local_port:  u16,
    pub remote_ip:   Ipv4Addr,
    pub remote_port: u16,
}

/// Listening socket key (only local side).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TcpListenKey { pub local_ip: Ipv4Addr, pub local_port: u16 }

/// Stack-owned per-connection record. Wraps the TcpConn TCB in
/// its own Spinlock so demux + app calls don't contend with the
/// listener table lock. Cheap to clone the Arc.
pub struct TcpEntry {
    pub conn: Spinlock<TcpConn, StackLockClass>,
}

pub struct TcpListenEntry {
    /// Backlog of accepted-but-not-yet-claimed Arc<TcpEntry>.
    pub accept_q: Spinlock<VecDeque<Arc<TcpEntry>>, StackLockClass>,
    pub local: Endpoint,
}

pub struct NetStack {
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    udp:        Spinlock<BTreeMap<u16, UdpRxQueue>, StackLockClass>,
    tcp_conns:    Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>,
    tcp_listens:  Spinlock<BTreeMap<TcpListenKey, Arc<TcpListenEntry>>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    next_ip_id: Spinlock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    next_isn: Spinlock<u32, StackLockClass>,
}

impl NetStack {
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            udp:    Spinlock::new(BTreeMap::new()),
            tcp_conns:   Spinlock::new(BTreeMap::new()),
            tcp_listens: Spinlock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
            next_isn:   Spinlock::new(0x1000_0000),
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

    /// Open a passive listener at (`local_ip`, `local_port`).
    /// Returns the listen-entry Arc so callers can poll `accept`.
    /// `Eaddrinuse` if the (ip, port) tuple is already a listener.
    /// # C: O(log N)
    pub fn tcp_listen(&self, local_ip: Ipv4Addr, local_port: u16)
        -> NetResult<Arc<TcpListenEntry>>
    {
        let key = TcpListenKey { local_ip, local_port };
        let mut g = self.tcp_listens.lock();
        if g.contains_key(&key) { return Err(NetError::Eaddrinuse); }
        let entry = Arc::new(TcpListenEntry {
            accept_q: Spinlock::new(VecDeque::new()),
            local: Endpoint { ip: local_ip, port: local_port },
        });
        g.insert(key, entry.clone());
        Ok(entry)
    }

    /// Open an active TCP connection from `local` to `remote`.
    /// Emits the SYN, parks the half-open conn in the demux table.
    /// Caller polls the returned `TcpEntry`'s state until it
    /// reaches `Established` (or until a Reset happens).
    /// # C: O(log N) demux insert + 1 segment xmit
    pub fn tcp_connect(&self, local_ip: Ipv4Addr, local_port: u16,
                        remote_ip: Ipv4Addr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        let isn = {
            let mut s = self.next_isn.lock();
            *s = s.wrapping_add(0x1000);
            *s
        };
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: local_port },
            Endpoint { ip: remote_ip, port: remote_port },
            isn,
        );
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        let entry = Arc::new(TcpEntry { conn: Spinlock::new(conn) });
        let key = TcpKey { local_ip, local_port, remote_ip, remote_port };
        self.tcp_conns.lock().insert(key, entry.clone());
        self.send_l4_over_ipv4(local_ip, remote_ip, IpProto::Tcp, &syn)?;
        Ok(entry)
    }

    /// Pop one accepted connection from a listener's backlog.
    /// Returns `None` if no connection is ready.
    /// # C: O(1)
    pub fn tcp_accept(&self, listener: &TcpListenEntry) -> Option<Arc<TcpEntry>> {
        listener.accept_q.lock().pop_front()
    }

    /// Application sends `data` on an established connection.
    /// Returns the number of bytes drained into segments and
    /// transmitted; bytes still queued (waiting for ACK clocking)
    /// stay in the conn's send_buf for output() to drain later.
    /// # C: O(data + N segments)
    pub fn tcp_send(&self, entry: &TcpEntry, data: &[u8]) -> NetResult<usize> {
        let segs;
        let (src, dst) = {
            let mut c = entry.conn.lock();
            c.send(data);
            segs = c.output(1500);
            (c.local.ip, c.remote.ip)
        };
        for s in &segs {
            self.send_l4_over_ipv4(src, dst, IpProto::Tcp, s)?;
        }
        Ok(data.len())
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len()))
    pub fn tcp_recv(&self, entry: &TcpEntry, max: usize) -> Vec<u8> {
        entry.conn.lock().recv(max)
    }

    /// Application initiates graceful close: emits FIN, transitions
    /// the conn out of ESTABLISHED. The demux remains responsible
    /// for the rest of the close handshake (CloseWait, etc.).
    /// # C: O(1)
    pub fn tcp_close(&self, entry: &TcpEntry) -> NetResult<()> {
        let (seg, src, dst) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip)
        };
        self.send_l4_over_ipv4(src, dst, IpProto::Tcp, &seg)
    }

    /// Wrap an L4 segment in IPv4 + xmit it via the routing table.
    /// # C: O(payload)
    fn send_l4_over_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        let route = self.routes.lookup(dst).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let total = IPV4_HDR_LEN + l4.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        p.put(l4.len()).map_err(|_| NetError::Enobufs)?
            .copy_from_slice(l4);
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        push_ipv4_header(&mut p, src, dst, proto, id)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(route.iface);
        iface.xmit(p)
    }

    /// Deliver an L3 frame (starting at the IPv4 header) up the
    /// stack: parse IP, demux to ICMP / UDP / TCP, dispatch.
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
            p if p == IpProto::Tcp as u8 => self.deliver_tcp(iface, hdr.src, hdr.dst, payload)?,
            _ => {}
        }
        Ok(())
    }

    /// TCP demux. Look up an established connection by 4-tuple
    /// first; on miss, look for a matching listener and (on SYN)
    /// instantiate a new connection from it. Drives the matched
    /// TcpConn's `input`; xmit any returned response segment.
    /// # C: O(log N) lookup + O(payload) handler
    fn deliver_tcp(&self, _iface: NetIfaceId,
                    src_ip: Ipv4Addr, dst_ip: Ipv4Addr, seg: &[u8])
        -> NetResult<()>
    {
        if seg.len() < TCP_HDR_MIN_LEN { return Err(NetError::Einval); }
        let hdr = match TcpHdr::parse(seg, src_ip, dst_ip) {
            Ok(h) => h, Err(_) => return Ok(()),
        };
        let key = TcpKey {
            local_ip: dst_ip, local_port: hdr.dst_port,
            remote_ip: src_ip, remote_port: hdr.src_port,
        };
        // Established-conn lookup first.
        let entry = {
            let g = self.tcp_conns.lock();
            g.get(&key).cloned()
        };
        if let Some(entry) = entry {
            let resp = entry.conn.lock().input(src_ip, dst_ip, seg)
                .map_err(|_| NetError::Einval)?;
            if let Some(r) = resp {
                self.send_l4_over_ipv4(dst_ip, src_ip, IpProto::Tcp, &r)?;
            }
            return Ok(());
        }
        // Listener path: only SYNs spawn new conns.
        if (hdr.flags & tcp_flags::SYN) == 0 { return Ok(()); }
        let lkey = TcpListenKey { local_ip: dst_ip, local_port: hdr.dst_port };
        let listener = {
            let g = self.tcp_listens.lock();
            g.get(&lkey).cloned()
                .or_else(|| g.get(&TcpListenKey { local_ip: Ipv4Addr::ANY, local_port: hdr.dst_port }).cloned())
        };
        let listener = match listener { Some(l) => l, None => return Ok(()) };
        let mut new_conn = TcpConn::new_listener(listener.local);
        let resp = new_conn.input(src_ip, dst_ip, seg)
            .map_err(|_| NetError::Einval)?;
        let new_entry = Arc::new(TcpEntry { conn: Spinlock::new(new_conn) });
        self.tcp_conns.lock().insert(key, new_entry.clone());
        listener.accept_q.lock().push_back(new_entry);
        if let Some(r) = resp {
            self.send_l4_over_ipv4(dst_ip, src_ip, IpProto::Tcp, &r)?;
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
    fn tcp_handshake_via_loopback() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234).unwrap();
        let client = stack.tcp_connect(
            Ipv4Addr::LOOPBACK, 50000,
            Ipv4Addr::LOOPBACK, 1234,
        ).unwrap();
        // Drain lo a couple of times: SYN → SYN+ACK → ACK.
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let server = stack.tcp_accept(&listener).expect("accepted");
        assert_eq!(client.conn.lock().state, crate::tcp_state::TcpState::Established);
        assert_eq!(server.conn.lock().state, crate::tcp_state::TcpState::Established);
    }

    #[test]
    fn tcp_data_round_trip_via_loopback() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234).unwrap();
        let client = stack.tcp_connect(
            Ipv4Addr::LOOPBACK, 50000,
            Ipv4Addr::LOOPBACK, 1234,
        ).unwrap();
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let server = stack.tcp_accept(&listener).unwrap();
        stack.tcp_send(&client, b"oxide-tcp-payload").unwrap();
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let got = stack.tcp_recv(&server, 1024);
        assert_eq!(&got[..], b"oxide-tcp-payload");
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

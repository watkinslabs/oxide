// F180a: IPv6 transport methods on NetStack — UDP bind/recv/send,
// ICMPv6 echo response, NDP dispatch shells. Extracted from
// stack.rs to stay under the 1000-line per-file cap (docs/08§7).
// TCP-over-IPv6 lands in F180b once TcpConn is address-family
// agnostic; NDP cache + NS/NA in F180c.

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN, push_ipv6_header};
use crate::netdev::{NetError, NetResult};
use crate::pkt::Pkt;
use crate::stack::NetStack;

/// F180a: per-port IPv6 UDP queue. Same shape as `UdpRxQueue`
/// but keyed by IPv6 source-address.
pub struct Udp6RxQueue {
    pub bound_ip:   Ipv6Addr,
    pub bound_port: u16,
    pub q: Spinlock<VecDeque<(Ipv6Addr, u16, Vec<u8>)>, StackLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub error_eno: core::sync::atomic::AtomicI32,
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl Udp6RxQueue {
    /// # C: O(1)
    pub fn new(bound_ip: Ipv6Addr, bound_port: u16) -> Self {
        Self {
            bound_ip, bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error_eno: core::sync::atomic::AtomicI32::new(0),
            poll_subs: Spinlock::new(None),
        }
    }
    /// # C: O(1)
    pub fn take_error(&self) -> i32 {
        self.error_eno.swap(0, core::sync::atomic::Ordering::AcqRel)
    }
    /// # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }
}

impl NetStack {
    /// F180a: IPv6 UDP bind. `Eaddrinuse` if port taken.
    /// # C: O(log N)
    pub fn bind_udp6(&self, bind_ip: Ipv6Addr, port: u16) -> NetResult<()> {
        let mut g = self.udp6_map().lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        g.insert(port, Arc::new(Udp6RxQueue::new(bind_ip, port)));
        Ok(())
    }

    /// F180a: pop one queued IPv6 datagram for `port`.
    /// # C: O(log N)
    pub fn recv_udp6(&self, port: u16) -> Option<(Ipv6Addr, u16, Vec<u8>)> {
        let q = { self.udp6_map().lock().get(&port)?.clone() };
        let popped = q.q.lock().pop_front();
        popped
    }

    /// F180a: Arc clone for sys_recvfrom park path.
    /// # C: O(log N)
    pub fn udp6_queue_arc(&self, port: u16) -> Option<Arc<Udp6RxQueue>> {
        self.udp6_map().lock().get(&port).cloned()
    }

    /// F180a: release a v6 UDP port (close path).
    /// # C: O(log N)
    pub fn unbind_udp6(&self, port: u16) {
        self.udp6_map().lock().remove(&port);
    }

    /// F180a: build + transmit a UDP/IPv6 datagram. v1 routing:
    /// loopback → lo iface, else first non-lo. Real v6 route table
    /// lands in F180c with prefix-len + scope support.
    /// # C: O(payload + route lookup)
    pub fn send_udp6_to(&self, src_ip: Ipv6Addr, src_port: u16,
                         dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        let devs = self.ifaces.snapshot_devs();
        let iface_id = if dst_ip == Ipv6Addr::LOOPBACK {
            devs.iter().find(|(_, d)| d.name() == "lo")
                .map(|(i, _)| *i).ok_or(NetError::Enetunreach)?
        } else {
            devs.iter().find(|(_, d)| d.name() != "lo")
                .map(|(i, _)| *i).ok_or(NetError::Enetunreach)?
        };
        let iface = self.ifaces.lookup(iface_id).ok_or(NetError::Enetunreach)?;
        let l4_len = 8 + payload.len();
        let total = IPV6_HDR_LEN + l4_len;
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
        let body = p.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src_ip, dst_ip, payload, body);
        push_ipv6_header(&mut p, src_ip, dst_ip, IpProto::Udp)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface_id);
        iface.xmit(p)
    }

    /// F180: deliver an IPv6 L3 frame. Parses fixed header; demuxes
    /// next_header to ICMPv6 (echo + NS/NA stubs), UDP (route to
    /// bound udp6 queue), TCP (drop until F180b TcpConn refactor).
    /// Extension headers skipped (no HBH/Routing/Fragment yet).
    /// # C: O(payload)
    pub fn deliver_rx_ipv6(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let hdr = Ipv6Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let payload_end = IPV6_HDR_LEN + hdr.payload_length as usize;
        if payload_end > l3.len() { return Err(NetError::Einval); }
        let payload = &l3[IPV6_HDR_LEN..payload_end];
        match hdr.next_header {
            n if n == crate::icmpv6::IPPROTO_ICMPV6 => {
                self.deliver_rx_icmpv6(iface, hdr.src, hdr.dst, payload)?;
            }
            n if n == IpProto::Udp as u8 => {
                let udp = match crate::udp::parse_v6(payload, hdr.src, hdr.dst) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                let q_arc = { self.udp6_map().lock().get(&udp.dst_port).cloned() };
                if let Some(q) = q_arc {
                    let body = &payload[crate::udp::UDP_HDR_LEN .. udp.length as usize];
                    q.q.lock().push_back((hdr.src, udp.src_port, body.to_vec()));
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        q.waiters.wake_all();
                        let slot = q.poll_subs.lock().clone();
                        if let Some(weak) = slot {
                            if let Some(s) = weak.upgrade() { s.notify(); }
                        }
                    }
                }
            }
            n if n == IpProto::Tcp as u8 => {
                // F180b: dispatch through the unified deliver_tcp; the
                // demux table keys on IpAddr so v4 + v6 share it.
                let src = crate::addr::IpAddr::V6(hdr.src);
                let dst = crate::addr::IpAddr::V6(hdr.dst);
                let _ = self.deliver_tcp(iface, src, dst, payload);
            }
            _ => {}
        }
        Ok(())
    }

    /// F180/F180c: ICMPv6 dispatch — echo respond now; NDP NS/NA
    /// handling stubs for the F180c follow-on (cache + reply build).
    /// # C: O(payload)
    fn deliver_rx_icmpv6(
        &self, iface: NetIfaceId, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8],
    ) -> NetResult<()> {
        if payload.is_empty() { return Ok(()); }
        let typ = payload[0];
        match typ {
            t if t == crate::icmpv6::ICMPV6_TYPE_ECHO_REQUEST => {
                let reply = match crate::icmpv6::build_echo_reply(src, dst, payload) {
                    Ok(r) => r, Err(_) => return Ok(()),
                };
                self.xmit_ipv6(iface, dst, src, IpProto::Icmpv6, &reply)?;
            }
            t if t == crate::ndp::NDP_NS => {
                // F180c: parse the solicitation; if the target matches
                // an address bound on this iface, build a solicited NA
                // and ship it back. Source-lladdr in the NS populates
                // the cache too (peer is talking to us).
                if let Ok(msg) = crate::ndp::NdpMsg::parse(payload, src, dst) {
                    if let Some(mac) = msg.lladdr { self.ndp.insert(src, mac); }
                    if self.v6_addr_owned_by(iface, msg.target) {
                        let our_mac = self.ifaces.lookup(iface)
                            .map(|d| d.mac()).unwrap_or(crate::addr::MacAddr::ZERO);
                        let na = crate::ndp::NdpMsg::build_na(
                            msg.target, src, our_mac, msg.target, 0x2000_0000,
                        );
                        self.xmit_ipv6(iface, msg.target, src, IpProto::Icmpv6, &na)?;
                    }
                }
            }
            t if t == crate::ndp::NDP_NA => {
                // F180c: cache the target_lladdr binding so subsequent
                // v6 xmit on this neighbor can fill the Ethernet dst.
                if let Ok(msg) = crate::ndp::NdpMsg::parse(payload, src, dst) {
                    if let Some(mac) = msg.lladdr {
                        self.ndp.insert(msg.target, mac);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// F180b: family-dispatching L4 xmit. v4 stays on v4; v6 → v6;
    /// mismatched family pair fails Einval (no v4-in-v6 tunneling).
    /// # C: O(payload)
    pub fn send_l4_over_ip(&self, src: IpAddr, dst: IpAddr,
                            proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                // F161 wrapper handles TCP only; for non-TCP protos we
                // still need a v4 path. send_l4_over_ipv4 is private; the
                // only currently-routed proto via send_l4_over_ip is TCP,
                // so the pub wrapper suffices. Other protos (UDP) use
                // their own send_udp_to / send_udp6_to paths.
                let _ = proto;
                self.send_l4_over_ipv4_pub(s, d, l4)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => self.send_l4_over_ipv6(s, d, proto, l4),
            _ => Err(NetError::Einval),
        }
    }

    /// F180b: build + xmit a v6-encapsulated L4 segment. v1 routes
    /// loopback → lo, else first non-lo iface; F180c lifts to a real
    /// v6 route table.
    /// # C: O(payload + route lookup)
    pub(crate) fn send_l4_over_ipv6(&self, src: Ipv6Addr, dst: Ipv6Addr,
                                     proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        let devs = self.ifaces.snapshot_devs();
        let iface_id = if dst == Ipv6Addr::LOOPBACK {
            devs.iter().find(|(_, d)| d.name() == "lo")
                .map(|(i, _)| *i).ok_or(NetError::Enetunreach)?
        } else {
            devs.iter().find(|(_, d)| d.name() != "lo")
                .map(|(i, _)| *i).ok_or(NetError::Enetunreach)?
        };
        let iface = self.ifaces.lookup(iface_id).ok_or(NetError::Enetunreach)?;
        let total = IPV6_HDR_LEN + l4.len();
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
        p.put(l4.len()).map_err(|_| NetError::Enobufs)?
            .copy_from_slice(l4);
        push_ipv6_header(&mut p, src, dst, proto)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface_id);
        iface.xmit(p)
    }

    /// F180a: wrap `body` in IPv6 + xmit.
    /// # C: O(payload)
    fn xmit_ipv6(&self, iface: NetIfaceId, src: Ipv6Addr, dst: Ipv6Addr,
                  proto: IpProto, body: &[u8]) -> NetResult<()> {
        let total = IPV6_HDR_LEN + body.len();
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total);
        p.put(body.len()).map_err(|_| NetError::Enobufs)?
            .copy_from_slice(body);
        push_ipv6_header(&mut p, src, dst, proto)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface);
        let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
        dev.xmit(p)
    }
}

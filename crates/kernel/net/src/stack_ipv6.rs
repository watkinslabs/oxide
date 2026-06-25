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
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::stack::NetStack;
use crate::netfilter_hook::{nf_hook_eval, nf_output, NFPROTO_IPV6,
    NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN};

/// F180a: per-port IPv6 UDP queue. Same shape as `UdpRxQueue`
/// but keyed by IPv6 source-address.
pub struct Udp6RxQueue {
    pub bound_ip:   Ipv6Addr,
    pub bound_port: u16,
    pub q: Spinlock<VecDeque<(Ipv6Addr, u16, Vec<u8>)>, StackLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub error_eno: core::sync::atomic::AtomicI32,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
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
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
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
        self.bind_udp6_with_iface(bind_ip, port, None)
    }

    /// IPv6 UDP bind with an optional SO_BINDTODEVICE filter. # C: O(log N)
    pub fn bind_udp6_with_iface(&self, bind_ip: Ipv6Addr, port: u16,
                                iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut g = self.udp6_map().lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        let q = Arc::new(Udp6RxQueue::new(bind_ip, port));
        q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
        g.insert(port, q);
        Ok(())
    }

    /// Update the bound iface for an already-bound IPv6 UDP port. # C: O(log N)
    pub fn set_udp6_bound_iface(&self, port: u16, iface: Option<NetIfaceId>) -> bool {
        if let Some(q) = self.udp6_map().lock().get(&port) {
            q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
            true
        } else { false }
    }

    /// F180a: pop one queued IPv6 datagram for `port`.
    /// # C: O(log N)
    pub fn recv_udp6(&self, port: u16) -> Option<(Ipv6Addr, u16, Vec<u8>)> {
        self.recv_udp6_opts(port, false)
    }

    /// F180a: pop or peek one queued IPv6 datagram for `port`.
    /// # C: O(log N + payload bytes when peeking)
    pub fn recv_udp6_opts(&self, port: u16, peek: bool) -> Option<(Ipv6Addr, u16, Vec<u8>)> {
        let q = { self.udp6_map().lock().get(&port)?.clone() };
        let mut g = q.q.lock();
        if peek { g.front().cloned() } else { g.pop_front() }
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

    /// F180a: build + transmit a UDP/IPv6 datagram.
    /// # C: O(payload + route lookup)
    pub fn send_udp6_to(&self, src_ip: Ipv6Addr, src_port: u16,
                         dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        // Source-address selection (RFC 6724, v1 subset): an unbound
        // socket sends with src = :: (unspecified). For a loopback
        // destination the kernel must substitute ::1 so the peer's
        // recvfrom sees a meaningful source. Non-loopback dsts keep
        // :: until the v6 route table (F180c) supplies a real prefix.
        let src_ip = if src_ip == Ipv6Addr::ANY && dst_ip == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else {
            src_ip
        };
        let (iface_id, iface) = self.route6_iface(dst_ip).ok_or(NetError::Enetunreach)?;
        let l4_len = 8 + payload.len();
        let total = IPV6_HDR_LEN + l4_len;
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
        let body = p.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src_ip, dst_ip, payload, body);
        push_ipv6_header(&mut p, src_ip, dst_ip, IpProto::Udp)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface_id);
        if !nf_output(&p, NFPROTO_IPV6) { return Ok(()); }
        iface.xmit(p)
    }

    /// F180: deliver an IPv6 L3 frame. Parses fixed header; reassembles
    /// Fragment extension headers; demuxes next_header to ICMPv6, UDP, or TCP.
    /// # C: O(payload)
    pub fn deliver_rx_ipv6(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        // Netfilter ingress: PRE_ROUTING then (host stack → local) LOCAL_IN.
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV6) == 0 { return Ok(()); }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV6) == 0 { return Ok(()); }
        let hdr = Ipv6Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let payload_end = IPV6_HDR_LEN + hdr.payload_length as usize;
        if payload_end > l3.len() { return Err(NetError::Einval); }
        let payload = &l3[IPV6_HDR_LEN..payload_end];
        let assembled;
        let (next_header, payload) = if hdr.next_header == IpProto::Fragment as u8 {
            if payload.len() < 8 { return Err(NetError::Einval); }
            let next = payload[0];
            let frag = u16::from_be_bytes([payload[2], payload[3]]);
            let off8 = ((frag >> 3) & 0x1fff) as usize;
            let more = (frag & 1) != 0;
            let id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let k = crate::ipv6_reasm::ReasmKey {
                src: hdr.src,
                dst: hdr.dst,
                next_header: next,
                id,
            };
            match self.ipv6_reasm.push(k, crate::stack::net_now_ns(), off8 * 8, &payload[8..], more) {
                Some(bytes) => {
                    assembled = bytes;
                    (next, &assembled[..])
                }
                None => return Ok(()),
            }
        } else {
            (hdr.next_header, payload)
        };
        self.deliver_rx_ipv6_payload(iface, hdr.src, hdr.dst, next_header, payload)
    }

    /// Demux a complete IPv6 upper-layer payload after fixed-header parsing
    /// and any Fragment reassembly. # C: O(payload)
    fn deliver_rx_ipv6_payload(
        &self,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
    ) -> NetResult<()> {
        match next_header {
            n if n == crate::icmpv6::IPPROTO_ICMPV6 => {
                self.deliver_rx_icmpv6(iface, src, dst, payload)?;
            }
            n if n == IpProto::Udp as u8 => {
                let udp = match crate::udp::parse_v6(payload, src, dst) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                let q_arc = { self.udp6_map().lock().get(&udp.dst_port).cloned() };
                if let Some(q) = q_arc {
                    let bound = q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
                    if bound != 0 && bound != iface.raw() { return Ok(()); }
                    let body = &payload[crate::udp::UDP_HDR_LEN .. udp.length as usize];
                    q.q.lock().push_back((src, udp.src_port, body.to_vec()));
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
                let src = crate::addr::IpAddr::V6(src);
                let dst = crate::addr::IpAddr::V6(dst);
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
            t if t == crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG => {
                // F191: ICMPv6 Packet Too Big. Bytes 4..8 = MTU;
                // payload[8..] = invoking packet (IPv6 hdr + L4).
                if payload.len() >= 8 + crate::ipv6::IPV6_HDR_LEN + 4 {
                    let mtu = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    self.handle_v6_packet_too_big(mtu, &payload[8..]);
                }
            }
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
        self.send_l4_over_ip_tos(src, dst, proto, l4, 0)
    }

    /// F190: ECN-aware variant — `tos` populates the IPv4 TOS byte
    /// (or v6 Traffic-Class). ECT(0)=0x02 on ECN-enabled flows.
    /// # C: O(payload)
    pub fn send_l4_over_ip_tos(&self, src: IpAddr, dst: IpAddr,
                                proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()>
    {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                if tos != 0 {
                    return self.send_l4_over_ipv4_tos(s, d, proto, l4, tos);
                }
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

    /// F180b: build + xmit a v6-encapsulated L4 segment.
    /// # C: O(payload + route lookup)
    pub(crate) fn send_l4_over_ipv6(&self, src: Ipv6Addr, dst: Ipv6Addr,
                                     proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        let (iface_id, iface) = self.route6_iface(dst).ok_or(NetError::Enetunreach)?;
        self.xmit_ipv6_l4_on_iface(iface_id, iface, src, dst, proto, l4)
    }

    /// Emit one IPv6 L4 payload on a selected iface. If the fixed IPv6
    /// header plus L4 payload exceeds the iface MTU, emit RFC 8200 Fragment
    /// extension headers and split the payload into 8-byte aligned fragments.
    /// # C: O(payload)
    pub(crate) fn xmit_ipv6_l4_on_iface(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv6Addr, dst: Ipv6Addr, proto: IpProto,
        l4: &[u8]) -> NetResult<()>
    {
        let mtu = iface.mtu() as usize;
        let total = IPV6_HDR_LEN + l4.len();
        if l4.len() > u16::MAX as usize {
            return Err(NetError::Enobufs);
        }
        if total <= mtu {
            let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            p.put(l4.len()).map_err(|_| NetError::Enobufs)?
                .copy_from_slice(l4);
            push_ipv6_header(&mut p, src, dst, proto)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
            if !nf_output(&p, NFPROTO_IPV6) { return Ok(()); }
            return iface.xmit(p);
        }

        let max_payload = mtu.saturating_sub(IPV6_HDR_LEN + 8) & !7usize;
        if max_payload == 0 { return Err(NetError::Enobufs); }
        let frag_id = self.next_ipv6_frag_id();
        let mut off = 0usize;
        while off < l4.len() {
            let take = core::cmp::min(max_payload, l4.len() - off);
            let more = off + take < l4.len();
            let frag_off_units = (off / 8) as u16;
            let off_flags = (frag_off_units << 3) | if more { 1 } else { 0 };
            let frag_payload_len = 8 + take;
            let total = IPV6_HDR_LEN + frag_payload_len;
            let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            let body = p.put(frag_payload_len).map_err(|_| NetError::Enobufs)?;
            body[0] = proto as u8;
            body[1] = 0;
            body[2..4].copy_from_slice(&off_flags.to_be_bytes());
            body[4..8].copy_from_slice(&frag_id.to_be_bytes());
            body[8..].copy_from_slice(&l4[off..off + take]);
            push_ipv6_header(&mut p, src, dst, IpProto::Fragment)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
            if nf_output(&p, NFPROTO_IPV6) {
                iface.xmit(p)?;
            }
            off += take;
        }
        Ok(())
    }

    fn next_ipv6_frag_id(&self) -> u32 {
        let mut s = self.next_ip_id.lock();
        *s = s.wrapping_add(1);
        *s as u32
    }

    /// F191: clamp the affected TCP conn's peer_mss after an ICMPv6
    /// Packet Too Big. `invoking` is the bytes after the ICMPv6 hdr:
    /// IPv6 hdr (40 B) + first 4 bytes of L4 (ports).
    /// # C: O(log N) demux lookup
    fn handle_v6_packet_too_big(&self, mtu: u32, invoking: &[u8]) {
        use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
        use crate::stack::TcpKey;
        let h = match Ipv6Hdr::parse(invoking) { Ok(h) => h, Err(_) => return };
        if h.next_header != IpProto::Tcp as u8 { return; }
        if invoking.len() < IPV6_HDR_LEN + 4 { return; }
        let l4 = &invoking[IPV6_HDR_LEN..];
        let src_port = u16::from_be_bytes([l4[0], l4[1]]);
        let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        // v6 overhead = 40 (no TCP options budget).
        let new_mss = (mtu as u16).saturating_sub(40);
        if new_mss < 1280u16.saturating_sub(40) { return; }
        let key = TcpKey {
            local_ip:    crate::addr::IpAddr::V6(h.src),
            local_port:  src_port,
            remote_ip:   crate::addr::IpAddr::V6(h.dst),
            remote_port: dst_port,
        };
        if let Some(entry) = self.tcp_conns_map().lock().get(&key).cloned() {
            let mut c = entry.conn.lock();
            if c.peer_mss == 0 || new_mss < c.peer_mss {
                c.peer_mss = new_mss;
            }
        }
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
        if !nf_output(&p, NFPROTO_IPV6) { return Ok(()); }
        dev.xmit(p)
    }
}

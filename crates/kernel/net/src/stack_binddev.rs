use alloc::sync::Arc;

use crate::addr::{IpAddr, IpProto, Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::ipv4::IPV4_HDR_LEN;
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::stack::{NetStack, TcpEntry, TcpKey};
use crate::tcp_conn::{Endpoint, TcpConn};

impl NetStack {
    /// Resolve a raw SO_BINDTODEVICE ifindex. 0 means unbound. # C: O(N)
    pub fn bound_iface(&self, raw: u32) -> NetResult<Option<NetIfaceId>> {
        if raw == 0 { return Ok(None); }
        let id = NetIfaceId::from_raw(raw);
        self.ifaces.lookup(id).map(|_| Some(id)).ok_or(NetError::Enodev)
    }

    /// TCP MSS for `dst`, honoring a socket-bound egress interface. # C: O(N)
    pub fn mss_for_dst_on_iface(&self, dst: IpAddr, bound: Option<NetIfaceId>) -> u16 {
        let mtu = match bound {
            Some(id) => self.ifaces.lookup(id).map(|i| i.mtu()),
            None => match dst {
                IpAddr::V4(d) => self.routes.lookup(d)
                    .and_then(|r| self.ifaces.lookup(r.iface))
                    .map(|i| i.mtu()),
                IpAddr::V6(d) => self.route6_iface(d).map(|(_, i)| i.mtu()),
            },
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// Build + transmit UDP/IPv4, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_udp_to_bound(&self, src_ip: Ipv4Addr, src_port: u16,
        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>)
        -> NetResult<()>
    {
        self.send_udp_to_bound_opts(src_ip, src_port, dst_ip, dst_port, payload, bound, 0, crate::ipv4::IPV4_DEFAULT_TTL)
    }

    /// Build + transmit UDP/IPv4 with explicit TOS/TTL. # C: O(payload + N)
    pub fn send_udp_to_bound_opts(&self, src_ip: Ipv4Addr, src_port: u16,
        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8)
        -> NetResult<()>
    {
        let (iface_id, iface) = self.route_v4_iface(dst_ip, bound)?;
        let total = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        crate::udp::UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = self.next_ipv4_id();
        self.xmit_ipv4_l4_on_iface_opts(iface_id, iface, src_ip, dst_ip, IpProto::Udp, p.data(), tos, ttl, id)
    }

    /// Build + transmit UDP/IPv6, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_udp6_to_bound(&self, src_ip: Ipv6Addr, src_port: u16,
        dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>)
        -> NetResult<()>
    {
        let src_ip = if src_ip == Ipv6Addr::ANY && dst_ip == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else {
            src_ip
        };
        let (iface_id, iface) = match bound {
            Some(id) => (id, self.ifaces.lookup(id).ok_or(NetError::Enetunreach)?),
            None => self.route6_iface(dst_ip).ok_or(NetError::Enetunreach)?,
        };
        let l4_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(0, l4_len);
        let body = p.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src_ip, dst_ip, payload, body);
        self.xmit_ipv6_l4_on_iface(iface_id, iface, src_ip, dst_ip, IpProto::Udp, p.data())
    }

    /// Active TCP open with a socket-bound egress interface. # C: O(log N + payload)
    pub fn tcp_connect_ip_bound(&self, local_ip: IpAddr, local_port: u16,
        remote_ip: IpAddr, remote_port: u16, bound: Option<NetIfaceId>)
        -> NetResult<Arc<TcpEntry>>
    {
        let isn = self.next_isn_value();
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: local_port },
            Endpoint { ip: remote_ip, port: remote_port },
            isn,
        );
        conn.own_mss = self.mss_for_dst_on_iface(remote_ip, bound);
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        let entry = Arc::new(TcpEntry::new(conn));
        entry.set_bound_iface(bound);
        let key = TcpKey { local_ip, local_port, remote_ip, remote_port };
        self.tcp_conns.lock().insert(key, entry.clone());
        self.send_l4_over_ip_bound(local_ip, remote_ip, IpProto::Tcp, &syn, bound)?;
        crate::stack::stamp_last_sent_public(&entry, 1);
        Ok(entry)
    }

    /// Family-dispatched L4 transmit, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_l4_over_ip_bound(&self, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], bound: Option<NetIfaceId>) -> NetResult<()>
    {
        self.send_l4_over_ip_tos_bound(src, dst, proto, l4, 0, bound)
    }

    /// TOS/traffic-class L4 transmit, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_l4_over_ip_tos_bound(&self, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], tos: u8, bound: Option<NetIfaceId>) -> NetResult<()>
    {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => self.send_l4_over_ipv4_bound(s, d, proto, l4, tos, bound),
            (IpAddr::V6(s), IpAddr::V6(d)) => self.send_l4_over_ipv6_bound(s, d, proto, l4, bound),
            _ => Err(NetError::Einval),
        }
    }

    fn send_l4_over_ipv4_bound(&self, src: Ipv4Addr, dst: Ipv4Addr,
        proto: IpProto, l4: &[u8], tos: u8, bound: Option<NetIfaceId>) -> NetResult<()>
    {
        let (iface_id, iface) = self.route_v4_iface(dst, bound)?;
        self.xmit_ipv4_l4_on_iface(iface_id, iface, src, dst, proto, l4, tos, self.next_ipv4_id())
    }

    fn send_l4_over_ipv6_bound(&self, src: Ipv6Addr, dst: Ipv6Addr,
        proto: IpProto, l4: &[u8], bound: Option<NetIfaceId>) -> NetResult<()>
    {
        let (iface_id, iface) = match bound {
            Some(id) => (id, self.ifaces.lookup(id).ok_or(NetError::Enetunreach)?),
            None => self.route6_iface(dst).ok_or(NetError::Enetunreach)?,
        };
        self.xmit_ipv6_l4_on_iface(iface_id, iface, src, dst, proto, l4)
    }

    fn route_v4_iface(&self, dst: Ipv4Addr, bound: Option<NetIfaceId>)
        -> NetResult<(NetIfaceId, Arc<dyn NetDev>)>
    {
        if let Some(id) = bound {
            let iface = self.ifaces.lookup(id).ok_or(NetError::Enetunreach)?;
            return Ok((id, iface));
        }
        match self.routes.lookup(dst) {
            Some(r) => Ok((r.iface, self.ifaces.lookup(r.iface).ok_or(NetError::Enetunreach)?)),
            None if dst.is_broadcast() => {
                let devs = self.ifaces.snapshot_devs();
                let pick = devs.iter().find(|(_, d)| d.name() != "lo").ok_or(NetError::Enetunreach)?;
                Ok((pick.0, pick.1.clone()))
            }
            None => Err(NetError::Enetunreach),
        }
    }

    fn next_ipv4_id(&self) -> u16 {
        let mut s = self.next_ip_id.lock();
        *s = s.wrapping_add(1);
        *s
    }

    fn next_isn_value(&self) -> u32 {
        let mut s = self.next_isn.lock();
        *s = s.wrapping_add(0x1000);
        *s
    }
}

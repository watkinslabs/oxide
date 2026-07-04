use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::addr::{IpProto, Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::ipv6::{IPV6_HDR_LEN, push_ipv6_header};
use crate::pkt::Pkt;
use crate::netfilter_hook::{nf_output, NFPROTO_IPV6};
use crate::stack::NetStack;

use super::{Ipv6IfaceAddr, Udp6RxQueue};

impl NetStack {
    pub fn add_v6_addr(&self, iface: NetIfaceId, ip: Ipv6Addr) {
        self.add_v6_addr_meta(iface, ip, 128, u32::MAX, u32::MAX);
    }

    pub fn add_v6_addr_meta(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
    ) {
        let mut g = self.v6_addrs.lock();
        let addrs = g.entry(iface).or_default();
        let row = Ipv6IfaceAddr {
            addr: ip,
            prefixlen,
            preferred,
            valid,
        };
        match addrs.iter().position(|a| a.addr == ip) {
            Some(i) => addrs[i] = row,
            None => addrs.push(row),
        }
    }

    pub fn v6_addr_snapshot(&self) -> Vec<(NetIfaceId, Ipv6IfaceAddr)> {
        let mut out = Vec::new();
        for (iface, addrs) in self.v6_addrs.lock().iter() {
            for addr in addrs {
                out.push((*iface, *addr));
            }
        }
        out
    }

    pub fn bind_udp6(&self, bind_ip: Ipv6Addr, port: u16) -> NetResult<()> {
        self.bind_udp6_with_iface(bind_ip, port, None)
    }

    pub fn bind_udp6_with_iface(
        &self,
        bind_ip: Ipv6Addr,
        port: u16,
        iface: Option<NetIfaceId>,
    ) -> NetResult<()> {
        let mut g = self.udp6_map().lock();
        if g.contains_key(&port) {
            return Err(NetError::Eaddrinuse);
        }
        let q = Arc::new(Udp6RxQueue::new(bind_ip, port));
        q.bound_ifindex
            .store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
        g.insert(port, q);
        Ok(())
    }

    pub fn set_udp6_bound_iface(&self, port: u16, iface: Option<NetIfaceId>) -> bool {
        if let Some(q) = self.udp6_map().lock().get(&port) {
            q.bound_ifindex.store(
                iface.map(|i| i.raw()).unwrap_or(0),
                core::sync::atomic::Ordering::Release,
            );
            true
        } else {
            false
        }
    }

    pub fn recv_udp6(&self, port: u16) -> Option<(Ipv6Addr, u16, Vec<u8>)> {
        self.recv_udp6_opts(port, false)
    }

    pub fn recv_udp6_opts(
        &self,
        port: u16,
        peek: bool,
    ) -> Option<(Ipv6Addr, u16, Vec<u8>)> {
        let q = { self.udp6_map().lock().get(&port)?.clone() };
        let mut g = q.q.lock();
        if peek { g.front().cloned() } else { g.pop_front() }
    }

    pub fn udp6_queue_arc(&self, port: u16) -> Option<Arc<Udp6RxQueue>> {
        self.udp6_map().lock().get(&port).cloned()
    }

    pub fn unbind_udp6(&self, port: u16) {
        self.udp6_map().lock().remove(&port);
    }

    pub fn send_udp6_to(
        &self,
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> NetResult<()> {
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
        if !nf_output(&p, NFPROTO_IPV6) {
            return Ok(());
        }
        iface.xmit(p)
    }
}

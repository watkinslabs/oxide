use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::addr::IpProto;
use crate::icmp::{self, time_exceeded_code, unreach_code};
use crate::ipv4::{ip_checksum, push_ipv4_header, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{
    nf_hook_eval, nf_output, NFPROTO_IPV4, NF_INET_FORWARD, NF_INET_POST_ROUTING,
};
use crate::pkt::Pkt;
use crate::stack::NetStack;

impl NetStack {
    /// True when this IPv4 destination belongs to the host. # C: O(N addrs)
    pub(crate) fn ipv4_dst_is_local(&self, dst: Ipv4Addr) -> bool {
        if dst.is_loopback() || dst.is_broadcast() || dst.is_multicast() {
            return true;
        }
        crate::iface_addr::snapshot_ns(crate::netdev::current_net_ns())
            .iter()
            .any(|row| row.addr == dst)
    }

    fn ipv4_iface_addr(&self, iface: NetIfaceId) -> Option<Ipv4Addr> {
        crate::iface_addr::primary(crate::netdev::current_net_ns(), iface).map(|(addr, _)| addr)
    }

    fn should_emit_icmp_error(&self, l3: &[u8]) -> bool {
        if l3.len() < IPV4_HDR_LEN { return false; }
        if l3[9] != IpProto::Icmp as u8 { return true; }
        let total = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        if total < IPV4_HDR_LEN + icmp::ICMP_HDR_LEN || total > l3.len() { return false; }
        !matches!(l3[IPV4_HDR_LEN], icmp::ICMP_TYPE_DEST_UNREACH | icmp::ICMP_TYPE_TIME_EXC)
    }

    fn send_ipv4_forward_error(
        &self,
        ingress: NetIfaceId,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        typ: u8,
        code: u8,
        invoking: &[u8],
    ) -> NetResult<()> {
        if !self.should_emit_icmp_error(invoking) { return Ok(()); }
        let body = match icmp::build_ipv4_error(typ, code, invoking) {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        let dev = self.ifaces.lookup(ingress).ok_or(NetError::Enetunreach)?;
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, IPV4_HDR_LEN + body.len());
        p.put(body.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(&body);
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        push_ipv4_header(&mut p, src, dst, IpProto::Icmp, id).map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(ingress);
        if nf_output(&p, NFPROTO_IPV4) { dev.xmit(p)?; }
        Ok(())
    }

    /// Forward one IPv4 packet after PRE_ROUTING has accepted it. # C: O(N routes + len)
    pub(crate) fn forward_ipv4(&self, ingress: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if !crate::forwarding::ipv4_enabled() { return Ok(()); }
        if l3.len() < IPV4_HDR_LEN { return Ok(()); }
        let src = Ipv4Addr::from_u32(u32::from_be_bytes([l3[12], l3[13], l3[14], l3[15]]));
        let dst = Ipv4Addr::from_u32(u32::from_be_bytes([l3[16], l3[17], l3[18], l3[19]]));
        let error_src = self.ipv4_iface_addr(ingress).unwrap_or(dst);
        if l3[8] <= 1 {
            return self.send_ipv4_forward_error(
                ingress, error_src, src, icmp::ICMP_TYPE_TIME_EXC, time_exceeded_code::TTL, l3,
            );
        }
        let route = match self.routes.lookup(dst) {
            Some(r) => r,
            None => {
                return self.send_ipv4_forward_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH, unreach_code::NET, l3,
                );
            }
        };
        let dev = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let total = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        if total < IPV4_HDR_LEN || total > l3.len() { return Err(NetError::Einval); }
        let mut p = Pkt::with_capacity(crate::pkt::DEFAULT_HEADROOM, crate::pkt::DEFAULT_HEADROOM + total);
        p.put(total).map_err(|_| NetError::Enobufs)?.copy_from_slice(&l3[..total]);
        {
            let b = p.data_mut();
            b[8] -= 1;
            b[10] = 0;
            b[11] = 0;
            let csum = ip_checksum(&b[..IPV4_HDR_LEN]);
            b[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(route.iface);
        if nf_hook_eval(NF_INET_FORWARD, p.data(), NFPROTO_IPV4) == 0 { return Ok(()); }
        if nf_hook_eval(NF_INET_POST_ROUTING, p.data(), NFPROTO_IPV4) == 0 { return Ok(()); }
        dev.xmit(p)
    }
}

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{
    nf_hook_eval, NFPROTO_IPV4, NF_INET_FORWARD, NF_INET_POST_ROUTING,
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

    /// Forward one IPv4 packet after PRE_ROUTING has accepted it. # C: O(N routes + len)
    pub(crate) fn forward_ipv4(&self, _ingress: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if !crate::forwarding::ipv4_enabled() { return Ok(()); }
        if l3.len() < IPV4_HDR_LEN || l3[8] <= 1 { return Ok(()); }
        let dst = Ipv4Addr::from_u32(u32::from_be_bytes([l3[16], l3[17], l3[18], l3[19]]));
        let route = match self.routes.lookup(dst) {
            Some(r) => r,
            None => return Ok(()),
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

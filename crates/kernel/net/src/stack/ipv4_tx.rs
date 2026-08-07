// IPv4 L4 transmit and fragment accounting. Receive demux stays in `ipv4`.

use super::*;

impl NetStack {
    /// Emit one IPv4 L4 payload carrying a compiled header option area. `dst`
    /// is the FINAL destination; a compiled source route puts its first hop on
    /// the wire and the caller must already have routed to that hop.
    /// # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_with_policy(&self, iface_id: NetIfaceId,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16, mtu: usize, df: bool,
        may_fragment: bool, owner: Option<&crate::SocketOwner>,
        opts: Option<&crate::ipv4_options::Compiled>)
        -> NetResult<crate::cgroup_bpf::EgressVerdict>
    {
        let stamp = crate::ipv4_options::timestamp();
        let hlen = crate::ipv4_options::header_len(opts);
        let total = hlen + l4.len();
        let flags = if df { crate::ipv4::IPV4_FLAG_DONT_FRAGMENT } else { 0 };
        let mut header = crate::ipv4_options::Header {
            src, dst, proto: proto as u8, tos, ttl, id, flags_frag: flags,
        };
        let mut full = Pkt::with_capacity(hlen, total + hlen);
        full.put(l4.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(l4);
        let slot = full.push(hlen).map_err(|_| NetError::Enobufs)?;
        crate::ipv4_options::write_header(slot, &header, opts, l4.len(), stamp);
        full.proto = crate::addr::eth_p::IPV4;
        full.iface = Some(iface_id);
        full.next_hop = Some(crate::pkt::TxNextHop::V4(next_hop));
        let net_ns = owner.map_or_else(crate::netdev::current_net_ns, crate::SocketOwner::net_ns);
        crate::mib::bump(net_ns, crate::mib::Mib::IpOutRequests);
        if !crate::netfilter_hook::nf_output_in(net_ns, &full, NFPROTO_IPV4) {
            return Ok(crate::cgroup_bpf::EgressVerdict::Allow);
        }
        let verdict = if let Some(owner) = owner {
            crate::cgroup_bpf::egress(owner, full.data(), crate::addr::eth_p::IPV4, iface_id)?
        } else { crate::cgroup_bpf::EgressVerdict::Allow };
        if total <= mtu { iface.xmit(full)?; return Ok(verdict); }
        if !may_fragment {
            crate::mib::bump(net_ns, crate::mib::Mib::IpFragFails);
            return Err(NetError::Emsgsize);
        }
        let max_payload = mtu.saturating_sub(hlen) & !7usize;
        if max_payload == 0 {
            crate::mib::bump(net_ns, crate::mib::Mib::IpFragFails);
            return Err(NetError::Emsgsize);
        }
        let later = opts.map(crate::ipv4_options::fragmented);
        let mut off = 0usize;
        while off < l4.len() {
            let take = ::core::cmp::min(max_payload, l4.len() - off);
            let more = off + take < l4.len();
            let frag_off_units = (off / 8) as u16;
            header.flags_frag = if more { crate::ipv4::IPV4_FLAG_MORE_FRAGMENTS } else { 0 } | frag_off_units;
            let opts = if off == 0 { opts } else { later.as_ref() };
            let total = hlen + take;
            let mut p = Pkt::with_capacity(hlen, total + hlen);
            let payload = match p.put(take) {
                Ok(payload) => payload,
                Err(_) => { crate::mib::bump(net_ns, crate::mib::Mib::IpFragFails); return Err(NetError::Enobufs); }
            };
            payload.copy_from_slice(&l4[off..off + take]);
            let slot = match p.push(hlen) {
                Ok(slot) => slot,
                Err(_) => { crate::mib::bump(net_ns, crate::mib::Mib::IpFragFails); return Err(NetError::Enobufs); }
            };
            crate::ipv4_options::write_header(slot, &header, opts, take, stamp);
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            p.next_hop = Some(crate::pkt::TxNextHop::V4(next_hop));
            if let Err(error) = iface.xmit(p) {
                crate::mib::bump(net_ns, crate::mib::Mib::IpFragFails);
                return Err(error);
            }
            crate::mib::bump(net_ns, crate::mib::Mib::IpFragCreates);
            off += take;
        }
        crate::mib::bump(net_ns, crate::mib::Mib::IpFragOks);
        Ok(verdict)
    }
}

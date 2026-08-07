use super::{Raw4Datagram, Raw4Endpoint};
use crate::addr::{eth_p, Ipv4Addr, NetIfaceId};
use crate::bpf_filter::FilterContext;
use crate::ipv4::Ipv4Hdr;
use crate::stack::NetStack;

impl NetStack {
    /// Reassemble when required and clone one full IPv4 packet to every match. # C: O(S * packet)
    pub(crate) fn deliver_raw4(&self, net_ns: u64, iface: NetIfaceId,
                               packet: &[u8], hdr: Ipv4Hdr, now_ns: u64,
                               opts: &crate::ipv4_options::Compiled) -> bool {
        let fragmented = hdr.flags_frag & 0x3fff != 0;
        let assembled;
        let full = if fragmented {
            let Some(value) = self.inet_tables(net_ns).raw4.reassembly.push(now_ns, packet, hdr)
                else { return false };
            assembled = value;
            &assembled[..]
        } else {
            let total = hdr.total_len as usize;
            if packet.len() < total { return false; }
            &packet[..total]
        };
        let Ok(normalized) = Ipv4Hdr::parse(full) else { return false; };
        let Some(table) = self.try_inet_tables(net_ns) else { return false; };
        let endpoints = table.raw4.endpoints(normalized.proto);
        if endpoints.is_empty() { return false; }
        let hatype = self.ifaces.lookup_in_ns(iface, net_ns)
            .map_or(0, |dev| dev.hardware_type());
        let mut delivered = false;
        for endpoint in endpoints {
            if !raw4_matches(&endpoint, iface, normalized.src, normalized.dst) { continue; }
            if normalized.proto == crate::addr::IpProto::Icmp as u8 {
                let Some(typ) = full.get(normalized.ihl_bytes()) else { continue };
                if !endpoint.accepts_icmp_type(*typ) { continue; }
            }
            if !crate::cgroup_bpf::ingress(
                &endpoint.owner, full, eth_p::IPV4, iface,
            ) { continue; }
            let verdict = endpoint.bpf_filter.verdict_with_context(FilterContext {
                packet: full,
                protocol: eth_p::IPV4,
                ifindex: Some(iface.raw()),
                pay_offset: normalized.ihl_bytes() as u32,
                hatype,
            });
            if verdict == 0 { continue; }
            let keep = (verdict as usize).min(full.len());
            delivered |= endpoint.enqueue(Raw4Datagram {
                packet: full[..keep].to_vec(),
                source: normalized.src,
                destination: normalized.dst,
                iface,
                ttl: normalized.ttl,
                options: opts.clone(),
            });
        }
        delivered
    }
}

fn raw4_matches(endpoint: &Raw4Endpoint, iface: NetIfaceId, src: Ipv4Addr,
                dst: Ipv4Addr) -> bool {
    let state = endpoint.snapshot();
    if !state.accepting { return false; }
    if state.bound_iface.is_some_and(|bound| bound != iface) { return false; }
    if state.remote.is_some_and(|peer| peer != src) { return false; }
    if !state.local.is_unspecified() && state.local != dst { return false; }
    if dst.is_multicast() && !endpoint.mcast.accept_v4(iface, dst, src) { return false; }
    true
}

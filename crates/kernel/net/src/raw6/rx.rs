use crate::addr::{eth_p, Ipv6Addr, NetIfaceId};
use crate::bpf_filter::FilterContext;

use super::matching::{tuple_matches, MatchInput};
use super::types::{Raw6Address, Raw6Datagram, Raw6Endpoint, Raw6RxMeta};

/// Stack-owned upper-layer IPv6 packet offered to one raw endpoint.
pub struct Raw6RxPacket<'a> {
    pub net_ns: u64,
    pub protocol: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub iface: NetIfaceId,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hatype: u16,
    pub payload: &'a [u8],
    pub packet: &'a [u8],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Raw6RxDisposition { NoMatch, PolicyDrop, QueueFull, Queued }

impl Raw6Endpoint {
    /// Match, filter, truncate, and publish one upper-layer packet. # C: O(payload)
    pub fn receive(&self, packet: Raw6RxPacket<'_>) -> Raw6RxDisposition {
        let mut state = self.state.lock();
        let tuple = MatchInput {
            net_ns: packet.net_ns, protocol: packet.protocol, src: packet.src,
            dst: packet.dst, iface: packet.iface,
        };
        if !tuple_matches(self.net_ns(), self.protocol(), &state, &tuple) {
            return Raw6RxDisposition::NoMatch;
        }
        if packet.dst.is_multicast()
            && !self.mcast.accept_v6(packet.iface, packet.dst, packet.src)
        {
            return Raw6RxDisposition::PolicyDrop;
        }
        if !crate::cgroup_bpf::ingress(
            &self.owner, packet.packet, eth_p::IPV6, packet.iface,
        ) { return Raw6RxDisposition::PolicyDrop; }
        if self.protocol() == crate::icmpv6::IPPROTO_ICMPV6 {
            let Some(typ) = packet.payload.first() else { return Raw6RxDisposition::PolicyDrop };
            if !state.icmp_filter.accepts(*typ) { return Raw6RxDisposition::PolicyDrop; }
        }
        let verdict = self.bpf_filter.verdict_with_context(FilterContext {
            packet: packet.payload, protocol: eth_p::IPV6,
            ifindex: Some(packet.iface.raw()), pay_offset: 0, hatype: packet.hatype,
        });
        if verdict == 0 { return Raw6RxDisposition::PolicyDrop; }
        let keep = packet.payload.len().min(verdict as usize);
        if state.queued_bytes.saturating_add(keep) > state.rcvbuf {
            return Raw6RxDisposition::QueueFull;
        }
        let scope_id = if packet.src.is_link_local() { packet.iface.raw() } else { 0 };
        state.datagrams.push_back(Raw6Datagram {
            payload: packet.payload[..keep].to_vec(),
            meta: Raw6RxMeta {
                source: Raw6Address::new(packet.src, scope_id), source_port: 0,
                destination: packet.dst, iface: packet.iface, hop_limit: packet.hop_limit,
                traffic_class: packet.traffic_class, flow_label: packet.flow_label,
            },
        });
        state.queued_bytes += keep;
        drop(state);
        self.notify_receive();
        Raw6RxDisposition::Queued
    }
}

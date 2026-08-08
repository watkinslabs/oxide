// The IPv6 UDP receive arm, split out of `rx` so the protocol switch — the
// path that continues into transmit — does not carry this arm's locals.

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::stack::NetStack;

use super::rx::RxAncillary;

impl NetStack {
    /// UDP receive demultiplex for one IPv6 datagram. The reference stack
    /// keeps this arm out of line for the same reason: the header parse, the
    /// endpoint vector and the per-socket filter context were all locals of
    /// the protocol switch, so the TCP arm — the one that continues into
    /// transmit — carried them without ever touching them.
    /// # C: O(N endpoints * payload)
    #[inline(never)]
    pub(super) fn deliver_rx_udp6(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr, dst: Ipv6Addr,
        hop_limit: u8, traffic_class: u8, ancillary: &RxAncillary, payload: &[u8],
        packet: &[u8])
    {
        let udp = match crate::udp::parse_v6(payload, src, dst) {
            Ok(h) => h,
            Err(_) => {
                crate::mib6::bump_udp(net_ns, crate::mib6::Udp6Mib::InErrors);
                return;
            }
        };
        // Reuseport selection classifies the datagram body, so resolve it
        // before the demux rather than per selected endpoint.
        let datagram_body = payload
            .get(crate::udp::UDP_HDR_LEN..udp.length as usize).unwrap_or(&[]);
        let endpoints = self.udp6_demux_in(net_ns, src, udp.src_port, dst, udp.dst_port, iface,
            datagram_body);
        if endpoints.is_empty() && !dst.is_multicast() {
            crate::mib6::bump_udp(net_ns, crate::mib6::Udp6Mib::NoPorts);
        }
        let gro_offered = crate::udp_gro::device_offers_gro(
            self.ifaces.lookup_in_ns(iface, net_ns).map_or(0, |dev| dev.hardware_type()));
        for q in endpoints {
            // A zero checksum reaches only an endpoint that opted into
            // accepting one; every other socket drops the datagram as a
            // checksum error rather than queueing it.
            if udp.checksum == 0
                && q.no_check6_rx.load(core::sync::atomic::Ordering::Acquire) == 0
            { continue; }
            if !crate::cgroup_bpf::ingress(
                &q.owner, packet, crate::addr::eth_p::IPV6, iface,
            ) { continue; }
            let packet = &payload[..udp.length as usize];
            let body = &packet[crate::udp::UDP_HDR_LEN..];
            let Some(keep) = crate::bpf_filter::retained_payload_len(
                q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                    packet, protocol: crate::addr::eth_p::IPV6,
                    ifindex: Some(iface.raw()),
                    pay_offset: crate::udp::UDP_HDR_LEN as u32,
                    hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                        .map_or(0, |dev| dev.hardware_type()),
                }), body.len(),
            ) else { continue; };
            if q.enqueue_gro(crate::stack_ipv6::Udp6Datagram {
                src, sport: udp.src_port, dst, dport: udp.dst_port, iface, hop_limit,
                traffic_class,
                flowinfo: crate::cmsg::flowinfo(traffic_class, ancillary.flow_label),
                ext_headers: ancillary.ext_headers.clone(),
                frag_max: ancillary.frag_max,
                // IP_CHECKSUM is an IPv4-level option; a native IPv6 receive
                // publishes the IPv6 ancillary level, which has no counterpart.
                checksum: None,
                payload: body[..keep].to_vec(),
            }, udp.checksum == 0, gro_offered) {
                crate::mib6::bump_udp(net_ns, crate::mib6::Udp6Mib::InDatagrams);
            } else {
                crate::mib6::bump_udp(net_ns, crate::mib6::Udp6Mib::RcvbufErrors);
                crate::mib6::bump_udp(net_ns, crate::mib6::Udp6Mib::InErrors);
            }
        }
    }
}

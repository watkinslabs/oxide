// Reply demultiplexing for ICMP datagram endpoints. A reply is steered solely
// by its echo identifier, which the kernel allocated and stamped on the probe —
// so a reply reaches exactly the endpoint that asked for it and no other.
// The delivered record starts at the ICMP message; the network header is the
// kernel's and is never handed to the caller.

use crate::addr::{eth_p, IpAddr, Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::bpf_filter::FilterContext;
use crate::ipv4::Ipv4Hdr;
use crate::stack::NetStack;

use super::ident::ReplyTuple;
use super::validate::{is_reply, PingFamily};

/// The IPv6 reply metadata the delivered record retains.
pub struct Reply6<'a> {
    pub net_ns: u64,
    pub iface: NetIfaceId,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hatype: u16,
    pub message: &'a [u8],
}

impl NetStack {
    /// Steer one IPv4 echo reply to the endpoint owning its identifier. # C: O(N)
    pub fn deliver_ping_v4(&self, net_ns: u64, iface: NetIfaceId, hdr: &Ipv4Hdr,
                           message: &[u8], packet: &[u8], hatype: u16) -> bool {
        if message.len() < super::validate::HEADER_LEN { return false; }
        if !is_reply(PingFamily::V4, message[0]) { return false; }
        let Some(table) = self.ping_table(net_ns) else { return false };
        let tuple = ReplyTuple {
            ident: super::validate::identifier(message),
            iface,
            destination: IpAddr::V4(hdr.dst),
        };
        let Some(endpoint) = table.lookup_v4(tuple) else { return false };
        if !crate::cgroup_bpf::ingress(&endpoint.owner, packet, eth_p::IPV4, iface) {
            return false;
        }
        let verdict = endpoint.bpf_filter.verdict_with_context(FilterContext {
            packet: message, protocol: eth_p::IPV4, ifindex: Some(iface.raw()),
            pay_offset: 0, hatype,
        });
        if verdict == 0 { return false; }
        let keep = (verdict as usize).min(message.len());
        endpoint.enqueue(crate::raw4::Raw4Datagram {
            packet: message[..keep].to_vec(),
            source: hdr.src,
            destination: hdr.dst,
            iface,
            ttl: hdr.ttl,
        })
    }

    /// Steer one IPv6 echo reply to the endpoint owning its identifier. # C: O(N)
    pub fn deliver_ping_v6(&self, reply: Reply6<'_>) -> bool {
        if reply.message.len() < super::validate::HEADER_LEN { return false; }
        if !is_reply(PingFamily::V6, reply.message[0]) { return false; }
        let Some(table) = self.ping_table(reply.net_ns) else { return false };
        let tuple = ReplyTuple {
            ident: super::validate::identifier(reply.message),
            iface: reply.iface,
            destination: IpAddr::V6(reply.dst),
        };
        let Some(endpoint) = table.lookup_v6(tuple) else { return false };
        if !crate::cgroup_bpf::ingress(&endpoint.owner, reply.message, eth_p::IPV6, reply.iface) {
            return false;
        }
        let verdict = endpoint.bpf_filter.verdict_with_context(FilterContext {
            packet: reply.message, protocol: eth_p::IPV6, ifindex: Some(reply.iface.raw()),
            pay_offset: 0, hatype: reply.hatype,
        });
        if verdict == 0 { return false; }
        let keep = (verdict as usize).min(reply.message.len());
        let scope_id = if reply.src.is_link_local() { reply.iface.raw() } else { 0 };
        endpoint.enqueue(crate::raw6::Raw6Datagram {
            payload: reply.message[..keep].to_vec(),
            meta: crate::raw6::Raw6RxMeta {
                source: crate::raw6::Raw6Address::new(reply.src, scope_id),
                source_port: 0,
                destination: reply.dst,
                iface: reply.iface,
                hop_limit: reply.hop_limit,
                traffic_class: reply.traffic_class,
                flow_label: reply.flow_label,
            },
        })
    }

    /// Report one ICMP error that quotes an echo probe this kernel originated.
    /// The quoted probe carries the identifier, so the error reaches the same
    /// endpoint the reply would have. # C: O(N)
    pub fn report_ping_error_v4(&self, net_ns: u64, iface: NetIfaceId, local: Ipv4Addr,
                                quoted: &[u8], entry: crate::SocketErrorEntry, hard: bool,
                                quoted_ip: &[u8]) -> bool {
        if quoted.len() < super::validate::HEADER_LEN { return false; }
        if !super::validate::supported(PingFamily::V4, quoted[0], quoted[1]) { return false; }
        let Some(table) = self.ping_table(net_ns) else { return false };
        let tuple = ReplyTuple {
            ident: super::validate::identifier(quoted), iface, destination: IpAddr::V4(local),
        };
        let Some(endpoint) = table.lookup_v4(tuple) else { return false };
        endpoint.publish_quoted_error(entry, hard, quoted_ip)
    }

    /// Report one ICMPv6 error that quotes an echo probe this kernel
    /// originated. # C: O(N)
    pub fn report_ping_error_v6(&self, net_ns: u64, iface: NetIfaceId, local: Ipv6Addr,
                                quoted: &[u8], entry: crate::SocketErrorEntry, hard: bool) -> bool {
        if quoted.len() < super::validate::HEADER_LEN { return false; }
        if !super::validate::supported(PingFamily::V6, quoted[0], quoted[1]) { return false; }
        let Some(table) = self.ping_table(net_ns) else { return false };
        let tuple = ReplyTuple {
            ident: super::validate::identifier(quoted), iface, destination: IpAddr::V6(local),
        };
        let Some(endpoint) = table.lookup_v6(tuple) else { return false };
        endpoint.publish_error(entry, hard)
    }
}

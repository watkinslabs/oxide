//! Packet-to-conntrack binding. The binding is made once at the Linux
//! conntrack hook priority and carried by `Pkt` through the remaining hooks.

use conntrack::core::{L4, Packet, Track};
use conntrack::proto::tcp_window::TcpSeg;
use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
use conntrack::uapi::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
                      NFPROTO_IPV4, NFPROTO_IPV6};

use crate::pkt::Pkt;

impl super::NetStack {
    /// Enter conntrack once for a packet entering the PRE_ROUTING/LOCAL_OUT
    /// path. A pending entry is confirmed only after later hooks accept it.
    pub(crate) fn track_conntrack(&self, namespace: u64, p: &mut Pkt, family: u8) -> bool {
        if p.conntrack_state().is_some() { return true; }
        let Some((tuple, l4)) = packet_parts(p.data(), family) else {
            return true;
        };
        let table = self.conntrack_in(namespace);
        let tracked = table.track(&Packet { tuple, l4, len: p.len() as u64 }, p.timestamp_ns / 1_000_000_000);
        match tracked {
            Track::Ok { conn, dir, ctinfo, .. } => {
                p.set_conntrack_state(table, Some(conn), ctinfo, dir);
                true
            }
            Track::Untracked => {
                p.set_conntrack_state(table, None, conntrack::uapi::IP_CT_UNTRACKED, 0);
                true
            }
            // Conntrack reports INVALID to the hook; it does not itself
            // impose the nftables verdict. A later ct-state rule may drop it,
            // while an unrelated rule is allowed to accept it.
            Track::Invalid | Track::Repeat => {
                p.set_conntrack_state(table, None, 0, 0);
                true
            }
        }
    }
}

fn packet_parts<'a>(pkt: &'a [u8], family: u8) -> Option<(Tuple, L4<'a>)> {
    let (src, dst, proto, off) = match family {
        NFPROTO_IPV4 => {
            if pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if ihl < 20 || ihl > pkt.len() { return None; }
            (InetAddr::v4(pkt[12..16].try_into().ok()?),
             InetAddr::v4(pkt[16..20].try_into().ok()?), pkt[9], ihl)
        }
        NFPROTO_IPV6 => {
            if pkt.len() < 40 || pkt[0] >> 4 != 6 { return None; }
            let src = InetAddr::v6(pkt[8..24].try_into().ok()?);
            let dst = InetAddr::v6(pkt[24..40].try_into().ok()?);
            // The IPv6 fixed header's next-header byte names the first
            // extension, not necessarily the transport protocol. Conntrack
            // must use the same extension walk as delivery; otherwise an
            // nft ct rule sees every HBH/routing packet as a generic flow.
            let payload = &pkt[40..];
            let (proto, transport) = match crate::ipv6_ext::walk(pkt[6], payload).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, payload } =>
                    (next_header, pkt.len() - payload.len()),
                crate::ipv6_ext::ExtWalk::Fragment { next_header, offset, payload, .. } => {
                    // Non-initial fragments carry no usable L4 tuple. Keep
                    // them as generic fragment flows; the first fragment is
                    // still parsed at the transport offset.
                    if offset != 0 { (next_header, pkt.len()) }
                    else { (next_header, pkt.len() - payload.len()) }
                }
            };
            (src, dst, proto, transport)
        }
        _ => return None,
    };
    if off > pkt.len() { return None; }
    let (src_proto, dst_proto, l4) = match proto {
        IPPROTO_TCP => {
            let tcp = pkt.get(off..)?;
            if tcp.len() < 20 { return None; }
            let hdr_len = ((tcp[12] >> 4) as usize) * 4;
            if hdr_len < 20 || hdr_len > tcp.len() { return None; }
            let seg = TcpSeg { seq: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
                ack: u32::from_be_bytes(tcp[8..12].try_into().ok()?),
                win: u16::from_be_bytes(tcp[14..16].try_into().ok()?), flags: tcp[13],
                datalen: tcp.len().saturating_sub(hdr_len) as u32,
                options: &tcp[20..hdr_len] };
            (ProtoPart::port(u16::from_be_bytes(tcp[0..2].try_into().ok()?)),
             ProtoPart::port(u16::from_be_bytes(tcp[2..4].try_into().ok()?)), L4::Tcp(seg))
        }
        IPPROTO_UDP => {
            let udp = pkt.get(off..off.checked_add(8)?)?;
            (ProtoPart::port(u16::from_be_bytes(udp[0..2].try_into().ok()?)),
             ProtoPart::port(u16::from_be_bytes(udp[2..4].try_into().ok()?)), L4::Udp)
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let icmp = pkt.get(off..off.checked_add(8)?)?;
            (ProtoPart::icmp(u16::from_be_bytes(icmp[4..6].try_into().ok()?),
                             icmp[0], icmp[1]),
             ProtoPart::icmp(0, icmp[0], icmp[1]), L4::Icmp)
        }
        _ => (ProtoPart::default(), ProtoPart::default(), L4::Generic),
    };
    Some((Tuple { src: TupleEnd { addr: src, proto: src_proto },
                  dst: TupleEnd { addr: dst, proto: dst_proto },
                  l3num: family, protonum: proto, zone: 0 }, l4))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    #[test]
    fn tcp_packet_attaches_namespace_owned_conntrack_entry() {
        let stack = super::super::NetStack::new();
        let mut pkt = Pkt::from_owned(vec![
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, IPPROTO_TCP, 0, 0,
            10, 0, 0, 1, 10, 0, 0, 2,
            0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0,
            0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ]);
        assert!(stack.track_conntrack(17, &mut pkt, NFPROTO_IPV4));
        let (_, conn, info, dir) = pkt.conntrack_state().expect("conntrack attached");
        assert!(conn.is_some());
        assert_eq!((info, dir), (conntrack::uapi::IP_CT_NEW, 0));
    }

    #[test]
    fn ipv6_conntrack_skips_extension_headers_before_udp() {
        let mut packet = vec![0u8; 40 + 8 + 8];
        packet[0] = 0x60;
        packet[6] = crate::ipv6_ext::NH_HOP_BY_HOP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = IPPROTO_UDP;
        packet[41] = 0; // one eight-byte hop-by-hop header
        packet[48..50].copy_from_slice(&1234u16.to_be_bytes());
        packet[50..52].copy_from_slice(&5353u16.to_be_bytes());
        let (tuple, _) = packet_parts(&packet, NFPROTO_IPV6).expect("IPv6 tuple");
        assert_eq!(tuple.protonum, IPPROTO_UDP);
        assert_eq!(tuple.src.proto, ProtoPart::port(1234));
        assert_eq!(tuple.dst.proto, ProtoPart::port(5353));
    }
}

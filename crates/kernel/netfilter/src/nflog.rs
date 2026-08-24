//! NFLOG packet notifications, matching `nfnetlink_log`'s packet message
//! shape. Configuration batching is deliberately separate from packet
//! delivery; a subscribed NETLINK_NETFILTER socket is the live receiver.

use alloc::{string::String, vec, vec::Vec};

use net::pkt::Pkt;
use netlink::{nlmsg_align, Nlmsghdr};

use crate::Nfgenmsg;

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 1;
const NFULA_PACKET_HDR: u16 = 1;
const NFULA_MARK: u16 = 2;
const NFULA_PAYLOAD: u16 = 10;
const NFULA_PREFIX: u16 = 11;
const NFULA_L2HDR: u16 = 17;

fn attr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len() + (nlmsg_align(len) - len), 0);
}

/// Emit one NFLOG packet notification. The callback returns true even when no
/// userspace listener is currently subscribed: Linux's logger consumes the
/// packet after resolving its group instance, and an empty receiver set is not
/// a packet verdict.
pub fn log_packet(namespace: u64, group: u16, p: &Pkt, family: u8, hook: u32,
                  prefix: &str, snaplen: u32, _flags: u32) -> bool {
    let mut attrs = Vec::new();
    let mut packet_hdr = [0u8; 4];
    packet_hdr[..2].copy_from_slice(&p.proto.to_be_bytes());
    packet_hdr[2] = hook as u8;
    attr(&mut attrs, NFULA_PACKET_HDR, &packet_hdr);
    attr(&mut attrs, NFULA_MARK, &p.tx.mark.to_be_bytes());
    if !prefix.is_empty() {
        let mut text = String::from(prefix).into_bytes();
        text.push(0);
        attr(&mut attrs, NFULA_PREFIX, &text);
    }
    if let Some(frame) = p.mac_frame() { attr(&mut attrs, NFULA_L2HDR, frame); }
    let payload = if snaplen == 0 { p.data() } else { &p.data()[..p.len().min(snaplen as usize)] };
    attr(&mut attrs, NFULA_PAYLOAD, payload);

    let body_len = Nlmsghdr::SIZE + Nfgenmsg::SIZE + attrs.len();
    let mut msg = vec![0u8; body_len];
    Nlmsghdr {
        nlmsg_len: body_len as u32,
        nlmsg_type: (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET,
        nlmsg_flags: 0, nlmsg_seq: 0, nlmsg_pid: 0,
    }.write_to(&mut msg[..Nlmsghdr::SIZE]);
    Nfgenmsg { nfgen_family: family, version: 0, res_id: group }.write_to(
        &mut msg[Nlmsghdr::SIZE..Nlmsghdr::SIZE + Nfgenmsg::SIZE]);
    msg[Nlmsghdr::SIZE + Nfgenmsg::SIZE..].copy_from_slice(&attrs);
    let _ = netlink::netfilter_multicast_in(namespace, group as u32, &msg);
    true
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::log_packet;
    use netlink::{NetlinkSocket, proto, register_netfilter_listener};

    #[test]
    fn nf_log_packet_multicasts_linux_packet_message_shape() {
        let ns = net::net_ns::initial_namespace();
        let socket = Arc::new(NetlinkSocket::new(proto::NETLINK_NETFILTER, &ns));
        socket.groups.add(7);
        register_netfilter_listener(&socket);
        let mut packet = net::pkt::Pkt::from_owned(alloc::vec![1, 2, 3, 4]);
        packet.proto = net::addr::eth_p::IPV4;
        packet.tx.mark = 0x1234;
        assert!(log_packet(ns.id().as_u64(), 7, &packet, 2, 1, "audit", 3, 0));
        let mut bytes = [0u8; 256];
        let n = socket.read(&mut bytes).expect("NFLOG datagram");
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), (4 << 8) | 1);
        assert_eq!(bytes[16], 2);
        assert!(bytes[..n].windows(5).any(|w| w == b"audit"));
    }
}

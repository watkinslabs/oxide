//! nftables synproxy packet ownership.
//!
//! The SYN proxy is a stateless front half of the TCP handshake.  A client
//! SYN receives a cookie SYN-ACK; a valid client ACK is consumed and replaced
//! with the SYN that the protected peer must see.  No socket or request queue
//! is allocated before the protected peer answers.

use super::*;
use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::netdev::NetResult;
use crate::pkt::Pkt;
use crate::tcp_hdr::{self, TcpHdr};

const DEFAULT_MSS: u16 = 536;

impl NetStack {
    /// Consume one nftables synproxy packet after emitting its handshake peer.
    /// # C: O(segment + route)
    pub(crate) fn apply_synproxy(&self, p: &mut Pkt, family: u8, configured_mss: u16,
                                 wscale: u8, flags: u32) -> Result<(), crate::netfilter_action::ApplyError> {
        let packet = p.data();
        let (src, dst, off) = match family {
            crate::netfilter_hook::NFPROTO_IPV4 => {
                if packet.len() < 20 || packet[0] >> 4 != 4 { return Err(crate::netfilter_action::ApplyError::Invalid); }
                let ihl = (packet[0] & 0x0f) as usize * 4;
                if ihl < 20 || packet.len() < ihl + 20 { return Err(crate::netfilter_action::ApplyError::Invalid); }
                (IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
                 IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])), ihl)
            }
            crate::netfilter_hook::NFPROTO_IPV6 => {
                if packet.len() < 40 { return Err(crate::netfilter_action::ApplyError::Invalid); }
                let off = match crate::ipv6_ext::walk(packet[6], &packet[40..]).ok() {
                    Some(crate::ipv6_ext::ExtWalk::Done { payload, .. })
                    | Some(crate::ipv6_ext::ExtWalk::Fragment { offset: 0, payload, .. }) =>
                        packet.len() - payload.len(),
                    _ => return Err(crate::netfilter_action::ApplyError::Invalid),
                };
                (IpAddr::V6(Ipv6Addr(packet[8..24].try_into().unwrap())),
                 IpAddr::V6(Ipv6Addr(packet[24..40].try_into().unwrap())), off)
            }
            _ => return Err(crate::netfilter_action::ApplyError::Unsupported),
        };
        let tcp = packet.get(off..).ok_or(crate::netfilter_action::ApplyError::Invalid)?;
        let hdr = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => TcpHdr::parse(tcp, s, d),
            (IpAddr::V6(s), IpAddr::V6(d)) => TcpHdr::parse_v6(tcp, s, d),
            _ => unreachable!(),
        }.map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
        if hdr.flags & tcp_hdr::flags::RST != 0 { return Ok(()); }
        let net_ns = p.iface.and_then(|iface| self.ifaces.namespace(iface)).unwrap_or(0);
        let peer_mss = tcp_hdr::parse_mss_option(tcp).unwrap_or(DEFAULT_MSS);
        let mss = if configured_mss == 0 { peer_mss } else { configured_mss.min(peer_mss) };
        let option_flags = flags;
        let now = crate::tcp_conn::ka_now_ns();
        if hdr.flags & tcp_hdr::flags::SYN != 0 && hdr.flags & tcp_hdr::flags::ACK == 0 {
            let (cookie, encoded_mss) = crate::syncookies::init_sequence(
                src, dst, hdr.src_port, hdr.dst_port, hdr.seq, now,
                matches!(src, IpAddr::V6(_)), mss);
            let options = syn_options(encoded_mss, wscale, option_flags);
            self.send_synproxy_segment(net_ns, dst, src, hdr.dst_port, hdr.src_port,
                cookie, hdr.seq.wrapping_add(1), tcp_hdr::flags::SYN | tcp_hdr::flags::ACK,
                0, &options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
            return Err(crate::netfilter_action::ApplyError::Stolen);
        }
        if hdr.flags & tcp_hdr::flags::ACK != 0 && hdr.flags & tcp_hdr::flags::SYN == 0 {
            let Some(encoded_mss) = crate::syncookies::validate(src, dst, hdr.src_port,
                hdr.dst_port, hdr.seq, hdr.ack, now, matches!(src, IpAddr::V6(_))) else {
                return Err(crate::netfilter_action::ApplyError::Invalid);
            };
            let options = syn_options(encoded_mss, wscale, option_flags);
            self.send_synproxy_segment(net_ns, src, dst, hdr.src_port, hdr.dst_port,
                hdr.seq.wrapping_sub(1), hdr.ack.wrapping_sub(1), tcp_hdr::flags::SYN,
                hdr.window, &options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
            return Err(crate::netfilter_action::ApplyError::Stolen);
        }
        Ok(())
    }

    fn send_synproxy_segment(&self, net_ns: u64, src: IpAddr, dst: IpAddr,
                             src_port: u16, dst_port: u16, seq: u32, ack: u32,
                             flags: u8, window: u16, options: &[u8], mark: u32) -> NetResult<()> {
        let mut segment = alloc::vec![0u8; 20 + options.len()];
        let mut hdr = TcpHdr { src_port, dst_port, seq, ack, data_offset: ((segment.len() / 4) as u8),
            flags, window, checksum: 0, urg_ptr: 0 };
        hdr.build_into_ip(src, dst, &mut segment);
        segment[20..].copy_from_slice(options);
        // The options are part of the checksum input, so rebuild after copying them.
        hdr.build_into_ip(src, dst, &mut segment);
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => self.send_tcp_ipv4_segment_in(
                net_ns, s, d, &segment, 0, None, crate::uapi::IP_PMTUDISC_WANT,
                None, None, mark).map(|_| ()),
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, d, None, mark)?;
                self.xmit_ipv6_l4_on_iface(iface_id, iface, next_hop, s, d,
                    crate::IpProto::Tcp, &segment)
            }
            _ => Err(crate::netdev::NetError::Einval),
        }
    }
}

fn syn_options(mss: u16, wscale: u8, flags: u32) -> alloc::vec::Vec<u8> {
    let mut options = alloc::vec::Vec::new();
    if flags & 0x01 != 0 {
        options.extend_from_slice(&[tcp_hdr::opt::MSS, 4]);
        options.extend_from_slice(&mss.to_be_bytes());
    }
    if flags & 0x02 != 0 && wscale != 0 {
        options.extend_from_slice(&[tcp_hdr::opt::NOP, tcp_hdr::opt::WSCALE, 3, wscale]);
    }
    while options.len() % 4 != 0 { options.push(tcp_hdr::opt::NOP); }
    options
}

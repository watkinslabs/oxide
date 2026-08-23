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
const OPT_MSS: u32 = 0x01;
const OPT_WSCALE: u32 = 0x02;
const OPT_SACK: u32 = 0x04;
const OPT_TIMESTAMP: u32 = 0x08;
const OPT_ECN: u32 = 0x10;

impl NetStack {
    /// Consume one nftables synproxy packet after emitting its handshake peer.
    /// # C: O(segment + route)
    pub(crate) fn apply_synproxy(&self, p: &mut Pkt, family: u8, configured_mss: u16,
        wscale: u8, flags: u32, _hook: u32)
        -> Result<(), crate::netfilter_action::ApplyError> {
        let Some((_, Some(conn), _, dir)) = p.conntrack_state_owned() else {
            // Linux's synproxy hook is a conntrack extension; without an
            // owner it has nothing to proxy and must leave the packet alone.
            return Ok(());
        };
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
        let net_ns = p.iface.and_then(|iface| self.ifaces.namespace(iface)).unwrap_or(0);
        let peer_mss = tcp_hdr::parse_mss_option(tcp).unwrap_or(DEFAULT_MSS);
        let mss = if configured_mss == 0 { peer_mss } else { configured_mss.min(peer_mss) };
        let option_flags = syn_option_flags(tcp, flags)
            | if hdr.flags & (tcp_hdr::flags::ECE | tcp_hdr::flags::CWR)
                == (tcp_hdr::flags::ECE | tcp_hdr::flags::CWR) { OPT_ECN } else { 0 };
        let tcp_state = match &*conn.proto.lock() {
            ::conntrack::ProtoState::Tcp(track) => track.state,
            _ => return Ok(()),
        };
        if hdr.flags & tcp_hdr::flags::RST != 0 {
            if dir == ::conntrack::uapi::IP_CT_DIR_REPLY
                && tcp_state == ::conntrack::proto::tcp_state::TCP_CONNTRACK_CLOSE
            {
                if let Some(synproxy) = *conn.synproxy.lock() {
                    conn.seqadj_init(dir, synproxy.isn.wrapping_sub(hdr.seq)
                        .wrapping_add(1) as i32);
                }
            }
            return Ok(());
        }
        let now = crate::tcp_conn::ka_now_ns();
        if dir == ::conntrack::uapi::IP_CT_DIR_REPLY
            && tcp_state == ::conntrack::proto::tcp_state::TCP_CONNTRACK_SYN_RECV
            && hdr.flags & (tcp_hdr::flags::SYN | tcp_hdr::flags::ACK)
                == (tcp_hdr::flags::SYN | tcp_hdr::flags::ACK) {
            let Some(mut synproxy) = *conn.synproxy.lock() else {
                return Err(crate::netfilter_action::ApplyError::Invalid);
            };
            let server_ts = crate::tcp_hdr::parse_ts_option(tcp);
            let server_wscale = crate::tcp_hdr::parse_wscale_option(tcp).unwrap_or(0);
            let client_window = match &*conn.proto.lock() {
                ::conntrack::ProtoState::Tcp(track) => track.seen[
                    ::conntrack::uapi::IP_CT_DIR_ORIGINAL as usize].td_maxwin as u16,
                _ => 0,
            };
            if let Some((tsval, _)) = server_ts {
                synproxy.tsoff = tsval.wrapping_sub(synproxy.its) as i32;
            }
            // The protected peer used a different ISN from the cookie sent
            // to the client. Conntrack translates that reply direction and
            // the opposite ACK field for every later segment.
            conn.seqadj_init(dir, synproxy.isn.wrapping_sub(hdr.seq) as i32);
            *conn.synproxy.lock() = Some(synproxy);
            // The protected peer completed its half of the handshake.  Linux
            // acknowledges it toward the peer and separately completes the
            // client's half before consuming this SYN-ACK.
            let ack_options = server_ts.map(|(tsval, tsecr)|
                syn_options(0, 0, option_flags & (OPT_TIMESTAMP | OPT_ECN), tsecr, tsval))
                .unwrap_or_default();
            let client_options = server_ts.map(|(tsval, tsecr)|
                syn_options(0, 0, option_flags & (OPT_TIMESTAMP | OPT_ECN), tsval, tsecr))
                .unwrap_or_default();
            let ecn = if option_flags & OPT_ECN != 0 {
                tcp_hdr::flags::ECE | tcp_hdr::flags::CWR
            } else { 0 };
            self.send_synproxy_segment(net_ns, dst, src, hdr.dst_port, hdr.src_port,
                hdr.ack, hdr.seq.wrapping_add(1), tcp_hdr::flags::ACK | ecn,
                client_window, &ack_options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
            self.send_synproxy_segment(net_ns, src, dst, hdr.src_port, hdr.dst_port,
                hdr.seq.wrapping_add(1), hdr.ack, tcp_hdr::flags::ACK | ecn,
                hdr.window >> server_wscale, &client_options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
            return Err(crate::netfilter_action::ApplyError::Stolen);
        }
        if dir == ::conntrack::uapi::IP_CT_DIR_ORIGINAL
            && matches!(tcp_state, ::conntrack::proto::tcp_state::TCP_CONNTRACK_CLOSE
                | ::conntrack::proto::tcp_state::TCP_CONNTRACK_SYN_SENT)
            && hdr.flags & tcp_hdr::flags::SYN != 0 && hdr.flags & tcp_hdr::flags::ACK == 0 {
            // Linux resets the extension only when a closed entry is reopened.
            // A SYN retransmission in SYN_SENT must retain the pending exchange.
            if tcp_state == ::conntrack::proto::tcp_state::TCP_CONNTRACK_CLOSE {
                conn.seqadj_init(::conntrack::uapi::IP_CT_DIR_ORIGINAL, 0);
                *conn.synproxy.lock() = None;
            }
            let (cookie, encoded_mss) = crate::syncookies::init_sequence(
                src, dst, hdr.src_port, hdr.dst_port, hdr.seq, now,
                matches!(src, IpAddr::V6(_)), mss);
            let tsval = if option_flags & OPT_TIMESTAMP != 0 {
                ((now / 1_000_000) as u32 & !0x3f)
                    | if option_flags & OPT_WSCALE != 0 { (wscale & 0x0f) as u32 } else { 0 }
                    | if option_flags & OPT_SACK != 0 { 1 << 4 } else { 0 }
                    | if option_flags & OPT_ECN != 0 { 1 << 5 } else { 0 }
            } else { 0 };
            let client_tsval = tcp_hdr::parse_ts_option(tcp).map(|(tsval, _)| tsval).unwrap_or(0);
            let options = syn_options(encoded_mss, wscale, option_flags, tsval, client_tsval);
            let ecn = if option_flags & OPT_ECN != 0 {
                tcp_hdr::flags::ECE | tcp_hdr::flags::CWR
            } else { 0 };
            self.send_synproxy_segment(net_ns, dst, src, hdr.dst_port, hdr.src_port,
                cookie, hdr.seq.wrapping_add(1), tcp_hdr::flags::SYN | tcp_hdr::flags::ACK | ecn,
                0, &options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
            return Err(crate::netfilter_action::ApplyError::Stolen);
        }
        if dir == ::conntrack::uapi::IP_CT_DIR_ORIGINAL
            && tcp_state == ::conntrack::proto::tcp_state::TCP_CONNTRACK_SYN_SENT
            && hdr.flags & tcp_hdr::flags::ACK != 0 && hdr.flags & tcp_hdr::flags::SYN == 0 {
            let Some(encoded_mss) = crate::syncookies::validate(src, dst, hdr.src_port,
                hdr.dst_port, hdr.seq, hdr.ack, now, matches!(src, IpAddr::V6(_))) else {
                return Err(crate::netfilter_action::ApplyError::Invalid);
            };
            let ack_ts = crate::tcp_hdr::parse_ts_option(tcp);
            let mut ack_options = syn_option_flags(tcp, flags) | OPT_MSS;
            if hdr.flags & (tcp_hdr::flags::ECE | tcp_hdr::flags::CWR)
                == (tcp_hdr::flags::ECE | tcp_hdr::flags::CWR) {
                ack_options |= OPT_ECN;
            }
            let ack_wscale = ack_ts.map(|(_, tsecr)| (tsecr & 0x0f) as u8)
                .or_else(|| tcp_hdr::parse_wscale_option(tcp)).unwrap_or(wscale);
            if let Some((_, tsecr)) = ack_ts {
                if tsecr & 0x0f != 0x0f { ack_options |= OPT_WSCALE; }
                if tsecr & (1 << 4) != 0 { ack_options |= OPT_SACK; }
                if tsecr & (1 << 5) != 0 { ack_options |= OPT_ECN; }
                ack_options |= OPT_TIMESTAMP;
            }
            let options = syn_options(encoded_mss, ack_wscale, ack_options,
                ack_ts.map(|(tsval, _)| tsval).unwrap_or(0),
                ack_ts.map(|(_, tsecr)| tsecr).unwrap_or(0));
            let ecn = if ack_options & OPT_ECN != 0 {
                tcp_hdr::flags::ECE | tcp_hdr::flags::CWR
            } else { 0 };
            let seq = if hdr.flags & tcp_hdr::flags::SYN != 0 {
                hdr.seq.wrapping_sub(1)
            } else {
                // Linux's keep-alive/cookie-retransmission path passes
                // SEG.SEQ + 1 to synproxy_send_server_syn, which emits
                // that value minus one.  It does not reopen the extension.
                hdr.seq
            };
            if hdr.flags & tcp_hdr::flags::SYN == 0 {
                self.send_synproxy_segment(net_ns, src, dst, hdr.src_port, hdr.dst_port,
                    seq, hdr.ack.wrapping_sub(1), tcp_hdr::flags::SYN | ecn,
                    hdr.window, &options, p.tx.mark).map_err(|_| crate::netfilter_action::ApplyError::Invalid)?;
                return Err(crate::netfilter_action::ApplyError::Stolen);
            }
            let its = ack_ts.map(|(_, tsecr)| tsecr).unwrap_or(0);
            *conn.synproxy.lock() = Some(::conntrack::entry::SynproxyState {
                isn: hdr.ack, its, tsoff: 0,
            });
            self.send_synproxy_segment(net_ns, src, dst, hdr.src_port, hdr.dst_port,
                seq, hdr.ack.wrapping_sub(1), tcp_hdr::flags::SYN | ecn,
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

fn syn_option_flags(tcp: &[u8], allowed: u32) -> u32 {
    let mut flags = 0;
    if allowed & OPT_MSS != 0 && tcp_hdr::parse_mss_option(tcp).is_some() { flags |= OPT_MSS; }
    if allowed & OPT_WSCALE != 0 && tcp_hdr::parse_wscale_option(tcp).is_some() { flags |= OPT_WSCALE; }
    if allowed & OPT_SACK != 0 && tcp_hdr::parse_sack_permitted(tcp) { flags |= OPT_SACK; }
    if allowed & OPT_TIMESTAMP != 0 && tcp_hdr::parse_ts_option(tcp).is_some() { flags |= OPT_TIMESTAMP; }
    flags
}

fn syn_options(mss: u16, wscale: u8, flags: u32, tsval: u32, tsecr: u32)
    -> alloc::vec::Vec<u8> {
    let mut options = alloc::vec::Vec::new();
    if flags & OPT_MSS != 0 {
        options.extend_from_slice(&[tcp_hdr::opt::MSS, 4]);
        options.extend_from_slice(&mss.to_be_bytes());
    }
    if flags & OPT_TIMESTAMP != 0 {
        if flags & OPT_SACK != 0 {
            options.extend_from_slice(&[tcp_hdr::opt::SACK_PERMIT, 2,
                tcp_hdr::opt::TIMESTAMP, 10]);
        } else {
            options.extend_from_slice(&[tcp_hdr::opt::NOP, tcp_hdr::opt::NOP,
                tcp_hdr::opt::TIMESTAMP, 10]);
        }
        options.extend_from_slice(&tsval.to_be_bytes());
        options.extend_from_slice(&tsecr.to_be_bytes());
    } else if flags & OPT_SACK != 0 {
        options.extend_from_slice(&[tcp_hdr::opt::NOP, tcp_hdr::opt::NOP,
            tcp_hdr::opt::SACK_PERMIT, 2]);
    }
    if flags & OPT_WSCALE != 0 {
        options.extend_from_slice(&[tcp_hdr::opt::NOP, tcp_hdr::opt::WSCALE, 3, wscale]);
    }
    while options.len() % 4 != 0 { options.push(tcp_hdr::opt::NOP); }
    options
}

fn swap_timestamp_options(options: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = options.to_vec();
    let mut i = 0usize;
    while i < out.len() {
        let kind = out[i];
        if kind == tcp_hdr::opt::END { break; }
        if kind == tcp_hdr::opt::NOP { i += 1; continue; }
        if i + 1 >= out.len() { break; }
        let len = out[i + 1] as usize;
        if len < 2 || i + len > out.len() { break; }
        if kind == tcp_hdr::opt::TIMESTAMP && len == 10 {
            let first = [out[i + 2], out[i + 3], out[i + 4], out[i + 5]];
            let second = [out[i + 6], out[i + 7], out[i + 8], out[i + 9]];
            out[i + 2..i + 6].copy_from_slice(&second);
            out[i + 6..i + 10].copy_from_slice(&first);
            break;
        }
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::{syn_options, swap_timestamp_options, OPT_SACK, OPT_TIMESTAMP};

    #[test]
    fn encodes_enabled_syn_options_and_alignment() {
        assert_eq!(syn_options(1460, 7, 0x03, 0, 0), vec![
            2, 4, 0x05, 0xb4,
            1, 3, 3, 7,
        ]);
    }

    #[test]
    fn omits_disabled_syn_options() {
        assert!(syn_options(1460, 7, 0, 0, 0).is_empty());
        assert_eq!(syn_options(1460, 0, 0x03, 0, 0), vec![2, 4, 0x05, 0xb4,
            1, 3, 3, 0]);
    }

    #[test]
    fn builds_and_swaps_timestamp_cookie_options() {
        let options = syn_options(0, 7, OPT_TIMESTAMP | OPT_SACK,
            0x1122_3344, 0x5566_7788);
        assert_eq!(&options[..], &[4, 2, 8, 10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88]);
        let swapped = swap_timestamp_options(&options);
        assert_eq!(&swapped[..], &[4, 2, 8, 10, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44]);
    }
}

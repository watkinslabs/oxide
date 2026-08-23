//! Effects carried from nftables into the packet owner.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use conntrack::tuple::InetAddr;
use alloc::sync::Arc;
use nat::NatRange;

pub const PAYLOAD_LL_HEADER: u32 = 0;
pub const PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const PAYLOAD_INNER_HEADER: u32 = 3;
pub const PAYLOAD_CSUM_NONE: u32 = 0;
pub const PAYLOAD_CSUM_INET: u32 = 1;
pub const PAYLOAD_CSUM_SCTP: u32 = 2;
pub const PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ApplyError {
    Unsupported,
    Invalid,
    /// The packet was handed to a device owner and must not re-enter the
    /// ordinary stack path (Linux NF_STOLEN).
    Stolen,
}

/// One effect recorded by a netfilter rule and applied by the packet owner.
/// The action list is ordered: Linux evaluates expressions and consumes each
/// effect at the hook that owns the relevant packet state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Nat { manip: u8, range: NatRange },
    Masquerade { range: NatRange },
    Redirect { range: NatRange },
    Dup { gateway: Option<InetAddr>, oif: Option<u32> },
    Fwd { oif: u32, gateway: Option<InetAddr>, nfproto: Option<u8> },
    Log { group: Option<u16>, level: u32, prefix: String, snaplen: u32,
          qthreshold: u16, flags: u32 },
    Reject { reject_type: u32, icmp_code: u8, family: u8 },
    TproxyAssign { addr: InetAddr, port: u16 },
    Synproxy { mss: u16, wscale: u8, flags: u32 },
    FlowOffload { table: String },
    PayloadSet { base: u32, offset: u32, data: Vec<u8>, csum_type: u32,
                 csum_offset: u32, csum_flags: u32 },
    ExthdrSet { op: u32, htype: u8, offset: u32, data: Vec<u8> },
    ExthdrStrip { op: u32, htype: u8 },
}

impl Action {
    /// Apply an action to the packet buffer which owns the hook walk.
    /// Actions that require route, conntrack, or device ownership stay
    /// explicit failures until that owner supplies the corresponding state;
    /// silently accepting and dropping them would split nftables' truth.
    pub fn apply(&self, p: &mut crate::pkt::Pkt, family: u8) -> Result<(), ApplyError> {
        self.apply_at(p, family, 0)
    }

    /// Apply an action at its owning netfilter hook. Stateful actions are
    /// committed to the packet's namespace-owned conntrack entry before the
    /// packet bytes are manipulated, matching Linux's nft NAT path.
    pub fn apply_at(&self, p: &mut crate::pkt::Pkt, family: u8, hook: u32)
        -> Result<(), ApplyError> {
        match self {
            Self::Nat { manip, range } => apply_nat_setup(p, *manip, range),
            Self::Masquerade { range } => {
                let source = masquerade_source(p, family)?;
                let range = nat::policy::masquerade_range(hook as u8, source, range)
                    .map_err(|_| ApplyError::Invalid)?;
                apply_nat_setup(p, nat::uapi::NF_NAT_MANIP_SRC, &range)
            }
            Self::Redirect { range } => {
                let address = redirect_address(p, family, hook as u8);
                let range = nat::policy::redirect_range(hook as u8, family, address, range)
                    .map_err(|_| ApplyError::Invalid)?;
                apply_nat_setup(p, nat::uapi::NF_NAT_MANIP_DST, &range)
            }
            Self::Reject { reject_type, icmp_code, family } => {
                apply_reject(p, *reject_type, *icmp_code, *family, hook)
            }
            Self::TproxyAssign { addr, port } => apply_tproxy(p, *addr, *port, family, hook),
            Self::Fwd { oif, gateway, nfproto } => apply_fwd(p, *oif, *gateway, *nfproto, family),
            Self::Dup { gateway, oif } => apply_dup(p, *gateway, *oif, family),
            Self::Log { group, level, prefix, snaplen, qthreshold, flags } =>
                apply_log(p, *group, *level, prefix, *snaplen, *qthreshold, *flags, family, hook),
            Self::PayloadSet { base, offset, data, csum_type, csum_offset, csum_flags } => {
                if *csum_type > PAYLOAD_CSUM_INET
                    || *csum_flags & !PAYLOAD_L4CSUM_PSEUDOHDR != 0
                    || (*csum_type == PAYLOAD_CSUM_NONE
                        && (*csum_offset != 0 || *csum_flags != 0)) {
                    return Err(ApplyError::Unsupported);
                }
                let base_start = match *base {
                    PAYLOAD_NETWORK_HEADER => 0,
                    PAYLOAD_TRANSPORT_HEADER => transport_offset(p.data(), family)
                        .ok_or(ApplyError::Invalid)?,
                    _ => return Err(ApplyError::Unsupported),
                };
                let start = base_start.checked_add(*offset as usize).ok_or(ApplyError::Invalid)?;
                let end = start.checked_add(data.len()).ok_or(ApplyError::Invalid)?;
                let dst = p.data_mut().get_mut(start..end).ok_or(ApplyError::Invalid)?;
                dst.copy_from_slice(data);
                if *csum_type == PAYLOAD_CSUM_INET {
                    repair_payload_checksum(p, family, *base, base_start,
                        *csum_offset as usize)?;
                }
                Ok(())
            }
            Self::ExthdrSet { op, htype, offset, data } =>
                apply_exthdr_set(p, family, *op, *htype, *offset as usize, data),
            Self::ExthdrStrip { op, htype } => apply_exthdr_strip(p, family, *op, *htype),
            _ => Err(ApplyError::Unsupported),
        }
    }
}

fn apply_tproxy(p: &mut crate::pkt::Pkt, addr: InetAddr, port: u16,
                family: u8, hook: u32) -> Result<(), ApplyError> {
    let udp = match family {
        crate::netfilter_hook::NFPROTO_IPV4 => p.data().get(9).copied()
            == Some(crate::addr::IpProto::Udp as u8),
        crate::netfilter_hook::NFPROTO_IPV6 => p.data().get(6).copied()
            .and_then(|next| crate::ipv6_ext::walk(next, p.data().get(40..)?).ok())
            .map(|walk| matches!(walk, crate::ipv6_ext::ExtWalk::Done { next_header: 17, .. }
                | crate::ipv6_ext::ExtWalk::Fragment { next_header: 17, offset: 0, .. }))
            .unwrap_or(false),
        _ => false,
    };
    if hook != crate::netfilter_hook::NF_INET_PRE_ROUTING || !udp
        || (family == crate::netfilter_hook::NFPROTO_IPV4 && addr.0[4..] != [0; 12]) {
        return Err(ApplyError::Unsupported);
    }
    p.tproxy = Some(crate::pkt::TproxyTarget { addr, port });
    Ok(())
}

fn apply_dup(p: &crate::pkt::Pkt, gateway: Option<InetAddr>, oif: Option<u32>, family: u8)
    -> Result<(), ApplyError> {
    if family != crate::netfilter_hook::NFPROTO_NETDEV || gateway.is_some() {
        return Err(ApplyError::Unsupported);
    }
    let oif = oif.ok_or(ApplyError::Invalid)?;
    let ingress = p.iface.ok_or(ApplyError::Invalid)?;
    let ns = crate::global_stack().ifaces.namespace(ingress).ok_or(ApplyError::Invalid)?;
    let (target, _) = crate::global_stack().ifaces.lookup_ifindex_in_ns(oif, ns)
        .ok_or(ApplyError::Invalid)?;
    let lease = crate::global_stack().ifaces.acquire_egress_in_ns(target, ns)
        .ok_or(ApplyError::Invalid)?;
    // Linux's netdev mirror path sends the clone under the same direct device
    // recursion guard while the original skb remains on its caller's path.
    lease.xmit_raw_policy_from(p.data(), None, true).map_err(|_| ApplyError::Invalid)
}

fn apply_log(p: &crate::pkt::Pkt, group: Option<u16>, level: u32, prefix: &str,
             snaplen: u32, _qthreshold: u16, flags: u32, family: u8, hook: u32)
             -> Result<(), ApplyError> {
    if let Some(group) = group {
        let namespace = p.iface.and_then(|iface| crate::global_stack().ifaces.namespace(iface))
            .unwrap_or_else(|| crate::net_ns::namespace_id(&crate::net_ns::current_namespace()));
        if !crate::netfilter_hook::nf_log_packet(namespace, group, p, family, hook,
                                                 prefix, snaplen, flags) {
            return Err(ApplyError::Unsupported);
        }
        return Ok(());
    }
    let lvl = level.min(klog::syslog::LOGLEVEL_DEBUG);
    klog::write_raw_at(prefix.as_bytes(), lvl);
    klog::write_raw_at(b" nftables mark=", lvl);
    klog::write_dec_at(p.tx.mark as u64, lvl);
    klog::write_raw_at(b" len=", lvl);
    let copied = if snaplen == 0 { p.len() } else { p.len().min(snaplen as usize) };
    klog::write_dec_at(copied as u64, lvl);
    if flags != 0 {
        klog::write_raw_at(b" flags=", lvl);
        klog::write_dec_at(flags as u64, lvl);
    }
    klog::write_raw_at(b"\n", lvl);
    Ok(())
}

fn apply_fwd(p: &mut crate::pkt::Pkt, oif: u32, gateway: Option<InetAddr>,
             nfproto: Option<u8>, family: u8) -> Result<(), ApplyError> {
    if family != crate::netfilter_hook::NFPROTO_NETDEV {
        return Err(ApplyError::Unsupported);
    }
    let ingress = p.iface.ok_or(ApplyError::Invalid)?;
    let ns = crate::global_stack().ifaces.namespace(ingress).ok_or(ApplyError::Invalid)?;
    let (target, _) = crate::global_stack().ifaces.lookup_ifindex_in_ns(oif, ns)
        .ok_or(ApplyError::Invalid)?;
    let lease = crate::global_stack().ifaces.acquire_egress_in_ns(target, ns)
        .ok_or(ApplyError::Invalid)?;
    if nfproto.is_none() && gateway.is_none() {
        // The no-address form is the netdev redirect: it owns the complete
        // link frame and sends it through the selected device unchanged.
        // Linux's netdev forwarding path transmits under its device
        // recursion guard; direct dispatch prevents the redirected frame
        // from re-entering a second netdev egress walk.
        lease.xmit_raw_policy_from(p.data(), None, true)
            .map_err(|_| ApplyError::Invalid)?;
        return Err(ApplyError::Stolen);
    }
    let proto = nfproto.ok_or(ApplyError::Invalid)?;
    let gateway = gateway.ok_or(ApplyError::Invalid)?;
    let frame = p.data();
    let eth = crate::ethernet::EthHdr::parse(frame).map_err(|_| ApplyError::Invalid)?;
    let l3 = frame.get(eth.hdr_len..).ok_or(ApplyError::Invalid)?;
    let mut out = crate::Pkt::from_owned(l3.to_vec());
    out.proto = eth.ethertype;
    out.iface = Some(target);
    out.tx = p.tx;
    match proto {
        crate::netfilter_hook::NFPROTO_IPV4 => {
            if eth.ethertype != crate::eth_p::IPV4 || l3.len() < 20 || l3[0] >> 4 != 4
                || gateway.0[4..] != [0; 12] { return Err(ApplyError::Invalid); }
            if l3[8] <= 1 { return Err(ApplyError::Invalid); }
            let b = out.data_mut();
            b[8] -= 1;
            b[10] = 0; b[11] = 0;
            let checksum = crate::ipv4::ip_checksum(&b[..20]);
            b[10..12].copy_from_slice(&checksum.to_be_bytes());
            out.next_hop = Some(crate::pkt::TxNextHop::V4(crate::Ipv4Addr::new(
                gateway.0[0], gateway.0[1], gateway.0[2], gateway.0[3])));
        }
        crate::netfilter_hook::NFPROTO_IPV6 => {
            if eth.ethertype != crate::eth_p::IPV6 || l3.len() < 40 || l3[0] >> 4 != 6
                || gateway.0[..4] == [0; 4] && gateway.0[4..] == [0; 12] { return Err(ApplyError::Invalid); }
            if l3[7] <= 1 { return Err(ApplyError::Invalid); }
            let b = out.data_mut();
            b[7] -= 1;
            out.next_hop = Some(crate::pkt::TxNextHop::V6 {
                addr: crate::Ipv6Addr(gateway.0), src: crate::Ipv6Addr::ANY,
            });
        }
        _ => return Err(ApplyError::Unsupported),
    }
    lease.xmit(out).map_err(|_| ApplyError::Invalid)?;
    Err(ApplyError::Stolen)
}

fn masquerade_source(p: &crate::pkt::Pkt, family: u8) -> Result<Option<InetAddr>, ApplyError> {
    let Some((_, Some(conn), _, _)) = p.conntrack_state_owned() else {
        return Err(ApplyError::Invalid);
    };
    let ns = conn.net_ns;
    let iface = p.iface.ok_or(ApplyError::Invalid)?;
    if family == conntrack::uapi::NFPROTO_IPV6 {
        let dst = p.data().get(24..40).ok_or(ApplyError::Invalid)?;
        let dst = crate::addr::Ipv6Addr(dst.try_into().map_err(|_| ApplyError::Invalid)?);
        let source = crate::global_stack().routes6.lookup_policy_mark_in(
            ns, dst, crate::global_stack().policy_rules(), p.tx.mark)
            .and_then(|route| route.src_hint)
            .or_else(|| crate::global_stack().v6_src_on_iface(iface))
            .map(|addr| InetAddr::v6(addr.0));
        return Ok(source);
    }
    let bytes = p.data().get(16..20).ok_or(ApplyError::Invalid)?;
    let dst = crate::addr::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let source = crate::global_stack().routes.lookup_result_mark_in(ns, dst, p.tx.mark)
        .ok().and_then(|route| route.src_hint)
        .or_else(|| crate::iface_addr::primary(ns, iface).map(|(addr, _)| addr))
        .map(|addr| InetAddr::v4(addr.octets()));
    Ok(source)
}

fn redirect_address(p: &crate::pkt::Pkt, family: u8, hook: u8) -> Option<InetAddr> {
    if hook == nat::uapi::NF_INET_PRE_ROUTING {
        let iface = p.iface?;
        if family == conntrack::uapi::NFPROTO_IPV6 {
            return crate::global_stack().v6_src_on_iface(iface).map(|addr| InetAddr::v6(addr.0));
        }
        return crate::iface_addr::primary(crate::global_stack().ifaces.namespace(iface)?, iface)
            .map(|(addr, _)| InetAddr::v4(addr.octets()));
    }
    None
}

fn apply_reject(p: &crate::pkt::Pkt, reject_type: u32, icmp_code: u8,
                family: u8, _hook: u32) -> Result<(), ApplyError> {
    // Linux's ICMP/ICMPX reject sends an error and then retains the DROP
    // verdict. TCP-reset rejects need a transport-aware response builder and
    // must not be mistaken for an ICMP response.
    if family != conntrack::uapi::NFPROTO_IPV4 {
        return Err(ApplyError::Unsupported);
    }
    let iface = p.iface.ok_or(ApplyError::Invalid)?;
    let bytes = p.data();
    if bytes.len() < 20 || bytes[0] >> 4 != 4 { return Err(ApplyError::Invalid); }
    if reject_type == 1 {
        let ns = crate::global_stack().ifaces.namespace(iface).ok_or(ApplyError::Invalid)?;
        crate::global_stack().send_tcp_reset_ipv4(ns, bytes, p.tx.mark)
            .map_err(|_| ApplyError::Invalid)?;
        return Ok(());
    }
    let src = crate::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = crate::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    crate::global_stack().send_ipv4_error(iface, dst, src,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, icmp_code, bytes)
        .map_err(|_| ApplyError::Invalid)
}

fn apply_nat_setup(p: &mut crate::pkt::Pkt, manip: u8, range: &NatRange)
    -> Result<(), ApplyError> {
    let Some((table, Some(conn), _info, _dir)) = p.conntrack_state_owned() else {
        return Err(ApplyError::Invalid);
    };
    if nat::setup::initialized(conn.status(), manip) { return Ok(()); }
    let now = p.timestamp_ns / 1_000_000_000;
    struct Env<'a> { table: &'a conntrack::CtTable, conn: &'a Arc<conntrack::Conn>, now: u64 }
    impl nat::NatEnv for Env<'_> {
        fn tuple_taken(&self, tuple: &conntrack::tuple::Tuple) -> bool {
            self.table.tuple_taken(tuple, Some(self.conn), self.now)
        }
        fn random_u16(&self) -> u16 { self.table.random_u16() }
        fn try_evict(&self, _tuple: &conntrack::tuple::Tuple) -> bool {
            self.table.early_drop(self.now)
        }
    }
    let env = Env { table: &table.table, conn: &conn, now };
    if nat::setup_info(&conn, range, manip, &env) == nat::SetupResult::Drop {
        return Err(ApplyError::Invalid);
    }
    Ok(())
}

pub(crate) fn apply_conntrack_packet(p: &mut crate::pkt::Pkt, conn: Arc<conntrack::Conn>,
                                     dir: u8, family: u8, hook: u32)
                                     -> Result<(), ApplyError> {
    if !nat::packet_needs_manip(conn.status(), hook as u8, dir) { return Ok(()); }
    let target = nat::target_tuple(&conn, dir).ok_or(ApplyError::Invalid)?;
    let l4 = transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
    nat::manip::manip_packet(p.data_mut(), l4, &target,
                             nat::uapi::hook_to_manip(hook as u8))
        .map_err(|_| ApplyError::Invalid)
}

fn transport_offset(pkt: &[u8], family: u8) -> Option<usize> {
    if family == 10 {
        if pkt.len() < 40 { return None; }
        return match crate::ipv6_ext::walk(pkt[6], &pkt[40..]).ok()? {
            crate::ipv6_ext::ExtWalk::Done { payload, .. } => Some(pkt.len() - payload.len()),
            crate::ipv6_ext::ExtWalk::Fragment { offset: 0, payload, .. } =>
                Some(pkt.len() - payload.len()),
            crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
        };
    }
    if family != 2 || pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > pkt.len() { return None; }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    if frag != 0 { return None; }
    Some(ihl)
}

fn l4_protocol(pkt: &[u8], family: u8) -> Option<u8> {
    match family {
        crate::netfilter_hook::NFPROTO_IPV4 => pkt.get(9).copied(),
        crate::netfilter_hook::NFPROTO_IPV6 => {
            if pkt.len() < 40 { return None; }
            match crate::ipv6_ext::walk(pkt[6], &pkt[40..]).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, .. } => Some(next_header),
                crate::ipv6_ext::ExtWalk::Fragment { offset: 0, next_header, .. } =>
                    Some(next_header),
                crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
            }
        }
        _ => None,
    }
}

fn repair_payload_checksum(p: &mut crate::pkt::Pkt, family: u8, base: u32,
                           base_start: usize, csum_offset: usize) -> Result<(), ApplyError> {
    let bytes = p.data();
    if base == PAYLOAD_NETWORK_HEADER {
        if family != crate::netfilter_hook::NFPROTO_IPV4 || csum_offset != 10 {
            return Err(ApplyError::Unsupported);
        }
        let ihl = (bytes.first().ok_or(ApplyError::Invalid)? & 0x0f) as usize * 4;
        if ihl < 20 || ihl > bytes.len() { return Err(ApplyError::Invalid); }
        p.data_mut()[10..12].fill(0);
        let checksum = crate::ipv4::ip_checksum(&p.data()[..ihl]);
        p.data_mut()[10..12].copy_from_slice(&checksum.to_be_bytes());
        return Ok(());
    }
    if base != PAYLOAD_TRANSPORT_HEADER || csum_offset > 0xff { return Err(ApplyError::Unsupported); }
    let l4 = base_start;
    let proto = l4_protocol(bytes, family).ok_or(ApplyError::Invalid)?;
    if bytes.len() == l4 { return Err(ApplyError::Invalid); }
    let (src4, dst4, src6, dst6) = match family {
        crate::netfilter_hook::NFPROTO_IPV4 => (
            Some(crate::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
            Some(crate::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])), None, None),
        crate::netfilter_hook::NFPROTO_IPV6 => (
            None, None,
            Some(crate::Ipv6Addr(bytes[8..24].try_into().map_err(|_| ApplyError::Invalid)?)),
            Some(crate::Ipv6Addr(bytes[24..40].try_into().map_err(|_| ApplyError::Invalid)?))),
        _ => return Err(ApplyError::Unsupported),
    };
    let checksum_at = l4.checked_add(csum_offset).ok_or(ApplyError::Invalid)?;
    if checksum_at.checked_add(2).ok_or(ApplyError::Invalid)? > bytes.len() {
        return Err(ApplyError::Invalid);
    }
    let segment = p.data_mut().get_mut(l4..).ok_or(ApplyError::Invalid)?;
    match (family, proto, csum_offset) {
        (crate::netfilter_hook::NFPROTO_IPV4, 17, 6) => {
            if segment.len() < 8 { return Err(ApplyError::Invalid); }
            let src = src4.ok_or(ApplyError::Invalid)?; let dst = dst4.ok_or(ApplyError::Invalid)?;
            let sport = u16::from_be_bytes([segment[0], segment[1]]);
            let dport = u16::from_be_bytes([segment[2], segment[3]]);
            let payload = segment[8..].to_vec();
            crate::udp::UdpHdr::build_into(sport, dport, src, dst, &payload, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV6, 17, 6) => {
            if segment.len() < 8 { return Err(ApplyError::Invalid); }
            let src = src6.ok_or(ApplyError::Invalid)?; let dst = dst6.ok_or(ApplyError::Invalid)?;
            let sport = u16::from_be_bytes([segment[0], segment[1]]);
            let dport = u16::from_be_bytes([segment[2], segment[3]]);
            let payload = segment[8..].to_vec();
            crate::udp::build_into_v6(sport, dport, src, dst, &payload, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV4, 6, 16) => {
            if segment.len() < crate::tcp_hdr::TCP_HDR_MIN_LEN { return Err(ApplyError::Invalid); }
            let src = src4.ok_or(ApplyError::Invalid)?; let dst = dst4.ok_or(ApplyError::Invalid)?;
            let mut hdr = crate::tcp_hdr::TcpHdr {
                src_port: u16::from_be_bytes([segment[0], segment[1]]),
                dst_port: u16::from_be_bytes([segment[2], segment[3]]),
                seq: u32::from_be_bytes(segment[4..8].try_into().map_err(|_| ApplyError::Invalid)?),
                ack: u32::from_be_bytes(segment[8..12].try_into().map_err(|_| ApplyError::Invalid)?),
                data_offset: segment[12] >> 4, flags: segment[13],
                window: u16::from_be_bytes([segment[14], segment[15]]), checksum: 0,
                urg_ptr: u16::from_be_bytes([segment[18], segment[19]]),
            };
            if hdr.data_offset < 5 || segment.len() < hdr.data_offset as usize * 4 {
                return Err(ApplyError::Invalid);
            }
            hdr.build_into(src, dst, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV6, 6, 16) => {
            if segment.len() < crate::tcp_hdr::TCP_HDR_MIN_LEN { return Err(ApplyError::Invalid); }
            let src = src6.ok_or(ApplyError::Invalid)?; let dst = dst6.ok_or(ApplyError::Invalid)?;
            let mut hdr = crate::tcp_hdr::TcpHdr {
                src_port: u16::from_be_bytes([segment[0], segment[1]]),
                dst_port: u16::from_be_bytes([segment[2], segment[3]]),
                seq: u32::from_be_bytes(segment[4..8].try_into().map_err(|_| ApplyError::Invalid)?),
                ack: u32::from_be_bytes(segment[8..12].try_into().map_err(|_| ApplyError::Invalid)?),
                data_offset: segment[12] >> 4, flags: segment[13],
                window: u16::from_be_bytes([segment[14], segment[15]]), checksum: 0,
                urg_ptr: u16::from_be_bytes([segment[18], segment[19]]),
            };
            if hdr.data_offset < 5 || segment.len() < hdr.data_offset as usize * 4 {
                return Err(ApplyError::Invalid);
            }
            hdr.build_into_v6(src, dst, segment);
        }
        _ => return Err(ApplyError::Unsupported),
    }
    Ok(())
}

fn tcp_option(p: &[u8], family: u8, want: u8) -> Option<(usize, usize)> {
    let at = transport_offset(p, family)?;
    let segment = p.get(at..)?;
    let header_len = (*segment.get(12)? >> 4) as usize * 4;
    if header_len < crate::tcp_hdr::TCP_HDR_MIN_LEN || header_len > segment.len() {
        return None;
    }
    let mut i = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    while i < header_len {
        let kind = *segment.get(i)?;
        if kind == 0 { return None; }
        if kind == want {
            let len = if kind == 1 { 1 } else { *segment.get(i + 1)? as usize };
            if len < 2 || i + len > header_len { return None; }
            return Some((at + i, len));
        }
        let len = if kind == 1 { 1 } else { *segment.get(i + 1)? as usize };
        if len < 2 || i + len > header_len { return None; }
        i += len;
    }
    None
}

fn apply_exthdr_set(p: &mut crate::pkt::Pkt, family: u8, op: u32, htype: u8,
                    offset: usize, data: &[u8]) -> Result<(), ApplyError> {
    match op {
        // NFT_EXTHDR_OP_TCPOPT. Linux only permits two- and four-byte writes
        // to TCP options; the parser has already enforced that shape.
        1 => {
            let l4 = transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
            let (at, len) = tcp_option(p.data(), family, htype).ok_or(ApplyError::Invalid)?;
            if offset.checked_add(data.len()).ok_or(ApplyError::Invalid)? > len {
                return Err(ApplyError::Invalid);
            }
            let start = at + offset;
            p.data_mut()[start..start + data.len()].copy_from_slice(data);
            repair_payload_checksum(p, family, PAYLOAD_TRANSPORT_HEADER, l4, 16)
        }
        // NFT_EXTHDR_OP_IPV4. Only the supported IPv4 options are exposed by
        // the evaluator, and they live inside the variable-length IP header.
        2 => {
            if family != crate::netfilter_hook::NFPROTO_IPV4 { return Err(ApplyError::Unsupported); }
            let ihl = (*p.data().first().ok_or(ApplyError::Invalid)? & 0x0f) as usize * 4;
            let (at, len) = ipv4_option(p.data(), htype).ok_or(ApplyError::Invalid)?;
            if at + offset + data.len() > at + len || at + offset + data.len() > ihl {
                return Err(ApplyError::Invalid);
            }
            let start = at + offset;
            p.data_mut()[start..start + data.len()].copy_from_slice(data);
            repair_payload_checksum(p, family, PAYLOAD_NETWORK_HEADER, 0, 10)
        }
        _ => Err(ApplyError::Unsupported),
    }
}

fn ipv4_option(p: &[u8], want: u8) -> Option<(usize, usize)> {
    if p.len() < 20 { return None; }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > p.len() { return None; }
    let mut i = 20;
    while i < ihl {
        let kind = p[i];
        if kind == 0 { return None; }
        if kind == want {
            let len = p.get(i + 1).copied()? as usize;
            if len < 2 || i + len > ihl { return None; }
            return Some((i, len));
        }
        if kind == 1 { i += 1; continue; }
        let len = p.get(i + 1).copied()? as usize;
        if len < 2 || i + len > ihl { return None; }
        i += len;
    }
    None
}

fn apply_exthdr_strip(p: &mut crate::pkt::Pkt, family: u8, op: u32, htype: u8)
    -> Result<(), ApplyError> {
    match op {
        1 => {
            let l4 = match transport_offset(p.data(), family) {
                Some(l4) => l4,
                None => return Ok(()),
            };
            let (at, len) = match tcp_option(p.data(), family, htype) {
                Some(found) => found,
                None => return Ok(()),
            };
            p.data_mut()[at..at + len].fill(1);
            repair_payload_checksum(p, family, PAYLOAD_TRANSPORT_HEADER, l4, 16)
        }
        2 => {
            if family != crate::netfilter_hook::NFPROTO_IPV4 { return Err(ApplyError::Unsupported); }
            let (at, len) = match ipv4_option(p.data(), htype) {
                Some(found) => found,
                None => return Ok(()),
            };
            p.data_mut()[at..at + len].fill(1);
            repair_payload_checksum(p, family, PAYLOAD_NETWORK_HEADER, 0, 10)
        }
        _ => Err(ApplyError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, sync::Arc, vec};
    use conntrack::entry::Conn;
    use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
    use conntrack::uapi::{IP_CT_NEW, IPPROTO_TCP, NFPROTO_IPV4};
    use super::{apply_conntrack_packet, Action, ApplyError, PAYLOAD_NETWORK_HEADER,
                PAYLOAD_TRANSPORT_HEADER};
    use crate::pkt::Pkt;

    #[test]
    fn payload_set_repairs_ipv4_header_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 20];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Udp, 0, 1).write_to(&mut bytes);
        let action = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 1,
            data: vec![0x2e], csum_type: super::PAYLOAD_CSUM_INET, csum_offset: 10,
            csum_flags: 0 };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert_eq!(crate::ipv4::ip_checksum(pkt.data()), 0);
    }

    #[test]
    fn payload_set_repairs_ipv4_udp_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 32];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Udp, 12, 1).write_to(&mut bytes);
        crate::udp::UdpHdr::build_into(1000, 2000, src, dst, &[1, 2, 3, 4], &mut bytes[20..]);
        let action = Action::PayloadSet { base: PAYLOAD_TRANSPORT_HEADER, offset: 8,
            data: vec![9], csum_type: super::PAYLOAD_CSUM_INET, csum_offset: 6,
            csum_flags: super::PAYLOAD_L4CSUM_PSEUDOHDR };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert!(crate::udp::udp_checksum_ok(&pkt.data()[20..], src, dst));
    }

    #[test]
    fn exthdr_set_updates_tcp_option_and_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 44];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Tcp, 24, 1).write_to(&mut bytes);
        let mut tcp = crate::tcp_hdr::TcpHdr {
            src_port: 1000, dst_port: 2000, seq: 1, ack: 0, data_offset: 6,
            flags: crate::tcp_hdr::flags::SYN, window: 4096, checksum: 0, urg_ptr: 0,
        };
        tcp.build_into(src, dst, &mut bytes[20..]);
        bytes[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        tcp.build_into(src, dst, &mut bytes[20..]);
        let action = Action::ExthdrSet { op: 1, htype: 2, offset: 2,
            data: vec![0x04, 0x00] };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert_eq!(&pkt.data()[42..44], &[0x04, 0x00]);
        assert!(crate::tcp_hdr::tcp_checksum_ok(&pkt.data()[20..], src, dst));
    }

    #[test]
    fn payload_set_mutates_packet_owner_buffer() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let action = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 1,
            data: vec![0x2e], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[1], 0x2e);
    }

    #[test]
    fn ipv6_udp_tproxy_records_target() {
        let src = crate::Ipv6Addr([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = crate::Ipv6Addr([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut bytes = vec![0u8; 48];
        crate::ipv6::Ipv6Hdr::build(src, dst, crate::IpProto::Udp, 8)
            .write_to(&mut bytes);
        bytes[40..48].copy_from_slice(&[0x03, 0xe8, 0x07, 0xd0, 0, 8, 0, 0]);
        let target = InetAddr::v6([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let mut pkt = Pkt::from_owned(bytes);
        Action::TproxyAssign { addr: target, port: 5353 }
            .apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_IPV6,
                crate::netfilter_hook::NF_INET_PRE_ROUTING).unwrap();
        assert_eq!(pkt.tproxy_target(), Some(crate::pkt::TproxyTarget { addr: target, port: 5353 }));
    }

    #[test]
    fn payload_set_resolves_transport_header_and_rejects_bounds() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
                                            0, 53, 0, 54]);
        let action = Action::PayloadSet { base: PAYLOAD_TRANSPORT_HEADER, offset: 1,
            data: vec![0xab], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[21], 0xab);
        let invalid = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 24,
            data: vec![1], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        assert_eq!(invalid.apply(&mut pkt, 2), Err(ApplyError::Invalid));
    }

    #[test]
    fn stateful_actions_are_not_silently_discarded() {
        let mut pkt = Pkt::from_owned(vec![0; 20]);
        let action = Action::FlowOffload { table: String::new() };
        assert_eq!(action.apply(&mut pkt, 2), Err(ApplyError::Unsupported));
    }

    #[test]
    fn syslog_log_is_consumed_without_changing_the_packet_verdict() {
        let mut pkt = Pkt::from_owned(vec![0u8; 20]);
        let action = Action::Log { group: None, level: 4, prefix: String::from("nft: "),
            snaplen: 32, qthreshold: 0, flags: 0 };
        assert_eq!(action.apply(&mut pkt, 2), Ok(()));
        let nflog = Action::Log { group: Some(7), level: 4, prefix: String::new(),
            snaplen: 0, qthreshold: 1, flags: 0 };
        assert_eq!(nflog.apply(&mut pkt, 2), Err(ApplyError::Unsupported));
    }

    #[test]
    fn nat_action_binds_the_pending_flow_and_rewrites_the_owner() {
        let orig = Tuple { src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]),
                proto: ProtoPart::port(40000) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]),
                proto: ProtoPart::port(443) }, l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP, zone: 0 };
        let conn = Arc::new(Conn::new(1, orig, orig.invert().unwrap(), 7));
        let table = Arc::new(conntrack::CtNet::new(7, 1));
        table.table.add_pending(conn.clone());
        let mut pkt = Pkt::from_owned(vec![
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, IPPROTO_TCP, 0, 0,
            10, 0, 0, 1, 198, 51, 100, 2, 0x9c, 0x40, 1, 0xbb,
            0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ]);
        pkt.set_conntrack_state(table, Some(conn.clone()), IP_CT_NEW, 0);
        let action = Action::Nat { manip: nat::uapi::NF_NAT_MANIP_SRC,
            range: nat::NatRange::single_addr(InetAddr::v4([203, 0, 113, 9]), 0) };
        action.apply_at(&mut pkt, NFPROTO_IPV4, 4).unwrap();
        apply_conntrack_packet(&mut pkt, conn.clone(), 0, NFPROTO_IPV4, 4).unwrap();
        assert_eq!(&pkt.data()[12..16], &[203, 0, 113, 9]);
        assert_eq!(conn.reply_tuple().dst.addr, InetAddr::v4([203, 0, 113, 9]));
        assert!(action.apply_at(&mut pkt, NFPROTO_IPV4, 4).is_ok());
    }

    #[test]
    fn netdev_fwd_neighbour_form_decrements_ttl_and_uses_the_target_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (source, _) = stack.register_loopback();
        let (target, target_dev) = stack.register_loopback();
        let ifindex = stack.ifaces.ifindex_in_ns(target, 0).unwrap();
        let mut l3 = vec![0u8; 20];
        crate::ipv4::Ipv4Hdr::build(crate::Ipv4Addr::LOOPBACK, crate::Ipv4Addr::LOOPBACK,
            crate::IpProto::Udp, 0, 1).write_to(&mut l3);
        let mut frame = vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr([2, 0, 0, 0, 0, 1]), crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);
        let mut pkt = Pkt::from_owned(frame);
        pkt.proto = crate::eth_p::IPV4;
        pkt.iface = Some(source);
        let action = Action::Fwd { oif: ifindex,
            gateway: Some(InetAddr::v4([127, 0, 0, 1])), nfproto: Some(NFPROTO_IPV4) };
        assert_eq!(action.apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_NETDEV, 0),
            Err(ApplyError::Stolen));
        assert_eq!(target_dev.rx_len(), 1);
        assert_eq!(target_dev.rx_pop().unwrap().data()[8], 63);
    }

    #[test]
    fn netdev_dup_mirrors_the_frame_and_keeps_the_original_owner() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (source, _) = stack.register_loopback();
        let (target, target_dev) = stack.register_loopback();
        let ifindex = stack.ifaces.ifindex_in_ns(target, 0).unwrap();
        let mut frame = vec![0u8; crate::ethernet::ETH_HDR_LEN + 20];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr([2, 0, 0, 0, 0, 1]), crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN] = 0x45;
        let original = frame.clone();
        let mut pkt = Pkt::from_owned(frame);
        pkt.proto = crate::eth_p::IPV4;
        pkt.iface = Some(source);
        let action = Action::Dup { gateway: None, oif: Some(ifindex) };
        action.apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_NETDEV, 0).unwrap();
        assert_eq!(pkt.data(), original.as_slice());
        assert_eq!(target_dev.rx_len(), 1);
    }
}

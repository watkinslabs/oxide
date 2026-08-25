//! Effects carried from nftables into the packet owner.

extern crate alloc;
use alloc::{string::String, vec::Vec};

mod checksum;
mod tcp;
mod extensions;
#[cfg(test)]
mod tests;

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
    FlowOffload { table: String, flowtable: String },
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
            Self::Synproxy { mss, wscale, flags } => {
                if !matches!(hook, crate::netfilter_hook::NF_INET_LOCAL_IN
                    | crate::netfilter_hook::NF_INET_FORWARD) {
                    return Err(ApplyError::Unsupported);
                }
                crate::global_stack().apply_synproxy(p, family, *mss, *wscale, *flags, hook)
            }
            Self::FlowOffload { table, flowtable } =>
                crate::global_stack().offload_flow(table, flowtable, p, family, hook),
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
                    PAYLOAD_TRANSPORT_HEADER => checksum::transport_offset(p.data(), family)
                        .ok_or(ApplyError::Invalid)?,
                    _ => return Err(ApplyError::Unsupported),
                };
                let start = base_start.checked_add(*offset as usize).ok_or(ApplyError::Invalid)?;
                let end = start.checked_add(data.len()).ok_or(ApplyError::Invalid)?;
                let dst = p.data_mut().get_mut(start..end).ok_or(ApplyError::Invalid)?;
                dst.copy_from_slice(data);
                if *csum_type == PAYLOAD_CSUM_INET {
                    checksum::repair_payload_checksum(p, family, *base, base_start,
                        *csum_offset as usize)?;
                }
                Ok(())
            }
            Self::ExthdrSet { op, htype, offset, data } =>
                extensions::apply_exthdr_set(p, family, *op, *htype, *offset as usize, data),
            Self::ExthdrStrip { op, htype } => extensions::apply_exthdr_strip(p, family, *op, *htype),
        }
    }
}

fn apply_tproxy(p: &mut crate::pkt::Pkt, addr: InetAddr, port: u16,
                family: u8, hook: u32) -> Result<(), ApplyError> {
    let transport = match family {
        crate::netfilter_hook::NFPROTO_IPV4 => p.data().get(9).copied(),
        crate::netfilter_hook::NFPROTO_IPV6 => p.data().get(6).copied()
            .and_then(|next| crate::ipv6_ext::walk(next, p.data().get(40..)?).ok())
            .and_then(|walk| match walk {
                crate::ipv6_ext::ExtWalk::Done { next_header, .. }
                | crate::ipv6_ext::ExtWalk::Fragment { next_header, offset: 0, .. } => Some(next_header),
                crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
            }),
        _ => None,
    };
    if hook != crate::netfilter_hook::NF_INET_PRE_ROUTING
        || !matches!(transport, Some(6 | 17))
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
    if nat::packet_needs_manip(conn.status(), hook as u8, dir) {
        let target = nat::target_tuple(&conn, dir).ok_or(ApplyError::Invalid)?;
        let l4 = checksum::transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
        nat::manip::manip_packet(p.data_mut(), l4, &target,
                                 nat::uapi::hook_to_manip(hook as u8))
            .map_err(|_| ApplyError::Invalid)?;
    }
    if conn.status() & conntrack::uapi::IPS_SEQ_ADJUST != 0 {
        tcp::apply_tcp_seq_adjust(p, &conn, dir, family)?;
    }
    Ok(())
}

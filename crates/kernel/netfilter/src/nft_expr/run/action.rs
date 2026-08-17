//! Evaluation of the expressions that act on the packet. Each records what
//! it wants done and leaves the doing to the caller, which owns the packet
//! buffer, the route and the devices.

extern crate alloc;
use alloc::string::String;

use conntrack::tuple::InetAddr;
use nat::policy::{masquerade_range, redirect_range};
use nat::uapi::{NF_NAT_MANIP_DST, NF_NAT_MANIP_SRC, NF_NAT_RANGE_NETMAP};
use nat::NatRange;

use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::flags::{NFT_QUEUE_FLAG_BYPASS, NFT_QUEUE_FLAG_CPU_FANOUT};
use crate::nft_expr::hashing::jhash;
use crate::nft_expr::limits::{ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::nft_expr::regs::Regs;
use crate::nft_expr::run::packet::{l4proto, transport_offset};
use crate::nft_expr::uapi::*;

const BREAK: Option<i32> = Some(NFT_BREAK);

/// Address bytes in a register, widened to the tuple's storage. # C: O(1)
fn reg_addr(regs: &Regs, reg: u32, family: u8) -> Option<InetAddr> {
    if family == NFPROTO_IPV6 { return regs.load_addr16(reg).map(InetAddr::v6); }
    let b = regs.load(reg, 4)?;
    Some(InetAddr::v4([b[0], b[1], b[2], b[3]]))
}

/// Address the packet header carries at one end. # C: O(1)
fn header_addr(ctx: &EvalCtx, manip: u8) -> Option<InetAddr> {
    if ctx.family == NFPROTO_IPV6 {
        let at = if manip == NF_NAT_MANIP_SRC { 8 } else { 24 };
        let b = ctx.pkt.get(at..at + 16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        return Some(InetAddr::v6(a));
    }
    let at = if manip == NF_NAT_MANIP_SRC { 12 } else { 16 };
    let b = ctx.pkt.get(at..at + 4)?;
    Some(InetAddr::v4([b[0], b[1], b[2], b[3]]))
}

/// One-to-one prefix mapping: the host part of the packet's own address is
/// kept and only the network part is replaced, so the whole prefix maps.
/// # C: O(1)
pub fn netmap_addr(orig: InetAddr, min: InetAddr, max: InetAddr) -> InetAddr {
    let mut out = [0u8; 16];
    for i in 0..16 {
        let netmask = !(min.0[i] ^ max.0[i]);
        out[i] = (orig.0[i] & !netmask) | (min.0[i] & netmask);
    }
    InetAddr(out)
}

/// # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn nat(ctx: &mut EvalCtx, regs: &Regs, nat_type: u32, family: u8, flags: u32,
           sreg_addr_min: Option<u32>, sreg_addr_max: Option<u32>,
           sreg_proto_min: Option<u32>, sreg_proto_max: Option<u32>) -> Option<i32>
{
    let manip = if nat_type == NFT_NAT_SNAT { NF_NAT_MANIP_SRC } else { NF_NAT_MANIP_DST };
    let mut range = NatRange { flags, ..NatRange::default() };
    if let Some(min) = sreg_addr_min {
        let Some(min_addr) = reg_addr(regs, min, family) else { return BREAK };
        let max_addr = sreg_addr_max.and_then(|r| reg_addr(regs, r, family)).unwrap_or(min_addr);
        if flags & NF_NAT_RANGE_NETMAP != 0 {
            let Some(orig) = header_addr(ctx, manip) else { return BREAK };
            let mapped = netmap_addr(orig, min_addr, max_addr);
            range.min_addr = mapped;
            range.max_addr = mapped;
        } else {
            range.min_addr = min_addr;
            range.max_addr = max_addr;
        }
    }
    if let Some(min) = sreg_proto_min {
        let Some(min_port) = regs.load_be16(min) else { return BREAK };
        range.min_proto = min_port;
        range.max_proto = sreg_proto_max.and_then(|r| regs.load_be16(r)).unwrap_or(min_port);
    }
    ctx.actions.push(Action::Nat { manip, range });
    None
}

/// # C: O(1)
pub fn masq(ctx: &mut EvalCtx, regs: &Regs, flags: u32, sreg_proto_min: Option<u32>,
            sreg_proto_max: Option<u32>) -> Option<i32>
{
    let mut requested = NatRange { flags, ..NatRange::default() };
    if let Some(min) = sreg_proto_min {
        let Some(min_port) = regs.load_be16(min) else { return BREAK };
        requested.min_proto = min_port;
        requested.max_proto = sreg_proto_max.and_then(|r| regs.load_be16(r)).unwrap_or(min_port);
    }
    // No egress address means the packet cannot be given a valid source; the
    // reference drops rather than emitting a translation onto nothing.
    let src = ctx.route.and_then(|r| r.src_addr());
    match masquerade_range(ctx.hook, src, &requested) {
        Ok(range) => { ctx.actions.push(Action::Masquerade { range }); None }
        Err(_) => Some(NF_DROP),
    }
}

/// # C: O(1)
pub fn redir(ctx: &mut EvalCtx, regs: &Regs, flags: u32, sreg_proto_min: Option<u32>,
             sreg_proto_max: Option<u32>) -> Option<i32>
{
    let mut requested = NatRange { flags, ..NatRange::default() };
    if let Some(min) = sreg_proto_min {
        let Some(min_port) = regs.load_be16(min) else { return BREAK };
        requested.min_proto = min_port;
        requested.max_proto = sreg_proto_max.and_then(|r| regs.load_be16(r)).unwrap_or(min_port);
    }
    let iface = ctx.route.and_then(|r| r.iface_addr());
    match redirect_range(ctx.hook, ctx.family, iface, &requested) {
        Ok(range) => { ctx.actions.push(Action::Redirect { range }); None }
        Err(_) => Some(NF_DROP),
    }
}

/// A duplicated packet is a copy; the original's verdict is untouched.
/// # C: O(1)
pub fn dup(ctx: &mut EvalCtx, regs: &Regs, sreg_addr: Option<u32>, sreg_dev: Option<u32>)
    -> Option<i32>
{
    let gateway = sreg_addr.and_then(|r| reg_addr(regs, r, ctx.family));
    let oif = sreg_dev.and_then(|r| regs.load_u32(r));
    ctx.actions.push(Action::Dup { gateway, oif });
    None
}

/// Hop limit at which a packet may no longer be forwarded. # C: O(1)
const HOPLIMIT_EXHAUSTED: u8 = 1;

/// # C: O(1)
pub fn fwd(ctx: &mut EvalCtx, regs: &Regs, sreg_dev: u32, sreg_addr: Option<u32>,
           nfproto: Option<u8>) -> Option<i32>
{
    let Some(oif) = regs.load_u32(sreg_dev) else { return BREAK };
    let Some(proto) = nfproto else {
        ctx.actions.push(Action::Fwd { oif, nfproto: None });
        return Some(NF_STOLEN);
    };
    // The neighbour form rewrites the next hop, so it must be reading the
    // family it was configured for.
    let want_ethertype = match proto {
        NFPROTO_IPV4 => ETH_P_IP,
        NFPROTO_IPV6 => ETH_P_IPV6,
        _ => return BREAK,
    };
    if ctx.meta.protocol != Some(want_ethertype) { return BREAK; }
    let ttl_at = if proto == NFPROTO_IPV6 { 7 } else { 8 };
    let Some(&ttl) = ctx.pkt.get(ttl_at) else { return BREAK };
    if ttl <= HOPLIMIT_EXHAUSTED { return Some(NF_DROP); }
    let _ = sreg_addr;
    ctx.actions.push(Action::Fwd { oif, nfproto: Some(proto) });
    Some(NF_STOLEN)
}

/// # C: O(len(prefix))
#[allow(clippy::too_many_arguments)]
pub fn log(ctx: &mut EvalCtx, group: Option<u16>, level: u32, prefix: &str, snaplen: u32,
           qthreshold: u16, flags: u32) -> Option<i32>
{
    ctx.actions.push(Action::Log { group, level, prefix: String::from(prefix), snaplen,
                                   qthreshold, flags });
    None
}

/// A reject always drops; the answer to the sender is a side effect of the
/// drop, never an alternative to it. # C: O(1)
pub fn reject(ctx: &mut EvalCtx, reject_type: u32, icmp_code: u8) -> Option<i32> {
    let family = ctx.family;
    ctx.actions.push(Action::Reject { reject_type, icmp_code, family });
    Some(NF_DROP)
}

/// ICMP code an ICMPX reject maps onto for one family. # C: O(1)
pub fn icmpx_code(family: u8, code: u8) -> u8 {
    use crate::nft_expr::limits::*;
    if family == NFPROTO_IPV6 {
        match code {
            NFT_REJECT_ICMPX_NO_ROUTE => ICMPV6_NOROUTE,
            NFT_REJECT_ICMPX_PORT_UNREACH => ICMPV6_PORT_UNREACH,
            NFT_REJECT_ICMPX_HOST_UNREACH => ICMPV6_ADDR_UNREACH,
            NFT_REJECT_ICMPX_ADMIN_PROHIBITED => ICMPV6_ADM_PROHIBITED,
            _ => ICMPV6_NOROUTE,
        }
    } else {
        match code {
            NFT_REJECT_ICMPX_NO_ROUTE => ICMP_NET_UNREACH,
            NFT_REJECT_ICMPX_PORT_UNREACH => ICMP_PORT_UNREACH,
            NFT_REJECT_ICMPX_HOST_UNREACH => ICMP_HOST_UNREACH,
            NFT_REJECT_ICMPX_ADMIN_PROHIBITED => ICMP_PKT_FILTERED,
            _ => ICMP_NET_UNREACH,
        }
    }
}

/// Queue a flow lands in when a rule spreads one rule over several queues.
/// The flow's addresses pick the queue so both directions of one connection
/// stay on the same reader. # C: O(1)
pub fn queue_for_flow(ctx: &EvalCtx, base: u16, total: u16) -> u16 {
    let addrs = if ctx.family == NFPROTO_IPV6 { ctx.pkt.get(8..40) } else { ctx.pkt.get(12..20) };
    let hash = jhash(addrs.unwrap_or(&[]), ctx.family as u32);
    base.wrapping_add((hash % total as u32) as u16)
}

/// # C: O(1)
pub fn queue(ctx: &EvalCtx, regs: &Regs, num: u16, total: u16, flags: u32,
             sreg_qnum: Option<u32>) -> Option<i32>
{
    let queue = match sreg_qnum {
        Some(reg) => regs.load_u32(reg)? as u16,
        None if total > 1 => {
            if flags & NFT_QUEUE_FLAG_CPU_FANOUT != 0 {
                num.wrapping_add((ctx.cpu % total as u32) as u16)
            } else {
                queue_for_flow(ctx, num, total)
            }
        }
        None => num,
    };
    let mut code = nf_queue_nr(queue);
    if flags & NFT_QUEUE_FLAG_BYPASS != 0 { code |= NF_VERDICT_FLAG_QUEUE_BYPASS; }
    Some(code)
}

/// # C: O(1)
pub fn tproxy(ctx: &mut EvalCtx, regs: &Regs, family: u8, sreg_addr: Option<u32>,
              sreg_port: Option<u32>) -> Option<i32>
{
    if family != NFPROTO_UNSPEC && family != ctx.family { return BREAK; }
    let Some(proto) = l4proto(ctx) else { return BREAK };
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP { return BREAK; }
    let Some(thoff) = transport_offset(ctx) else { return BREAK };
    let Some(dport_bytes) = ctx.pkt.get(thoff + 2..thoff + 4) else { return BREAK };
    let addr = match sreg_addr {
        Some(reg) => match reg_addr(regs, reg, ctx.family) { Some(a) => a, None => return BREAK },
        None => match header_addr(ctx, NF_NAT_MANIP_DST) { Some(a) => a, None => return BREAK },
    };
    let port = match sreg_port.and_then(|r| regs.load_be16(r)) {
        Some(p) if p != 0 => p,
        _ => u16::from_be_bytes([dport_bytes[0], dport_bytes[1]]),
    };
    let Some(socket) = ctx.socket else { return BREAK };
    if !socket.tproxy_transparent(&addr, port) { return BREAK; }
    ctx.actions.push(Action::TproxyAssign { addr, port });
    None
}

/// TCP control bits the handshake proxy classifies on.
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;

/// # C: O(1)
pub fn synproxy(ctx: &mut EvalCtx, mss: u16, wscale: u8, flags: u32) -> Option<i32> {
    if l4proto(ctx) != Some(IPPROTO_TCP) { return BREAK; }
    let Some(thoff) = transport_offset(ctx) else { return BREAK };
    let Some(tcp) = ctx.pkt.get(thoff..thoff + 20) else { return BREAK };
    let control = tcp[13];
    if control & TCP_FLAG_RST != 0 { return None; }
    if control & TCP_FLAG_SYN != 0 && control & TCP_FLAG_ACK == 0 {
        // The proxy answers the opening segment itself, so the packet never
        // reaches the protected host.
        ctx.actions.push(Action::Synproxy { mss, wscale, flags });
        return Some(NF_STOLEN);
    }
    if control & TCP_FLAG_ACK != 0 && control & TCP_FLAG_SYN == 0 {
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let Some(cookies) = ctx.synproxy else { return BREAK };
        return match cookies.cookie_valid(seq, ack) {
            Some(_) => {
                ctx.actions.push(Action::Synproxy { mss, wscale, flags });
                Some(NF_STOLEN)
            }
            None => Some(NF_DROP),
        };
    }
    None
}

/// # C: O(1)
pub fn flow_offload(ctx: &mut EvalCtx, table: &str) -> Option<i32> {
    let Some(ct) = ctx.ct else { return BREAK };
    if !ct.offloadable() { return BREAK; }
    ctx.actions.push(Action::FlowOffload { table: String::from(table) });
    None
}

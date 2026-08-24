//! Evaluation of the expressions that read a source outside the packet:
//! the route, the routing table, the owning socket, the fingerprint database,
//! the transform state, tunnel metadata — plus the header-option walker.

use conntrack::tuple::InetAddr;

use crate::nft_expr::access::FibKey;
use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::flags::*;
use crate::nft_expr::limits::*;
use crate::nft_expr::regs::Regs;
use crate::nft_expr::run::packet::{l4proto, tcp_header, transport_offset};
use crate::nft_expr::uapi::*;

const BREAK: Option<i32> = Some(NFT_BREAK);

/// # C: O(1)
fn stored(result: Option<()>) -> Option<i32> { if result.is_some() { None } else { BREAK } }

/// # C: O(1)
pub fn rt(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32) -> Option<i32> {
    let Some(route) = ctx.route else { return BREAK };
    match key {
        NFT_RT_CLASSID  => match route.classid() {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },
        NFT_RT_NEXTHOP4 => {
            if ctx.family == NFPROTO_IPV6 { return BREAK; }
            match route.nexthop4() { Some(a) => stored(regs.store(dreg, &a)), None => BREAK }
        }
        NFT_RT_NEXTHOP6 => {
            if ctx.family != NFPROTO_IPV6 { return BREAK; }
            match route.nexthop6() { Some(a) => stored(regs.store(dreg, &a)), None => BREAK }
        }
        NFT_RT_TCPMSS   => match route.tcpmss() {
            Some(v) => stored(regs.store_u16(dreg, v)), None => BREAK },
        NFT_RT_XFRM     => stored(regs.store_u8(dreg, route.transformed() as u8)),
        _ => BREAK,
    }
}

/// Address a `fib` lookup keys on: the packet's own source or destination.
/// # C: O(1)
pub fn fib_addr(ctx: &EvalCtx, flags: u32) -> Option<InetAddr> {
    let want_src = flags & NFTA_FIB_F_SADDR != 0;
    if ctx.family == NFPROTO_IPV6 {
        let at = if want_src { 8 } else { 24 };
        let b = ctx.pkt.get(at..at + 16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        return Some(InetAddr::v6(a));
    }
    let at = if want_src { 12 } else { 16 };
    let b = ctx.pkt.get(at..at + 4)?;
    Some(InetAddr::v4([b[0], b[1], b[2], b[3]]))
}

/// Differentiated-services value the lookup honours. # C: O(1)
fn dscp(ctx: &EvalCtx) -> u8 {
    match ctx.family {
        NFPROTO_IPV6 => ctx.pkt.get(0).zip(ctx.pkt.get(1))
            .map_or(0, |(a, b)| (((*a & 0x0f) << 4) | (*b >> 4)) & 0xfc),
        _ => ctx.pkt.first().map_or(0, |_| ctx.pkt.get(1).copied().unwrap_or(0) & 0xfc),
    }
}

/// # C: O(log N routes)
pub fn fib(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, result: u32, flags: u32) -> Option<i32> {
    let Some(addr) = fib_addr(ctx, flags) else { return BREAK };
    let key = FibKey {
        family: ctx.family,
        addr,
        mark: if flags & NFTA_FIB_F_MARK != 0 { ctx.mark } else { 0 },
        dscp: dscp(ctx),
        iif: (flags & NFTA_FIB_F_IIF != 0).then(|| ctx.meta.iif.map(|i| i.index)).flatten(),
        oif: (flags & NFTA_FIB_F_OIF != 0).then(|| ctx.meta.oif.map(|i| i.index)).flatten(),
    };
    let Some(route) = ctx.route else { return BREAK };
    let entry = route.fib(&key);
    if flags & NFTA_FIB_F_PRESENT != 0 {
        let present = entry.as_ref().is_some_and(|e| e.oif.is_some());
        return stored(regs.store_u8(dreg, present as u8));
    }
    let Some(entry) = entry else { return BREAK };
    match result {
        // A locally delivered route leaves by no interface, so there is
        // nothing to report and the rule stops.
        NFT_FIB_RESULT_OIF => match entry.oif {
            Some(index) => stored(regs.store_u32(dreg, index)), None => BREAK },
        NFT_FIB_RESULT_OIFNAME => match entry.oif {
            Some(_) => stored(regs.store(dreg, &entry.oifname)), None => BREAK },
        NFT_FIB_RESULT_ADDRTYPE => stored(regs.store_u32(dreg, entry.addrtype)),
        _ => BREAK,
    }
}

/// # C: O(level)
pub fn socket(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32, level: u32) -> Option<i32> {
    let Some(sock) = ctx.socket else { return BREAK };
    if !sock.present() { return BREAK; }
    match key {
        NFT_SOCKET_TRANSPARENT => stored(regs.store_u8(dreg, sock.transparent() as u8)),
        NFT_SOCKET_MARK => {
            // A request or time-wait stub carries no mark of its own.
            if !sock.full() { return BREAK; }
            stored(regs.store_u32(dreg, sock.mark()))
        }
        NFT_SOCKET_WILDCARD => {
            if !sock.full() { return BREAK; }
            stored(regs.store_u8(dreg, sock.wildcard() as u8))
        }
        NFT_SOCKET_CGROUPV2 => match sock.cgroup_id(level) {
            Some(id) => stored(regs.store_u64(dreg, id)), None => BREAK },
        _ => BREAK,
    }
}

/// TCP control bits a fingerprint is taken from. # C: O(1)
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// # C: O(N fingerprints)
pub fn osf(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, ttl: u8, flags: u32) -> Option<i32> {
    // A fingerprint is only meaningful on the opening segment of a v4 flow.
    if ctx.family == NFPROTO_IPV6 { return BREAK; }
    if l4proto(ctx) != Some(IPPROTO_TCP) { return BREAK; }
    let Some(thoff) = transport_offset(ctx) else { return BREAK };
    let Some(tcp) = ctx.pkt.get(thoff..thoff + TCP_MIN_HDR) else { return BREAK };
    if tcp[13] & TCP_FLAG_SYN == 0 || tcp[13] & TCP_FLAG_ACK != 0 { return BREAK; }
    let mut genre = [0u8; NFT_OSF_MAXGENRELEN];
    if ctx.osf.is_none_or(|prints|
        !prints.genre(ttl, flags & NFT_OSF_F_VERSION != 0, &mut genre)) {
        genre[..7].copy_from_slice(b"unknown");
    }
    stored(regs.store(dreg, &genre))
}

/// # C: O(spnum)
pub fn xfrm(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32, dir: u32, spnum: u32)
    -> Option<i32>
{
    let Some(states) = ctx.xfrm else { return BREAK };
    let Some(state) = states.state(dir, spnum) else { return BREAK };
    match key {
        NFT_XFRM_KEY_REQID => stored(regs.store_u32(dreg, state.reqid)),
        NFT_XFRM_KEY_SPI   => stored(regs.store_u32(dreg, state.spi)),
        // An address is only carried when the transform encapsulates; a
        // transport-mode transform has none of its own.
        NFT_XFRM_KEY_DADDR_IP4 | NFT_XFRM_KEY_SADDR_IP4 => {
            if !state.tunnel_mode || state.family == NFPROTO_IPV6 { return BREAK; }
            let a = if key == NFT_XFRM_KEY_SADDR_IP4 { state.saddr } else { state.daddr };
            stored(regs.store(dreg, &a[..4]))
        }
        NFT_XFRM_KEY_DADDR_IP6 | NFT_XFRM_KEY_SADDR_IP6 => {
            if !state.tunnel_mode || state.family != NFPROTO_IPV6 { return BREAK; }
            let a = if key == NFT_XFRM_KEY_SADDR_IP6 { state.saddr } else { state.daddr };
            stored(regs.store(dreg, &a))
        }
        _ => BREAK,
    }
}

/// # C: O(1)
pub fn tunnel(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32, mode: u32) -> Option<i32> {
    let Some(meta) = ctx.tunnel else { return BREAK };
    match key {
        NFT_TUNNEL_PATH => stored(regs.store_u8(dreg, meta.present(mode) as u8)),
        NFT_TUNNEL_ID => match meta.id(mode) {
            Some(id) => stored(regs.store_u32(dreg, id)), None => BREAK },
        _ => BREAK,
    }
}

/// Length of the TCP option starting at `at`, honouring the single-byte
/// no-operation and end-of-list kinds. # C: O(1)
pub fn tcp_optlen(opt: &[u8], at: usize) -> usize {
    match opt.get(at) {
        Some(&TCPOPT_NOP) | Some(&TCPOPT_EOL) => 1,
        _ => opt.get(at + 1).copied().unwrap_or(1).max(1) as usize,
    }
}

/// Offset and length of one TCP option within a TCP header. # C: O(N options)
pub fn find_tcp_option(header: &[u8], kind: u8) -> Option<(usize, usize)> {
    let mut at = TCP_MIN_HDR;
    while at + 1 < header.len() {
        if header[at] == TCPOPT_EOL { return None; }
        let optlen = tcp_optlen(header, at);
        if header[at] == kind {
            if at + optlen > header.len() { return None; }
            return Some((at, optlen));
        }
        at += optlen;
    }
    None
}

/// Offset and length of one IPv6 extension header. # C: O(N headers)
pub fn find_ipv6_exthdr(pkt: &[u8], want: u8) -> Option<(usize, usize)> {
    let mut next = *pkt.get(6)?;
    let mut at = IPV6_FIXED_HDR;
    for _ in 0..8 {
        if next == want { return Some((at, (*pkt.get(at + 1)? as usize + 1) * 8)); }
        if !matches!(next, 0 | 43 | 60) { return None; }
        let len = (*pkt.get(at + 1)? as usize + 1) * 8;
        next = *pkt.get(at)?;
        at += len;
    }
    None
}

/// Offset and length of one IPv4 option. Only the options the reference
/// reports are matched; the rest are skipped over. # C: O(N options)
pub fn find_ipv4_option(pkt: &[u8], want: u8) -> Option<(usize, usize)> {
    if !matches!(want, IPOPT_LSRR | IPOPT_SSRR | IPOPT_RR | IPOPT_RA) { return None; }
    let ihl = (*pkt.first()? & 0x0f) as usize * 4;
    let mut at = 20;
    while at + 1 < ihl.min(pkt.len()) {
        let kind = pkt[at];
        if kind == 0 { return None; }
        if kind == 1 { at += 1; continue; }
        let len = pkt[at + 1] as usize;
        if len < 2 || at + len > ihl { return None; }
        if kind == want { return Some((at, len)); }
        at += len;
    }
    None
}

/// Offset and length of one SCTP chunk. Chunk lengths are padded to a word.
/// # C: O(N chunks)
pub fn find_sctp_chunk(body: &[u8], want: u8) -> Option<(usize, usize)> {
    let mut at = 12;
    while at + 4 <= body.len() {
        let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        if len < 4 { return None; }
        if body[at] == want { return Some((at, len)); }
        at += (len + 3) & !3;
    }
    None
}

/// # C: O(N options)
#[allow(clippy::too_many_arguments)]
pub fn exthdr(ctx: &mut EvalCtx, regs: &mut Regs, dreg: Option<u32>, sreg: Option<u32>,
              op: u32, htype: u8, offset: u32, len: u32, flags: u32) -> Option<i32>
{
    let present_only = flags & NFT_EXTHDR_F_PRESENT != 0;
    if let Some(sreg) = sreg {
        let Some(data) = regs.load(sreg, len as usize) else { return BREAK };
        let data = data.to_vec();
        ctx.actions.push(Action::ExthdrSet { op, htype, offset, data });
        return None;
    }
    let Some(dreg) = dreg else {
        ctx.actions.push(Action::ExthdrStrip { op, htype });
        return None;
    };
    let found = match op {
        NFT_EXTHDR_OP_IPV6 => {
            if ctx.family != NFPROTO_IPV6 { return BREAK; }
            find_ipv6_exthdr(ctx.pkt, htype).map(|(at, optlen)| (ctx.pkt, at, optlen))
        }
        NFT_EXTHDR_OP_IPV4 => {
            if ctx.family == NFPROTO_IPV6 { return BREAK; }
            find_ipv4_option(ctx.pkt, htype).map(|(at, optlen)| (ctx.pkt, at, optlen))
        }
        NFT_EXTHDR_OP_TCPOPT => {
            let Some((header, _)) = tcp_header(ctx) else { return BREAK };
            find_tcp_option(header, htype).map(|(at, optlen)| (header, at, optlen))
        }
        NFT_EXTHDR_OP_SCTP => {
            if l4proto(ctx) != Some(IPPROTO_SCTP) { return BREAK; }
            let Some(thoff) = transport_offset(ctx) else { return BREAK };
            let Some(body) = ctx.pkt.get(thoff..) else { return BREAK };
            find_sctp_chunk(body, htype).map(|(at, optlen)| (body, at, optlen))
        }
        NFT_EXTHDR_OP_DCCP => {
            // The reference reports presence only, and an absent option is a
            // zero rather than a reason to stop the rule.
            if l4proto(ctx) != Some(IPPROTO_DCCP) { return BREAK; }
            return stored(regs.store_u8(dreg, 0));
        }
        _ => return BREAK,
    };
    let Some((buf, at, optlen)) = found else {
        if present_only { return stored(regs.store_u8(dreg, 0)); }
        return BREAK;
    };
    if present_only { return stored(regs.store_u8(dreg, 1)); }
    let start = at + offset as usize;
    if offset as usize + len as usize > optlen { return BREAK; }
    let Some(bytes) = buf.get(start..start + len as usize) else { return BREAK };
    let mut padded = [0u8; NFT_DATA_VALUE_MAXLEN];
    padded[..bytes.len()].copy_from_slice(bytes);
    stored(regs.store_padded(dreg, &padded[..bytes.len()]))
}

//! Header geometry the packet-reading expressions share.

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::limits::{IPPROTO_TCP, IPV6_FIXED_HDR, TCP_MIN_HDR};
use crate::nft_expr::uapi::{NFPROTO_IPV6, NFT_PAYLOAD_INNER_HEADER, NFT_PAYLOAD_LL_HEADER,
                            NFT_PAYLOAD_NETWORK_HEADER, NFT_PAYLOAD_TRANSPORT_HEADER};

/// IPv4 version nibble. # C: O(1)
const IP_VERSION_4: u8 = 4;

/// Byte offset of the transport header inside the network-layer packet, or
/// `None` when the header cannot be located — a truncated packet, an
/// unexpected version, or a non-initial fragment whose transport header is
/// simply not present.
/// # C: O(1)
pub fn transport_offset(ctx: &EvalCtx) -> Option<usize> {
    if ctx.meta.fragoff != 0 { return None; }
    if ctx.pkt.is_empty() { return None; }
    match ctx.family {
        NFPROTO_IPV6 => Some(IPV6_FIXED_HDR),
        _ => {
            if ctx.pkt[0] >> 4 != IP_VERSION_4 { return None; }
            let ihl = (ctx.pkt[0] & 0x0f) as usize * 4;
            if ihl < 20 { return None; }
            Some(ihl)
        }
    }
}

/// L4 protocol the packet carries. The context wins when it names one,
/// because a hook that already parsed the packet knows about tunnelling the
/// header bytes do not show. # C: O(1)
pub fn l4proto(ctx: &EvalCtx) -> Option<u8> {
    if let Some(proto) = ctx.meta.l4proto { return Some(proto); }
    match ctx.family {
        NFPROTO_IPV6 => ctx.pkt.get(6).copied(),
        _ => {
            if ctx.pkt.first().map(|b| b >> 4) != Some(IP_VERSION_4) { return None; }
            ctx.pkt.get(9).copied()
        }
    }
}

/// Slice one payload base resolves to, with the offset the base starts at.
/// # C: O(1)
pub fn base_slice<'a>(ctx: &'a EvalCtx<'a>, base: u32) -> Option<&'a [u8]> {
    match base {
        NFT_PAYLOAD_LL_HEADER => (!ctx.ll.is_empty()).then_some(ctx.ll),
        NFT_PAYLOAD_NETWORK_HEADER => Some(ctx.pkt),
        NFT_PAYLOAD_TRANSPORT_HEADER => {
            // A transport header only exists once the L4 protocol is known and
            // the packet is not a later fragment.
            l4proto(ctx)?;
            let off = transport_offset(ctx)?;
            ctx.pkt.get(off..)
        }
        NFT_PAYLOAD_INNER_HEADER => (!ctx.inner.is_empty()).then_some(ctx.inner),
        _ => None,
    }
}

/// TCP header and its length, when the packet carries a complete one.
/// # C: O(1)
pub fn tcp_header<'a>(ctx: &'a EvalCtx<'a>) -> Option<(&'a [u8], usize)> {
    if l4proto(ctx)? != IPPROTO_TCP { return None; }
    let off = transport_offset(ctx)?;
    let tcp = ctx.pkt.get(off..)?;
    if tcp.len() < TCP_MIN_HDR { return None; }
    let hdr_len = (tcp[12] >> 4) as usize * 4;
    if hdr_len < TCP_MIN_HDR || tcp.len() < hdr_len { return None; }
    Some((&tcp[..hdr_len], hdr_len))
}

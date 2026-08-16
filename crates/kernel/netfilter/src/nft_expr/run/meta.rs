//! Evaluation of the `meta` key set, both directions.

use crate::nft_expr::ctx::{EvalCtx, IfInfo};
use crate::nft_expr::limits::{ETH_ALEN, IFNAMSIZ};
use crate::nft_expr::regs::Regs;
use crate::nft_expr::run::packet::l4proto;
use crate::nft_expr::uapi::*;

const BREAK: Option<i32> = Some(NFT_BREAK);

/// # C: O(1)
fn stored(result: Option<()>) -> Option<i32> { if result.is_some() { None } else { BREAK } }

/// # C: O(1)
fn iface(info: Option<IfInfo>) -> Option<IfInfo> { info }

/// # C: O(len)
fn store_name(regs: &mut Regs, dreg: u32, name: &[u8; IFNAMSIZ]) -> Option<i32> {
    stored(regs.store(dreg, name))
}

/// Read one meta key into `dreg`. A key whose source the context does not
/// carry breaks the rule rather than reporting a made-up value.
/// # C: O(1)
pub fn get(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32) -> Option<i32> {
    match key {
        NFT_META_LEN       => stored(regs.store_u32(dreg, ctx.pkt_len())),
        NFT_META_PROTOCOL  => match ctx.meta.protocol {
            Some(p) => stored(regs.store_be16(dreg, p)), None => BREAK },
        NFT_META_NFPROTO   => stored(regs.store_u8(dreg, ctx.family)),
        NFT_META_L4PROTO   => match l4proto(ctx) {
            Some(p) => stored(regs.store_u8(dreg, p)), None => BREAK },
        NFT_META_PRIORITY  => stored(regs.store_u32(dreg, ctx.meta.priority)),
        NFT_META_MARK      => stored(regs.store_u32(dreg, ctx.mark)),
        NFT_META_SECMARK   => stored(regs.store_u32(dreg, ctx.meta.secmark)),
        NFT_META_NFTRACE   => stored(regs.store_u8(dreg, ctx.meta.nftrace as u8)),
        NFT_META_CPU       => stored(regs.store_u32(dreg, ctx.cpu)),
        NFT_META_PRANDOM   => stored(regs.store_u32(dreg, ctx.meta.prandom)),
        NFT_META_SECPATH   => stored(regs.store_u8(dreg, ctx.meta.secpath as u8)),

        NFT_META_IIF       => match iface(ctx.meta.iif) {
            Some(i) => stored(regs.store_u32(dreg, i.index)), None => BREAK },
        NFT_META_OIF       => match iface(ctx.meta.oif) {
            Some(i) => stored(regs.store_u32(dreg, i.index)), None => BREAK },
        NFT_META_SDIF      => match iface(ctx.meta.sdif) {
            Some(i) => stored(regs.store_u32(dreg, i.index)), None => BREAK },
        NFT_META_IIFNAME   => match iface(ctx.meta.iif) {
            Some(i) => store_name(regs, dreg, &i.name), None => BREAK },
        NFT_META_OIFNAME   => match iface(ctx.meta.oif) {
            Some(i) => store_name(regs, dreg, &i.name), None => BREAK },
        NFT_META_SDIFNAME  => match iface(ctx.meta.sdif) {
            Some(i) => store_name(regs, dreg, &i.name), None => BREAK },
        NFT_META_IIFKIND   => match iface(ctx.meta.iif) {
            Some(i) => store_name(regs, dreg, &i.kind), None => BREAK },
        NFT_META_OIFKIND   => match iface(ctx.meta.oif) {
            Some(i) => store_name(regs, dreg, &i.kind), None => BREAK },
        NFT_META_IIFTYPE   => match iface(ctx.meta.iif) {
            Some(i) => stored(regs.store_u16(dreg, i.iftype)), None => BREAK },
        NFT_META_OIFTYPE   => match iface(ctx.meta.oif) {
            Some(i) => stored(regs.store_u16(dreg, i.iftype)), None => BREAK },
        NFT_META_IIFGROUP  => match iface(ctx.meta.iif) {
            Some(i) => stored(regs.store_u32(dreg, i.group)), None => BREAK },
        NFT_META_OIFGROUP  => match iface(ctx.meta.oif) {
            Some(i) => stored(regs.store_u32(dreg, i.group)), None => BREAK },

        NFT_META_BRI_IIFNAME => match iface(ctx.meta.bri_iif) {
            Some(i) => store_name(regs, dreg, &i.name), None => BREAK },
        NFT_META_BRI_OIFNAME => match iface(ctx.meta.bri_oif) {
            Some(i) => store_name(regs, dreg, &i.name), None => BREAK },
        NFT_META_BRI_IIFPVID => match ctx.meta.bri_iif_pvid {
            Some(v) => stored(regs.store_u16(dreg, v)), None => BREAK },
        NFT_META_BRI_IIFVPROTO => match ctx.meta.bri_iif_vproto {
            Some(v) => stored(regs.store_be16(dreg, v)), None => BREAK },
        NFT_META_BRI_BROUTE  => match ctx.meta.bri_broute {
            Some(v) => stored(regs.store_u8(dreg, v)), None => BREAK },
        NFT_META_BRI_IIFHWADDR => match ctx.meta.bri_iif_hwaddr {
            Some(a) => stored(regs.store(dreg, &a[..ETH_ALEN])), None => BREAK },

        NFT_META_SKUID     => match ctx.meta.skuid {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },
        NFT_META_SKGID     => match ctx.meta.skgid {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },
        NFT_META_RTCLASSID => match ctx.meta.rtclassid {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },
        NFT_META_CGROUP    => match ctx.meta.cgroup {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },

        NFT_META_TIME_NS   => match ctx.meta.time_ns {
            Some(v) => stored(regs.store_u64(dreg, v)), None => BREAK },
        NFT_META_TIME_DAY  => match ctx.meta.time_day {
            Some(v) => stored(regs.store_u8(dreg, v)), None => BREAK },
        NFT_META_TIME_HOUR => match ctx.meta.time_hour {
            Some(v) => stored(regs.store_u32(dreg, v)), None => BREAK },
        _ => BREAK,
    }
}

/// Write one meta key from `sreg`. Never sets a verdict; a key the packet
/// cannot accept is refused when the rule loads, not here. # C: O(1)
pub fn set(ctx: &mut EvalCtx, regs: &Regs, sreg: u32, key: u32) -> Option<i32> {
    match key {
        NFT_META_MARK     => { ctx.mark = regs.load_u32(sreg)?; }
        NFT_META_PRIORITY => { ctx.meta.priority = regs.load_u32(sreg)?; }
        NFT_META_SECMARK  => { ctx.meta.secmark = regs.load_u32(sreg)?; }
        NFT_META_NFTRACE  => { ctx.meta.nftrace = regs.load_u8(sreg)? != 0; }
        NFT_META_PKTTYPE  => {
            // A packet's delivery class may only be moved between classes the
            // link layer could have produced for it; anything else would
            // rewrite where the stack delivers the packet.
            let want = regs.load_u8(sreg)?;
            if pkttype_compatible(ctx.meta.pkttype, want) { ctx.meta.pkttype = Some(want); }
        }
        _ => return BREAK,
    }
    None
}

/// Delivery classes: to this host, to every host, to a group, to another
/// host. Only the multi-destination classes may be exchanged for one another.
pub const PACKET_HOST:      u8 = 0;
pub const PACKET_BROADCAST: u8 = 1;
pub const PACKET_MULTICAST: u8 = 2;
pub const PACKET_OTHERHOST: u8 = 3;

/// # C: O(1)
pub fn pkttype_compatible(current: Option<u8>, want: u8) -> bool {
    match current {
        Some(PACKET_MULTICAST) | Some(PACKET_BROADCAST) =>
            matches!(want, PACKET_HOST | PACKET_BROADCAST | PACKET_MULTICAST),
        Some(PACKET_OTHERHOST) => want == PACKET_HOST,
        Some(PACKET_HOST) => matches!(want, PACKET_HOST | PACKET_BROADCAST | PACKET_MULTICAST),
        _ => false,
    }
}

/// Read a key's value width, for the interpreter's bounds check. # C: O(1)
pub fn width(key: u32) -> Option<usize> {
    crate::nft_expr::parse::basic::meta_width(key)
}

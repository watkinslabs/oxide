//! Evaluation of the `ct` key set, both directions.

use conntrack::tuple::Tuple;
use conntrack::uapi::{IP_CT_DIR_MAX, IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_IS_REPLY,
                      IP_CT_UNTRACKED, IPCT_LABEL, IPCT_MARK, IPCT_SECMARK, NFPROTO_IPV6};

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::limits::{NF_CT_HELPER_NAME_LEN, NF_CT_LABELS_MAX_SIZE};
use crate::nft_expr::regs::Regs;
use crate::nft_expr::uapi::*;

const BREAK: Option<i32> = Some(NFT_BREAK);

/// # C: O(1)
fn stored(result: Option<()>) -> Option<i32> { if result.is_some() { None } else { BREAK } }

/// State bit for one packet. A packet with no entry is invalid unless the
/// ruleset deliberately exempted it from tracking, which is a state of its
/// own and must not read as any tracked state. # C: O(1)
pub fn state_bit(attached: bool, ctinfo: u8) -> u32 {
    if attached { return 1 << (ctinfo % IP_CT_IS_REPLY + 1); }
    if ctinfo == IP_CT_UNTRACKED { NF_CT_STATE_UNTRACKED_BIT } else { NF_CT_STATE_INVALID_BIT }
}

/// Direction a key reads: the one the rule named, or the packet's own.
/// # C: O(1)
fn key_dir(dir: Option<u8>, ctinfo: u8) -> u8 {
    dir.unwrap_or_else(|| conntrack::uapi::ctinfo2dir(ctinfo))
}

/// Address bytes of one tuple end. # C: O(1)
fn tuple_addr(tuple: &Tuple, src: bool) -> &[u8] {
    let end = if src { &tuple.src } else { &tuple.dst };
    end.addr.words(tuple.l3num)
}

/// # C: O(1)
fn tuple_port(tuple: &Tuple, src: bool) -> u16 {
    if src { tuple.src.proto.port } else { tuple.dst.proto.port }
}

/// # C: O(len)
pub fn get(ctx: &EvalCtx, regs: &mut Regs, dreg: u32, key: u32, dir: Option<u8>, len: u32)
    -> Option<i32>
{
    let Some(ct) = ctx.ct else { return BREAK };
    let ctinfo = ct.ctinfo();
    if key == NFT_CT_STATE {
        return stored(regs.store_u32(dreg, state_bit(ct.attached(), ctinfo)));
    }
    // Every other key reads the entry itself, and a template carries none of
    // the per-flow state those keys report.
    if !ct.attached() || ct.template() { return BREAK; }
    let dir_used = key_dir(dir, ctinfo);
    match key {
        NFT_CT_DIRECTION  => stored(regs.store_u8(dreg, conntrack::uapi::ctinfo2dir(ctinfo))),
        NFT_CT_STATUS     => stored(regs.store_u32(dreg, ct.status())),
        NFT_CT_MARK       => stored(regs.store_u32(dreg, ct.mark())),
        NFT_CT_SECMARK    => stored(regs.store_u32(dreg, ct.secmark())),
        NFT_CT_EXPIRATION => stored(regs.store_u32(dreg, ct.expiration_ms())),
        NFT_CT_ID         => stored(regs.store_u32(dreg, ct.id())),
        NFT_CT_ZONE       => stored(regs.store_u16(dreg, ct.zone())),
        NFT_CT_EVENTMASK  => stored(regs.store_u32(dreg, ct.eventmask())),
        NFT_CT_HELPER => {
            let mut name = [0u8; NF_CT_HELPER_NAME_LEN];
            if !ct.helper(&mut name) { return BREAK; }
            stored(regs.store(dreg, &name))
        }
        NFT_CT_LABELS => {
            // An entry with no labels reads as all-zero rather than breaking,
            // so a rule can test for the absence of a label.
            let mut labels = [0u8; NF_CT_LABELS_MAX_SIZE];
            ct.labels(&mut labels);
            stored(regs.store(dreg, &labels))
        }
        NFT_CT_PKTS | NFT_CT_BYTES | NFT_CT_AVGPKT => {
            let (mut pkts, mut bytes) = (0u64, 0u64);
            const BOTH: [u8; IP_CT_DIR_MAX] = [IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY];
            let dirs: &[u8] = match dir {
                Some(d) if (d as usize) < IP_CT_DIR_MAX => &BOTH[d as usize..d as usize + 1],
                _ => &BOTH,
            };
            for &d in dirs {
                if (d as usize) >= IP_CT_DIR_MAX { continue; }
                let (p, b) = ct.counters(d);
                pkts += p; bytes += b;
            }
            let value = match key {
                NFT_CT_PKTS => pkts,
                NFT_CT_BYTES => bytes,
                _ => if pkts == 0 { 0 } else { bytes / pkts },
            };
            stored(regs.store_u64(dreg, value))
        }
        _ => {
            let Some(tuple) = ct.tuple(dir_used) else { return BREAK };
            match key {
                NFT_CT_L3PROTOCOL => stored(regs.store_u8(dreg, tuple.l3num)),
                NFT_CT_PROTOCOL   => stored(regs.store_u8(dreg, tuple.protonum)),
                NFT_CT_PROTO_SRC  => stored(regs.store_be16(dreg, tuple_port(&tuple, true))),
                NFT_CT_PROTO_DST  => stored(regs.store_be16(dreg, tuple_port(&tuple, false))),
                NFT_CT_SRC | NFT_CT_DST => {
                    let bytes = tuple_addr(&tuple, key == NFT_CT_SRC);
                    if bytes.len() != len as usize { return BREAK; }
                    stored(regs.store(dreg, bytes))
                }
                NFT_CT_SRC_IP | NFT_CT_DST_IP => {
                    if tuple.l3num == NFPROTO_IPV6 { return BREAK; }
                    let end = if key == NFT_CT_SRC_IP { tuple.src } else { tuple.dst };
                    stored(regs.store(dreg, &end.addr.0[..4]))
                }
                NFT_CT_SRC_IP6 | NFT_CT_DST_IP6 => {
                    if tuple.l3num != NFPROTO_IPV6 { return BREAK; }
                    let end = if key == NFT_CT_SRC_IP6 { tuple.src } else { tuple.dst };
                    stored(regs.store(dreg, &end.addr.0))
                }
                _ => BREAK,
            }
        }
    }
}

/// Write one conntrack key. A packet with no entry is a silent no-op — the
/// reference never turns a failed set into a verdict. # C: O(len)
pub fn set(ctx: &EvalCtx, regs: &Regs, sreg: u32, key: u32, len: u32) -> Option<i32> {
    let Some(ct) = ctx.ct else { return None };
    match key {
        NFT_CT_ZONE => {
            // A zone may be attached before any entry exists: that is how a
            // rule places a packet in a zone before tracking happens.
            if let Some(zone) = regs.load(sreg, 2)
                .map(|b| u16::from_ne_bytes([b[0], b[1]])) { ct.set_zone(zone); }
            return None;
        }
        _ => if !ct.attached() { return None; },
    }
    match key {
        NFT_CT_MARK => {
            let Some(value) = regs.load_u32(sreg) else { return None };
            if ct.mark() != value { ct.set_mark(value); ct.set_eventmask(IPCT_MARK); }
        }
        NFT_CT_SECMARK => {
            let Some(value) = regs.load_u32(sreg) else { return None };
            if ct.secmark() != value { ct.set_secmark(value); ct.set_eventmask(IPCT_SECMARK); }
        }
        NFT_CT_LABELS => {
            let Some(value) = regs.load(sreg, len as usize) else { return None };
            ct.set_labels(value);
            ct.set_eventmask(IPCT_LABEL);
        }
        NFT_CT_EVENTMASK => {
            let Some(value) = regs.load_u32(sreg) else { return None };
            ct.set_eventmask(value);
        }
        _ => {}
    }
    None
}

/// Direction a `ct` key defaults to when the rule names none. # C: O(1)
pub const fn default_dir() -> u8 { IP_CT_DIR_ORIGINAL }

//! nftables rule-expression interpreter (Linux nft_expr.h).
//!
//! `NFTA_RULE_EXPRESSIONS` is a list of nested `NFTA_LIST_ELEM`
//! attrs, each carrying one expression. An expression is itself a
//! pair of nested attrs: `NFTA_EXPR_NAME` (the kind, e.g. "cmp")
//! and `NFTA_EXPR_DATA` (kind-specific TLVs).
//!
//! v1 supports the three primitives that suffice to filter on
//! header bytes — enough to express "drop traffic where src IP ==
//! X" or "accept on dst port 22":
//!   - `payload` — copy `len` bytes from packet base+offset into
//!     destination register
//!   - `cmp` — compare source register against a literal, op
//!     EQ/NEQ; non-match aborts the rule
//!   - `immediate` — load a literal into a register; when target
//!     is `NFT_REG_VERDICT` the rule's verdict is the loaded value
//!
//! Counter / set lookup / connection tracking ride follow-up PRs.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;

// --- expression-attr constants (Linux nft_expr.h) ---

pub const NFTA_LIST_ELEM:     u16 = 1;

pub const NFTA_EXPR_NAME:     u16 = 1;
pub const NFTA_EXPR_DATA:     u16 = 2;

pub const NFTA_PAYLOAD_DREG:   u16 = 1;
pub const NFTA_PAYLOAD_BASE:   u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN:    u16 = 4;

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP:   u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN:  u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR:  u16 = 5;

pub const NFTA_COUNTER_BYTES:   u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;

pub const NFTA_LOOKUP_SET:   u16 = 1;
pub const NFTA_LOOKUP_SREG:  u16 = 2;
pub const NFTA_LOOKUP_DREG:  u16 = 3;
pub const NFTA_LOOKUP_FLAGS: u16 = 4;

pub const NFT_LOOKUP_F_INV: u32 = 1;

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY:  u16 = 2;
pub const NFTA_META_SREG: u16 = 3;

// nft_meta_keys (Linux nf_tables.h)
pub const NFT_META_LEN:     u32 = 0;
pub const NFT_META_NFPROTO: u32 = 15;
pub const NFT_META_L4PROTO: u32 = 16;

pub const NFPROTO_IPV4: u8 = 2;

pub const NFTA_DATA_VALUE:   u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;

pub const NFTA_VERDICT_CODE: u16 = 1;

// nf_tables payload base
pub const NFT_PAYLOAD_LL_HEADER:        u32 = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER:   u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// cmp op
pub const NFT_CMP_EQ:  u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;

// Linux verdict codes carried in NFT_DATA_VERDICT. The
// "continue" code is encoded as -1 and means "fall through to
// the next rule"; absolute verdicts are the standard NF_* values.
pub const NF_DROP:   i32 = 0;
pub const NF_ACCEPT: i32 = 1;

// Register layout: 5 × 16-byte slots. reg 0 is verdict-only and
// not addressable as a payload destination here.
const REG_BYTES: usize = 80;

fn reg_off(r: u32) -> Option<usize> {
    // Legacy NFT_REG_1..4 = 1..4 (16-byte slots starting at 16).
    // 4-byte NFT_REG32_00..15 = 8..23 (4-byte slots starting at 16).
    if r >= 1 && r <= 4 { return Some((r as usize) * 16); }
    if r >= 8 && r <= 23 { return Some(16 + (r as usize - 8) * 4); }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Payload   { dreg: u32, base: u32, offset: u32, len: u32 },
    Cmp       { sreg: u32, op: u32, data: Vec<u8> },
    Immediate { dreg: u32, verdict: Option<i32>, value: Vec<u8> },
    Meta      { dreg: u32, key: u32 },
    Lookup    { sreg: u32, set: String, invert: bool },
    Counter,
    Bitwise { sreg: u32, dreg: u32, mask: Vec<u8>, xor: Vec<u8> },
}

/// Parse a `NFTA_RULE_EXPRESSIONS` payload into a list of
/// expressions. Unknown expressions are skipped (Linux's
/// `nft_match_init` would EOPNOTSUPP, but this v1 keeps the rule
/// running so a future PR can land more expression types without
/// breaking already-loaded rulesets).
/// # C: O(len(payload))
pub fn parse_exprs(payload: &[u8]) -> Vec<Expr> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= payload.len() {
        let nla_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > payload.len() { break; }
        let body = &payload[off + 4 .. off + nla_len];
        if mask_nla(nla_type) == NFTA_LIST_ELEM {
            if let Some(e) = parse_one_expr(body) { out.push(e); }
        }
        off += align4(nla_len);
    }
    out
}

fn mask_nla(t: u16) -> u16 { t & 0x3fff }
fn align4(n: usize) -> usize { (n + 3) & !3 }

fn parse_one_expr(body: &[u8]) -> Option<Expr> {
    let name = find_str(body, NFTA_EXPR_NAME)?;
    let data = find_bytes(body, NFTA_EXPR_DATA)?;
    match name {
        "payload"   => parse_payload(data),
        "cmp"       => parse_cmp(data),
        "immediate" => parse_immediate(data),
        "meta"      => parse_meta(data),
        "lookup"    => parse_lookup(data),
        "counter"   => Some(Expr::Counter),
        "bitwise"   => parse_bitwise(data),
        _ => None,
    }
}

fn parse_payload(d: &[u8]) -> Option<Expr> {
    Some(Expr::Payload {
        dreg:   find_u32_be(d, NFTA_PAYLOAD_DREG)?,
        base:   find_u32_be(d, NFTA_PAYLOAD_BASE)?,
        offset: find_u32_be(d, NFTA_PAYLOAD_OFFSET)?,
        len:    find_u32_be(d, NFTA_PAYLOAD_LEN)?,
    })
}

fn parse_cmp(d: &[u8]) -> Option<Expr> {
    let sreg = find_u32_be(d, NFTA_CMP_SREG)?;
    let op   = find_u32_be(d, NFTA_CMP_OP)?;
    let dn   = find_bytes(d, NFTA_CMP_DATA)?;
    let data = find_bytes(dn, NFTA_DATA_VALUE)?.to_vec();
    Some(Expr::Cmp { sreg, op, data })
}

fn parse_bitwise(d: &[u8]) -> Option<Expr> {
    let sreg = find_u32_be(d, NFTA_BITWISE_SREG)?;
    let dreg = find_u32_be(d, NFTA_BITWISE_DREG)?;
    let mask_n = find_bytes(d, NFTA_BITWISE_MASK)?;
    let xor_n  = find_bytes(d, NFTA_BITWISE_XOR)?;
    // Each is a nested attr with NFTA_DATA_VALUE inside.
    let mask = find_bytes(mask_n, NFTA_DATA_VALUE)?.to_vec();
    let xor  = find_bytes(xor_n,  NFTA_DATA_VALUE)?.to_vec();
    if mask.len() != xor.len() { return None; }
    Some(Expr::Bitwise { sreg, dreg, mask, xor })
}

fn parse_lookup(d: &[u8]) -> Option<Expr> {
    let set  = find_str(d, NFTA_LOOKUP_SET)?;
    let sreg = find_u32_be(d, NFTA_LOOKUP_SREG)?;
    let flags = find_u32_be(d, NFTA_LOOKUP_FLAGS).unwrap_or(0);
    let invert = (flags & NFT_LOOKUP_F_INV) != 0;
    Some(Expr::Lookup {
        sreg,
        set: String::from(set),
        invert,
    })
}

fn parse_meta(d: &[u8]) -> Option<Expr> {
    let dreg = find_u32_be(d, NFTA_META_DREG)?;
    let key  = find_u32_be(d, NFTA_META_KEY)?;
    Some(Expr::Meta { dreg, key })
}

fn parse_immediate(d: &[u8]) -> Option<Expr> {
    let dreg = find_u32_be(d, NFTA_IMMEDIATE_DREG)?;
    let data = find_bytes(d, NFTA_IMMEDIATE_DATA)?;
    let verdict = find_bytes(data, NFTA_DATA_VERDICT)
        .and_then(|v| find_u32_be(v, NFTA_VERDICT_CODE))
        .map(|c| c as i32);
    let value = find_bytes(data, NFTA_DATA_VALUE)
        .map(|s| s.to_vec()).unwrap_or_default();
    Some(Expr::Immediate { dreg, verdict, value })
}

fn find_str<'a>(attrs: &'a [u8], target: u16) -> Option<&'a str> {
    let bytes = find_bytes(attrs, target)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

fn find_bytes<'a>(attrs: &'a [u8], target: u16) -> Option<&'a [u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if mask_nla(nla_type) == target {
            return Some(&attrs[off + 4 .. off + nla_len]);
        }
        off += align4(nla_len);
    }
    None
}

fn find_u32_be(attrs: &[u8], target: u16) -> Option<u32> {
    let b = find_bytes(attrs, target)?;
    if b.len() < 4 { return None; }
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Set-lookup callback. `set_name` + `key` → optional data
/// payload. Caller resolves family/table — that context is per-
/// rule and stays out of the interpreter. The `key_len` parameter
/// tells the closure how many bytes to read from the source reg
/// (closures own set-shape knowledge).
pub type SetLookupFn<'a> = &'a dyn Fn(&str, &[u8]) -> Option<Vec<u8>>;

/// Thin wrapper around `run_rule_with_lookup` for rules that
/// don't reference sets.
/// # C: O(N_exprs · max_len)
pub fn run_rule(exprs: &[Expr], pkt: &[u8]) -> Option<i32> {
    run_rule_with_lookup(exprs, pkt, None)
}

/// Walk a parsed expression list against `pkt`. Returns:
///   - `Some(NF_DROP)` / `Some(NF_ACCEPT)` when an immediate sets
///     the verdict register
///   - `None` when no immediate fired (let chain policy decide) or
///     a cmp aborted the rule
/// `lookup` is invoked when a rule contains an Expr::Lookup; pass
/// `None` if the caller doesn't model sets.
/// # C: O(N_exprs · max_len) per rule
pub fn run_rule_with_lookup(exprs: &[Expr], pkt: &[u8], lookup: Option<SetLookupFn>) -> Option<i32> {
    let mut visits = 0u64;
    let mut bytes  = 0u64;
    run_rule_full(exprs, pkt, lookup, &mut visits, &mut bytes)
}

/// Same as `run_rule_with_lookup` but also accumulates counter
/// stats: every Counter expression the run path reaches bumps
/// `*packets += 1` and `*bytes += pkt.len()`. Cmp-aborted rules
/// don't reach later Counter exprs (positional semantics match
/// Linux's nft_counter).
/// # C: O(N_exprs · max_len)
pub fn run_rule_full(exprs: &[Expr], pkt: &[u8],
                     lookup: Option<SetLookupFn>,
                     packets: &mut u64, bytes: &mut u64) -> Option<i32> {
    let mut regs = vec![0u8; REG_BYTES];
    for e in exprs {
        match e {
            Expr::Payload { dreg, base, offset, len } => {
                let base_off: usize = match *base {
                    NFT_PAYLOAD_NETWORK_HEADER => 0,
                    NFT_PAYLOAD_TRANSPORT_HEADER => {
                        // IPv4 IHL → byte offset to L4. Only IPv4
                        // for now; IPv6 lands when v6 stack does.
                        if pkt.is_empty() || (pkt[0] >> 4) != 4 { return None; }
                        ((pkt[0] & 0x0f) as usize) * 4
                    }
                    _ => return None,
                };
                let off = base_off + *offset as usize;
                let l = *len as usize;
                if pkt.len() < off + l { return None; }
                let dst = reg_off(*dreg)?;
                if dst + l > regs.len() { return None; }
                regs[dst .. dst + l].copy_from_slice(&pkt[off .. off + l]);
            }
            Expr::Cmp { sreg, op, data } => {
                let src = reg_off(*sreg)?;
                if src + data.len() > regs.len() { return None; }
                let eq = &regs[src .. src + data.len()] == data.as_slice();
                let matched = match *op {
                    NFT_CMP_EQ  => eq,
                    NFT_CMP_NEQ => !eq,
                    _ => false,
                };
                if !matched { return None; }
            }
            Expr::Meta { dreg, key } => {
                let dst = reg_off(*dreg)?;
                match *key {
                    NFT_META_LEN => {
                        if dst + 4 > regs.len() { return None; }
                        regs[dst .. dst + 4].copy_from_slice(&(pkt.len() as u32).to_le_bytes());
                    }
                    NFT_META_NFPROTO => {
                        if dst + 1 > regs.len() { return None; }
                        regs[dst] = NFPROTO_IPV4;
                    }
                    NFT_META_L4PROTO => {
                        if pkt.len() < 10 { return None; }
                        if dst + 1 > regs.len() { return None; }
                        regs[dst] = pkt[9]; // IPv4 hdr.proto
                    }
                    _ => return None,
                }
            }
            Expr::Bitwise { sreg, dreg, mask, xor } => {
                let src = reg_off(*sreg)?;
                let dst = reg_off(*dreg)?;
                let l = mask.len();
                if src + l > regs.len() || dst + l > regs.len() { return None; }
                // Read first to handle aliasing (sreg == dreg).
                let mut tmp = Vec::with_capacity(l);
                for i in 0..l {
                    tmp.push((regs[src + i] & mask[i]) ^ xor[i]);
                }
                regs[dst .. dst + l].copy_from_slice(&tmp);
            }
            Expr::Counter => {
                *packets = packets.wrapping_add(1);
                *bytes   = bytes.wrapping_add(pkt.len() as u64);
            }
            Expr::Lookup { sreg, set, invert } => {
                let src = reg_off(*sreg)?;
                // Hand the closure a 16-byte register window (the
                // legacy register width); the closure inspects only
                // the prefix that matches its set's key_len.
                if src + 16 > regs.len() { return None; }
                let key = &regs[src .. src + 16];
                let hit = match lookup {
                    Some(f) => f(set.as_str(), key).is_some(),
                    None    => false,
                };
                let matched = hit ^ *invert;
                if !matched { return None; }
            }
            Expr::Immediate { dreg, verdict, value } => {
                if *dreg == 0 {
                    if let Some(v) = verdict {
                        if *v == NF_DROP || *v == NF_ACCEPT { return Some(*v); }
                    }
                    return None;
                }
                let dst = reg_off(*dreg)?;
                if dst + value.len() > regs.len() { return None; }
                regs[dst .. dst + value.len()].copy_from_slice(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
        let total = 4 + payload.len();
        buf.extend_from_slice(&(total as u16).to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(payload);
        while buf.len() % 4 != 0 { buf.push(0); }
    }

    fn nla_u32_be(buf: &mut Vec<u8>, ty: u16, v: u32) {
        nla(buf, ty, &v.to_be_bytes());
    }

    fn nla_str(buf: &mut Vec<u8>, ty: u16, s: &str) {
        let mut p = s.as_bytes().to_vec();
        p.push(0);
        nla(buf, ty, &p);
    }

    fn nla_nested(buf: &mut Vec<u8>, ty: u16, inner: &[u8]) {
        nla(buf, ty | 0x8000, inner);
    }

    fn build_immediate_drop() -> Vec<u8> {
        // NFTA_LIST_ELEM { NFTA_EXPR_NAME="immediate", NFTA_EXPR_DATA{ ... } }
        let mut verdict = Vec::new();
        nla_u32_be(&mut verdict, NFTA_VERDICT_CODE, NF_DROP as u32);
        let mut data = Vec::new();
        nla_nested(&mut data, NFTA_DATA_VERDICT, &verdict);
        let mut idata = Vec::new();
        nla_u32_be(&mut idata, NFTA_IMMEDIATE_DREG, 0); // VERDICT
        nla_nested(&mut idata, NFTA_IMMEDIATE_DATA, &data);
        let mut expr = Vec::new();
        nla_str(&mut expr, NFTA_EXPR_NAME, "immediate");
        nla_nested(&mut expr, NFTA_EXPR_DATA, &idata);
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &expr);
        out
    }

    #[test]
    fn parse_immediate_drop_round_trip() {
        let bytes = build_immediate_drop();
        let exprs = parse_exprs(&bytes);
        assert_eq!(exprs.len(), 1);
        assert!(matches!(exprs[0], Expr::Immediate { dreg: 0, verdict: Some(0), .. }));
    }

    #[test]
    fn run_immediate_drop_returns_drop() {
        let bytes = build_immediate_drop();
        let exprs = parse_exprs(&bytes);
        assert_eq!(run_rule(&exprs, &[]), Some(NF_DROP));
    }

    fn build_payload_cmp_drop_for_src_ipv4(src: [u8; 4]) -> Vec<u8> {
        // payload (NETWORK, offset 12, len 4) -> reg 1
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut payload_expr = Vec::new();
        nla_str(&mut payload_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut payload_expr, NFTA_EXPR_DATA, &pdata);

        // cmp (EQ, reg 1, src)
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &src);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut cmp_expr = Vec::new();
        nla_str(&mut cmp_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut cmp_expr, NFTA_EXPR_DATA, &cdata);

        // immediate drop
        let imm = build_immediate_drop();
        // imm wraps a single LIST_ELEM already — strip it: extract
        // the LIST_ELEM body. Simpler: rebuild flat list.

        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &payload_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &cmp_expr);
        out.extend_from_slice(&imm); // already a LIST_ELEM wrap
        out
    }

    fn ipv4_pkt_with_src(src: [u8; 4]) -> Vec<u8> {
        // 20-byte IPv4 header: src is at offset 12..16.
        let mut p = vec![0u8; 20];
        p[12..16].copy_from_slice(&src);
        p
    }

    #[test]
    fn drop_when_src_matches() {
        let rule = build_payload_cmp_drop_for_src_ipv4([10, 0, 0, 5]);
        let exprs = parse_exprs(&rule);
        assert_eq!(exprs.len(), 3);
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule(&exprs, &pkt), Some(NF_DROP));
    }

    #[test]
    fn skip_when_src_doesnt_match() {
        let rule = build_payload_cmp_drop_for_src_ipv4([10, 0, 0, 5]);
        let exprs = parse_exprs(&rule);
        let pkt = ipv4_pkt_with_src([10, 0, 0, 6]);
        assert_eq!(run_rule(&exprs, &pkt), None);
    }

    fn build_meta_l4proto_drop_match(want: u8) -> Vec<u8> {
        // meta l4proto -> reg1
        let mut mdata = Vec::new();
        nla_u32_be(&mut mdata, NFTA_META_DREG, 1);
        nla_u32_be(&mut mdata, NFTA_META_KEY,  NFT_META_L4PROTO);
        let mut m_expr = Vec::new();
        nla_str(&mut m_expr, NFTA_EXPR_NAME, "meta");
        nla_nested(&mut m_expr, NFTA_EXPR_DATA, &mdata);

        // cmp eq reg1, want (1 byte)
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[want]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &m_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &c_expr);
        out.extend_from_slice(&imm);
        out
    }

    fn ipv4_pkt_proto(proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[9] = proto;
        p
    }

    fn build_transport_port_drop(dst_port_be: [u8; 2]) -> Vec<u8> {
        // payload (TRANSPORT, offset 2, len 2) -> reg 1   (UDP dst port)
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 2);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 2);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &dst_port_be);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &c_expr);
        out.extend_from_slice(&imm);
        out
    }

    fn ipv4_udp_pkt(dst_port: u16) -> Vec<u8> {
        // Minimal IPv4 hdr (IHL=5 → 20 bytes) + 8 byte UDP hdr.
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // ver=4 IHL=5
        p[9] = 17;   // proto=UDP
        // UDP dst port at L4+2..L4+4
        let dp = dst_port.to_be_bytes();
        p[22] = dp[0]; p[23] = dp[1];
        p
    }

    #[test]
    fn payload_transport_filters_udp_dst_port() {
        let rule = build_transport_port_drop([0, 53]); // DNS
        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &ipv4_udp_pkt(53)), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &ipv4_udp_pkt(80)), None);
    }

    #[test]
    fn payload_transport_honors_variable_ihl() {
        // IHL=6 (24 bytes of IPv4 hdr w/ 4-byte options). Put port
        // at offset 24+2=26.
        let rule = build_transport_port_drop([0, 22]);
        let exprs = parse_exprs(&rule);
        let mut p = vec![0u8; 32];
        p[0] = 0x46; // ver=4 IHL=6
        p[9] = 6;    // TCP
        p[26] = 0; p[27] = 22;
        assert_eq!(run_rule(&exprs, &p), Some(NF_DROP));
    }

    #[test]
    fn meta_l4proto_matches_tcp() {
        let rule = build_meta_l4proto_drop_match(6); // TCP
        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &ipv4_pkt_proto(6)), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &ipv4_pkt_proto(17)), None);
    }

    #[test]
    fn meta_len_loads_pkt_len() {
        // Standalone parse-and-run of just meta + cmp on pkt len.
        let mut mdata = Vec::new();
        nla_u32_be(&mut mdata, NFTA_META_DREG, 1);
        nla_u32_be(&mut mdata, NFTA_META_KEY,  NFT_META_LEN);
        let mut m_expr = Vec::new();
        nla_str(&mut m_expr, NFTA_EXPR_NAME, "meta");
        nla_nested(&mut m_expr, NFTA_EXPR_DATA, &mdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &(20u32).to_le_bytes());
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &m_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &vec![0u8; 20]), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &vec![0u8; 40]), None);
    }

    #[test]
    fn bitwise_masks_then_xors() {
        // payload(NETWORK, 12, 4) -> reg1 ; bitwise reg1 mask 0xff_ff_00_00 xor 0 -> reg1 ;
        // cmp reg1 == 10.0.0.0 ; drop
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut maskval = Vec::new();
        nla(&mut maskval, NFTA_DATA_VALUE, &[0xff, 0xff, 0x00, 0x00]);
        let mut xorval = Vec::new();
        nla(&mut xorval, NFTA_DATA_VALUE, &[0, 0, 0, 0]);
        let mut bdata = Vec::new();
        nla_u32_be(&mut bdata, NFTA_BITWISE_SREG, 1);
        nla_u32_be(&mut bdata, NFTA_BITWISE_DREG, 1);
        nla_u32_be(&mut bdata, NFTA_BITWISE_LEN, 4);
        nla_nested(&mut bdata, NFTA_BITWISE_MASK, &maskval);
        nla_nested(&mut bdata, NFTA_BITWISE_XOR,  &xorval);
        let mut b_expr = Vec::new();
        nla_str(&mut b_expr, NFTA_EXPR_NAME, "bitwise");
        nla_nested(&mut b_expr, NFTA_EXPR_DATA, &bdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[10, 0, 0, 0]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &b_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        let pkt_in = ipv4_pkt_with_src([10, 0, 5, 7]); // /16 → 10.0.0.0
        assert_eq!(run_rule(&exprs, &pkt_in), Some(NF_DROP));
        let pkt_out = ipv4_pkt_with_src([192, 168, 1, 1]);
        assert_eq!(run_rule(&exprs, &pkt_out), None);
    }

    #[test]
    fn counter_increments_on_reach() {
        // counter ; immediate drop
        let mut counter_data = Vec::new(); // counter expr has no body in v1
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "counter");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &counter_data);
        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);
        let exprs = parse_exprs(&rule);

        let mut packets = 0u64;
        let mut bytes = 0u64;
        let pkt = vec![0u8; 40];
        assert_eq!(run_rule_full(&exprs, &pkt, None, &mut packets, &mut bytes),
                   Some(NF_DROP));
        assert_eq!(packets, 1);
        assert_eq!(bytes, 40);
        // Run again — accumulates
        assert_eq!(run_rule_full(&exprs, &pkt, None, &mut packets, &mut bytes),
                   Some(NF_DROP));
        assert_eq!(packets, 2);
        assert_eq!(bytes, 80);
        let _ = counter_data.is_empty();
    }

    #[test]
    fn counter_not_bumped_when_cmp_fails_before() {
        // cmp(reg1, eq, 0xff) — fails because reg starts 0; counter; drop
        // The counter sits after cmp, so it should NOT execute.
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[0xff, 0xff, 0xff, 0xff]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut cmp_expr = Vec::new();
        nla_str(&mut cmp_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut cmp_expr, NFTA_EXPR_DATA, &cdata);

        let mut counter_data = Vec::new();
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "counter");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &counter_data);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &cmp_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);
        let exprs = parse_exprs(&rule);
        let mut p = 0u64;
        let mut b = 0u64;
        assert_eq!(run_rule_full(&exprs, &vec![0u8; 20], None, &mut p, &mut b), None);
        assert_eq!(p, 0);
        assert_eq!(b, 0);
        let _ = counter_data.is_empty();
    }

    fn build_lookup_rule(set_name: &str, invert: bool) -> Vec<u8> {
        // payload (NETWORK 12, 4) -> reg 1; lookup (set, reg 1); drop
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut ldata = Vec::new();
        let mut sname = set_name.as_bytes().to_vec();
        sname.push(0);
        nla(&mut ldata, NFTA_LOOKUP_SET, &sname);
        nla_u32_be(&mut ldata, NFTA_LOOKUP_SREG, 1);
        nla_u32_be(&mut ldata, NFTA_LOOKUP_FLAGS, if invert { NFT_LOOKUP_F_INV } else { 0 });
        let mut l_expr = Vec::new();
        nla_str(&mut l_expr, NFTA_EXPR_NAME, "lookup");
        nla_nested(&mut l_expr, NFTA_EXPR_DATA, &ldata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &l_expr);
        out.extend_from_slice(&imm);
        out
    }

    #[test]
    fn lookup_hit_drops() {
        let rule = build_lookup_rule("blocked", false);
        let exprs = parse_exprs(&rule);
        let look = |_set: &str, key: &[u8]| -> Option<Vec<u8>> {
            if &key[..4] == &[10, 0, 0, 5] { Some(Vec::new()) } else { None }
        };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), Some(NF_DROP));
    }

    #[test]
    fn lookup_miss_falls_through() {
        let rule = build_lookup_rule("blocked", false);
        let exprs = parse_exprs(&rule);
        let look = |_s: &str, _k: &[u8]| -> Option<Vec<u8>> { None };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), None);
    }

    #[test]
    fn lookup_inverted_miss_drops() {
        let rule = build_lookup_rule("allowed", true);
        let exprs = parse_exprs(&rule);
        let look = |_s: &str, _k: &[u8]| -> Option<Vec<u8>> { None };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), Some(NF_DROP));
    }

    #[test]
    fn neq_inverts_match() {
        // Build a rule with NEQ on src=10.0.0.5 then immediate drop.
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[10, 0, 0, 5]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_NEQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();

        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        // pkt with a different src — NEQ matches — should drop
        let pkt = ipv4_pkt_with_src([10, 0, 0, 6]);
        assert_eq!(run_rule(&exprs, &pkt), Some(NF_DROP));
        // pkt with same src — NEQ doesn't match — skip
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule(&exprs, &pkt), None);
    }
}

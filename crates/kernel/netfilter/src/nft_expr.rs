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
        let nla_type = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]);
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
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
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

/// Walk a parsed expression list against `pkt`. Returns:
///   - `Some(NF_DROP)` / `Some(NF_ACCEPT)` when an immediate sets
///     the verdict register
///   - `None` when no immediate fired (let chain policy decide) or
///     a cmp aborted the rule
/// # C: O(N_exprs · max_len) per rule
pub fn run_rule(exprs: &[Expr], pkt: &[u8]) -> Option<i32> {
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

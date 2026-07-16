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

pub const NFTA_BYTEORDER_SREG: u16 = 1;
pub const NFTA_BYTEORDER_DREG: u16 = 2;
pub const NFTA_BYTEORDER_OP:   u16 = 3;
pub const NFTA_BYTEORDER_LEN:  u16 = 4;
pub const NFTA_BYTEORDER_SIZE: u16 = 5;

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

pub use net::netfilter_hook::{NFPROTO_IPV4, NFPROTO_IPV6};

pub const NFTA_DATA_VALUE:   u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;

pub const NFTA_VERDICT_CODE: u16 = 1;

/// Fixed IPv6 main-header length (no extension headers).
const IPV6_FIXED_HDR: usize = 40;

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
    Bitwise   { sreg: u32, dreg: u32, mask: Vec<u8>, xor: Vec<u8> },
    Byteorder { sreg: u32, dreg: u32, len: u32, size: u32 },
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
        "byteorder" => parse_byteorder(data),
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

fn parse_byteorder(d: &[u8]) -> Option<Expr> {
    let sreg = find_u32_be(d, NFTA_BYTEORDER_SREG)?;
    let dreg = find_u32_be(d, NFTA_BYTEORDER_DREG)?;
    let _op  = find_u32_be(d, NFTA_BYTEORDER_OP).unwrap_or(0);
    let len  = find_u32_be(d, NFTA_BYTEORDER_LEN)?;
    let size = find_u32_be(d, NFTA_BYTEORDER_SIZE)?;
    Some(Expr::Byteorder { sreg, dreg, len, size })
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
    run_rule_full(exprs, pkt, lookup, NFPROTO_IPV4, &mut visits, &mut bytes)
}

/// Same as `run_rule_with_lookup` but also accumulates counter
/// stats: every Counter expression the run path reaches bumps
/// `*packets += 1` and `*bytes += pkt.len()`. Cmp-aborted rules
/// don't reach later Counter exprs (positional semantics match
/// Linux's nft_counter).
/// # C: O(N_exprs · max_len)
pub fn run_rule_full(exprs: &[Expr], pkt: &[u8],
                     lookup: Option<SetLookupFn>, family: u8,
                     packets: &mut u64, bytes: &mut u64) -> Option<i32> {
    let mut regs = vec![0u8; REG_BYTES];
    for e in exprs {
        match e {
            Expr::Payload { dreg, base, offset, len } => {
                let base_off: usize = match *base {
                    NFT_PAYLOAD_NETWORK_HEADER => 0,
                    NFT_PAYLOAD_TRANSPORT_HEADER => {
                        // Network-header length → byte offset to L4. IPv6 has a
                        // fixed 40-byte header (extension-header walk is a
                        // follow-up); IPv4 reads IHL from the first byte.
                        if pkt.is_empty() { return None; }
                        match family {
                            NFPROTO_IPV6 => IPV6_FIXED_HDR,
                            _ => {
                                if (pkt[0] >> 4) != 4 { return None; }
                                ((pkt[0] & 0x0f) as usize) * 4
                            }
                        }
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
                        regs[dst] = family;
                    }
                    NFT_META_L4PROTO => {
                        if dst + 1 > regs.len() { return None; }
                        // IPv6 next-header @ +6, IPv4 protocol @ +9.
                        let proto = match family {
                            NFPROTO_IPV6 => { if pkt.len() < 7  { return None; } pkt[6] }
                            _            => { if pkt.len() < 10 { return None; } pkt[9] }
                        };
                        regs[dst] = proto;
                    }
                    _ => return None,
                }
            }
            Expr::Byteorder { sreg, dreg, len, size } => {
                let src = reg_off(*sreg)?;
                let dst = reg_off(*dreg)?;
                let l = *len as usize;
                let sz = *size as usize;
                if sz == 0 || l % sz != 0 { return None; }
                if src + l > regs.len() || dst + l > regs.len() { return None; }
                let mut tmp = Vec::with_capacity(l);
                for chunk in regs[src .. src + l].chunks(sz) {
                    for &b in chunk.iter().rev() { tmp.push(b); }
                }
                regs[dst .. dst + l].copy_from_slice(&tmp);
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
#[path = "nft_expr_tests.rs"]
mod tests;

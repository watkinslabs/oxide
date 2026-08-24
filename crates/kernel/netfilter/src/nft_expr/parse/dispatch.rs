//! Expression-name dispatch over one rule's `NFTA_RULE_EXPRESSIONS` blob.

extern crate alloc;
use alloc::vec::Vec;

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::nla::{align4, find_bytes, find_str, mask_nla};
use crate::nft_expr::parse::{basic, conn, misc, StateAlloc};
use crate::nft_expr::uapi::{NFPROTO_INET, NFTA_EXPR_DATA, NFTA_EXPR_NAME, NFTA_LIST_ELEM};

/// Parse one expression by name. # C: O(len(body))
pub fn parse_one_expr(body: &[u8], family: u8, alloc: &mut StateAlloc)
    -> Result<Expr, ParseError>
{
    let name = find_str(body, NFTA_EXPR_NAME).ok_or(ParseError::Malformed)?;
    if name == "notrack" { return Ok(Expr::Notrack); }
    let d = find_bytes(body, NFTA_EXPR_DATA).ok_or(ParseError::Malformed)?;
    match name {
        "payload"      => basic::payload(d),
        "cmp"          => basic::cmp(d),
        "immediate"    => basic::immediate(d),
        "meta"         => basic::meta(d),
        "lookup"       => basic::lookup(d),
        "counter"      => basic::counter(d),
        "bitwise"      => basic::bitwise(d),
        "byteorder"    => basic::byteorder(d),
        "range"        => basic::range(d),
        "hash"         => basic::hash(d),
        "numgen"       => basic::numgen(d, alloc),
        "objref"       => basic::objref(d),

        "ct"           => conn::ct(d, family),
        "nat"          => conn::nat_expr(d),
        "masq"         => conn::masq(d),
        "redir"        => conn::redir(d),
        "dup"          => conn::dup(d),
        "fwd"          => conn::fwd(d),
        "tproxy"       => conn::tproxy(d),
        "synproxy"     => conn::synproxy(d),
        "connlimit"    => conn::connlimit(d, alloc),
        "flow_offload" => conn::flow_offload(d),

        "limit"        => misc::limit(d, alloc),
        "log"          => misc::log(d),
        "queue"        => misc::queue(d),
        "quota"        => misc::quota(d, alloc),
        "reject"       => misc::reject(d),
        "exthdr"       => misc::exthdr(d),
        "tcpopt"       => misc::exthdr(d),
        "rt"           => misc::rt(d),
        "fib"          => misc::fib(d),
        "socket"       => misc::socket(d),
        "osf"          => misc::osf(d),
        "xfrm"         => misc::xfrm(d),
        "last"         => misc::last(d, alloc),
        "tunnel"       => misc::tunnel(d),
        _ => Err(ParseError::Unsupported),
    }
}

/// Parse and validate one complete rule expression blob for a family. An
/// unknown expression is refused rather than silently dropped, which would
/// remove policy from the rule while reporting success.
/// # C: O(len(payload))
pub fn parse_exprs_in(payload: &[u8], family: u8) -> Result<Vec<Expr>, ParseError> {
    let mut out = Vec::new();
    let mut alloc = StateAlloc::new();
    let mut off = 0;
    while off < payload.len() {
        if off + 4 > payload.len() { return Err(ParseError::Malformed); }
        let nla_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]);
        if nla_len < 4 || off + nla_len > payload.len() { return Err(ParseError::Malformed); }
        let body = &payload[off + 4..off + nla_len];
        if mask_nla(nla_type) == NFTA_LIST_ELEM {
            out.push(parse_one_expr(body, family, &mut alloc)?);
        }
        let next = off + align4(nla_len);
        if next > payload.len() { return Err(ParseError::Malformed); }
        off = next;
    }
    Ok(out)
}

/// Family-agnostic parse. The widest address width is assumed, which is what
/// a dual-stack table gets. # C: O(len(payload))
pub fn parse_exprs_checked(payload: &[u8]) -> Result<Vec<Expr>, ParseError> {
    parse_exprs_in(payload, NFPROTO_INET)
}

/// Lenient parse for callers that only want the executable expressions.
/// Invalid input produces none, so invalid policy never becomes executable.
/// # C: O(len(payload))
pub fn parse_exprs(payload: &[u8]) -> Vec<Expr> {
    parse_exprs_checked(payload).unwrap_or_default()
}

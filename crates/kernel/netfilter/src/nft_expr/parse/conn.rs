//! Parsers for the expressions that read or steer a tracked connection.

extern crate alloc;
use alloc::string::String;

use conntrack::uapi::IP_CT_DIR_MAX;
use nat::uapi::NF_NAT_RANGE_MASK;

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::flags::{NFT_CONNLIMIT_F_INV, NF_SYNPROXY_OPT_MASK};
use crate::nft_expr::limits::{NF_CT_HELPER_NAME_LEN, NF_CT_LABELS_MAX_SIZE};
use crate::nft_expr::nla::{find_str, find_u16_be, find_u32_be, find_u8};
use crate::nft_expr::parse::StateAlloc;
use crate::nft_expr::regs::register_load_valid;
use crate::nft_expr::uapi::*;

type Parsed = Result<Expr, ParseError>;

/// # C: O(1)
fn need<T>(v: Option<T>) -> Result<T, ParseError> { v.ok_or(ParseError::Malformed) }

/// Keys whose value depends on which direction of the flow is asked for.
/// # C: O(1)
fn ct_key_directional(key: u32) -> bool {
    matches!(key, NFT_CT_SRC | NFT_CT_DST | NFT_CT_SRC_IP | NFT_CT_DST_IP | NFT_CT_SRC_IP6
                  | NFT_CT_DST_IP6 | NFT_CT_PROTO_SRC | NFT_CT_PROTO_DST | NFT_CT_PKTS
                  | NFT_CT_BYTES | NFT_CT_AVGPKT)
}

/// Byte width one conntrack key reads. # C: O(1)
pub fn ct_width(key: u32, family: u8) -> Option<usize> {
    Some(match key {
        NFT_CT_STATE | NFT_CT_STATUS | NFT_CT_MARK | NFT_CT_SECMARK | NFT_CT_EXPIRATION
        | NFT_CT_EVENTMASK | NFT_CT_ID => 4,
        NFT_CT_DIRECTION | NFT_CT_L3PROTOCOL | NFT_CT_PROTOCOL => 1,
        NFT_CT_ZONE | NFT_CT_PROTO_SRC | NFT_CT_PROTO_DST => 2,
        NFT_CT_HELPER => NF_CT_HELPER_NAME_LEN,
        NFT_CT_LABELS => NF_CT_LABELS_MAX_SIZE,
        NFT_CT_PKTS | NFT_CT_BYTES | NFT_CT_AVGPKT => 8,
        NFT_CT_SRC_IP | NFT_CT_DST_IP => 4,
        NFT_CT_SRC_IP6 | NFT_CT_DST_IP6 => 16,
        NFT_CT_SRC | NFT_CT_DST => if family == NFPROTO_IPV4 { 4 } else { 16 },
        _ => return None,
    })
}

/// Keys a `ct` expression may write. # C: O(1)
pub fn ct_settable(key: u32) -> bool {
    matches!(key, NFT_CT_MARK | NFT_CT_SECMARK | NFT_CT_LABELS | NFT_CT_EVENTMASK
                  | NFT_CT_ZONE)
}

/// # C: O(len(d))
pub fn ct(d: &[u8], family: u8) -> Parsed {
    let key = need(find_u32_be(d, NFTA_CT_KEY))?;
    if key > NFT_CT_MAX { return Err(ParseError::Unsupported); }
    let dreg = find_u32_be(d, NFTA_CT_DREG);
    let sreg = find_u32_be(d, NFTA_CT_SREG);
    if dreg.is_some() == sreg.is_some() { return Err(ParseError::Malformed); }
    let dir = find_u8(d, NFTA_CT_DIRECTION);
    if let Some(dir) = dir {
        if !ct_key_directional(key) { return Err(ParseError::Unsupported); }
        if dir as usize >= IP_CT_DIR_MAX { return Err(ParseError::Malformed); }
    }
    let len = ct_width(key, family).ok_or(ParseError::Unsupported)?;
    if let Some(sreg) = sreg {
        if !ct_settable(key) { return Err(ParseError::Unsupported); }
        if !register_load_valid(sreg, len) { return Err(ParseError::Malformed); }
    }
    if let Some(dreg) = dreg {
        if !register_load_valid(dreg, len) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Ct { dreg, sreg, key, dir, len: len as u32 })
}

/// # C: O(len(d))
pub fn nat_expr(d: &[u8]) -> Parsed {
    use nat::uapi::{NF_NAT_RANGE_MAP_IPS, NF_NAT_RANGE_PROTO_SPECIFIED};
    let nat_type = need(find_u32_be(d, NFTA_NAT_TYPE))?;
    if nat_type > NFT_NAT_DNAT { return Err(ParseError::Malformed); }
    let family = need(find_u32_be(d, NFTA_NAT_FAMILY))? as u8;
    if family != NFPROTO_IPV4 && family != NFPROTO_IPV6 { return Err(ParseError::Unsupported); }
    let addr_len = if family == NFPROTO_IPV4 { 4 } else { 16 };
    let sreg_addr_min = find_u32_be(d, NFTA_NAT_REG_ADDR_MIN);
    let sreg_proto_min = find_u32_be(d, NFTA_NAT_REG_PROTO_MIN);
    if sreg_addr_min.is_none() && sreg_proto_min.is_none() { return Err(ParseError::Malformed); }
    let mut flags = find_u32_be(d, NFTA_NAT_FLAGS).unwrap_or(0);
    if flags & !NF_NAT_RANGE_MASK != 0 { return Err(ParseError::Unsupported); }
    let sreg_addr_max = match sreg_addr_min {
        Some(min) => {
            if !register_load_valid(min, addr_len) { return Err(ParseError::Malformed); }
            flags |= NF_NAT_RANGE_MAP_IPS;
            let max = find_u32_be(d, NFTA_NAT_REG_ADDR_MAX).unwrap_or(min);
            if !register_load_valid(max, addr_len) { return Err(ParseError::Malformed); }
            Some(max)
        }
        None => None,
    };
    let sreg_proto_max = match sreg_proto_min {
        Some(min) => {
            if !register_load_valid(min, 2) { return Err(ParseError::Malformed); }
            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            let max = find_u32_be(d, NFTA_NAT_REG_PROTO_MAX).unwrap_or(min);
            if !register_load_valid(max, 2) { return Err(ParseError::Malformed); }
            Some(max)
        }
        None => None,
    };
    Ok(Expr::Nat { nat_type, family, flags, sreg_addr_min, sreg_addr_max,
                   sreg_proto_min, sreg_proto_max })
}

/// # C: O(len(d))
pub fn masq(d: &[u8]) -> Parsed {
    use nat::uapi::NF_NAT_RANGE_PROTO_SPECIFIED;
    let mut flags = find_u32_be(d, NFTA_MASQ_FLAGS).unwrap_or(0);
    if flags & !NF_NAT_RANGE_MASK != 0 { return Err(ParseError::Unsupported); }
    let sreg_proto_min = find_u32_be(d, NFTA_MASQ_REG_PROTO_MIN);
    let sreg_proto_max = match sreg_proto_min {
        Some(min) => {
            if !register_load_valid(min, 2) { return Err(ParseError::Malformed); }
            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            let max = find_u32_be(d, NFTA_MASQ_REG_PROTO_MAX).unwrap_or(min);
            if !register_load_valid(max, 2) { return Err(ParseError::Malformed); }
            Some(max)
        }
        None => None,
    };
    Ok(Expr::Masq { flags, sreg_proto_min, sreg_proto_max })
}

/// The explicit flags attribute replaces the implied one rather than adding
/// to it, so a rule naming both a port register and flags gets exactly the
/// flags it named. # C: O(len(d))
pub fn redir(d: &[u8]) -> Parsed {
    use nat::uapi::NF_NAT_RANGE_PROTO_SPECIFIED;
    let mut flags = 0;
    let sreg_proto_min = find_u32_be(d, NFTA_REDIR_REG_PROTO_MIN);
    let sreg_proto_max = match sreg_proto_min {
        Some(min) => {
            if !register_load_valid(min, 2) { return Err(ParseError::Malformed); }
            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            let max = find_u32_be(d, NFTA_REDIR_REG_PROTO_MAX).unwrap_or(min);
            if !register_load_valid(max, 2) { return Err(ParseError::Malformed); }
            Some(max)
        }
        None => None,
    };
    if let Some(explicit) = find_u32_be(d, NFTA_REDIR_FLAGS) {
        if explicit & !NF_NAT_RANGE_MASK != 0 { return Err(ParseError::Unsupported); }
        flags = explicit;
    }
    Ok(Expr::Redir { flags, sreg_proto_min, sreg_proto_max })
}

/// # C: O(len(d))
pub fn dup(d: &[u8]) -> Parsed {
    let sreg_addr = find_u32_be(d, NFTA_DUP_SREG_ADDR);
    let sreg_dev = find_u32_be(d, NFTA_DUP_SREG_DEV);
    if sreg_addr.is_none() && sreg_dev.is_none() { return Err(ParseError::Malformed); }
    if let Some(dev) = sreg_dev {
        if !register_load_valid(dev, 4) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Dup { sreg_addr, sreg_dev })
}

/// # C: O(len(d))
pub fn fwd(d: &[u8]) -> Parsed {
    let sreg_dev = need(find_u32_be(d, NFTA_FWD_SREG_DEV))?;
    if !register_load_valid(sreg_dev, 4) { return Err(ParseError::Malformed); }
    let sreg_addr = find_u32_be(d, NFTA_FWD_SREG_ADDR);
    let nfproto = find_u32_be(d, NFTA_FWD_NFPROTO).map(|p| p as u8);
    if sreg_addr.is_some() != nfproto.is_some() { return Err(ParseError::Malformed); }
    if let (Some(addr), Some(proto)) = (sreg_addr, nfproto) {
        let len = match proto {
            NFPROTO_IPV4 => 4,
            NFPROTO_IPV6 => 16,
            _ => return Err(ParseError::Unsupported),
        };
        if !register_load_valid(addr, len) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Fwd { sreg_dev, sreg_addr, nfproto })
}

/// # C: O(len(d))
pub fn tproxy(d: &[u8]) -> Parsed {
    let family = find_u32_be(d, NFTA_TPROXY_FAMILY).unwrap_or(NFPROTO_UNSPEC as u32) as u8;
    if !matches!(family, NFPROTO_UNSPEC | NFPROTO_IPV4 | NFPROTO_IPV6) {
        return Err(ParseError::Unsupported);
    }
    let sreg_addr = find_u32_be(d, NFTA_TPROXY_REG_ADDR);
    let sreg_port = find_u32_be(d, NFTA_TPROXY_REG_PORT);
    if let Some(addr) = sreg_addr {
        let len = if family == NFPROTO_IPV6 { 16 } else { 4 };
        if !register_load_valid(addr, len) { return Err(ParseError::Malformed); }
    }
    if let Some(port) = sreg_port {
        if !register_load_valid(port, 2) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Tproxy { family, sreg_addr, sreg_port })
}

/// # C: O(len(d))
pub fn synproxy(d: &[u8]) -> Parsed {
    let flags = find_u32_be(d, NFTA_SYNPROXY_FLAGS).unwrap_or(0);
    if flags & !NF_SYNPROXY_OPT_MASK != 0 { return Err(ParseError::Unsupported); }
    let mss = find_u16_be(d, NFTA_SYNPROXY_MSS).unwrap_or(0);
    let wscale = find_u8(d, NFTA_SYNPROXY_WSCALE).unwrap_or(0);
    Ok(Expr::Synproxy { mss, wscale, flags })
}

/// # C: O(len(d))
pub fn connlimit(d: &[u8], alloc: &mut StateAlloc) -> Parsed {
    let count = need(find_u32_be(d, NFTA_CONNLIMIT_COUNT))?;
    let flags = find_u32_be(d, NFTA_CONNLIMIT_FLAGS).unwrap_or(0);
    if flags & !NFT_CONNLIMIT_F_INV != 0 { return Err(ParseError::Unsupported); }
    Ok(Expr::Connlimit { index: alloc.take_connlimit(), count,
                         invert: flags & NFT_CONNLIMIT_F_INV != 0 })
}

/// # C: O(len(d))
pub fn flow_offload(d: &[u8]) -> Parsed {
    let table = need(find_str(d, NFTA_FLOW_TABLE_NAME))?;
    Ok(Expr::FlowOffload { table: String::from(table) })
}

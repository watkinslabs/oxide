//! Parsers for the register-and-packet expressions: the ones whose whole job
//! is moving bytes between the packet, a literal and the register file.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::flags::NFT_LOOKUP_F_INV;
use crate::nft_expr::nla::{find_bytes, find_data_value, find_str, find_u32_be};
use crate::nft_expr::parse::StateAlloc;
use crate::nft_expr::regs::register_load_valid;
use crate::nft_expr::uapi::*;

type Parsed = Result<Expr, ParseError>;

/// # C: O(1)
fn need<T>(v: Option<T>) -> Result<T, ParseError> { v.ok_or(ParseError::Malformed) }

/// # C: O(len(d))
pub fn payload(d: &[u8]) -> Parsed {
    let base = need(find_u32_be(d, NFTA_PAYLOAD_BASE))?;
    if base > NFT_PAYLOAD_TUN_HEADER { return Err(ParseError::Malformed); }
    let offset = need(find_u32_be(d, NFTA_PAYLOAD_OFFSET))?;
    let len = need(find_u32_be(d, NFTA_PAYLOAD_LEN))?;
    if len == 0 || len as usize > NFT_DATA_VALUE_MAXLEN { return Err(ParseError::Malformed); }
    let sreg = find_u32_be(d, NFTA_PAYLOAD_SREG);
    let csum_type = find_u32_be(d, NFTA_PAYLOAD_CSUM_TYPE).unwrap_or(NFT_PAYLOAD_CSUM_NONE);
    if csum_type > NFT_PAYLOAD_CSUM_SCTP { return Err(ParseError::Unsupported); }
    let csum_offset = find_u32_be(d, NFTA_PAYLOAD_CSUM_OFFSET).unwrap_or(0);
    let csum_flags = find_u32_be(d, NFTA_PAYLOAD_CSUM_FLAGS).unwrap_or(0);
    let dreg = match sreg {
        Some(sreg) => {
            if !register_load_valid(sreg, len as usize) { return Err(ParseError::Malformed); }
            0
        }
        None => {
            let dreg = need(find_u32_be(d, NFTA_PAYLOAD_DREG))?;
            if !register_load_valid(dreg, len as usize) { return Err(ParseError::Malformed); }
            dreg
        }
    };
    Ok(Expr::Payload { dreg, base, offset, len, sreg, csum_type, csum_offset, csum_flags })
}

/// # C: O(len(d))
pub fn cmp(d: &[u8]) -> Parsed {
    let sreg = need(find_u32_be(d, NFTA_CMP_SREG))?;
    let op = need(find_u32_be(d, NFTA_CMP_OP))?;
    if op > NFT_CMP_GTE { return Err(ParseError::Malformed); }
    let data = need(find_data_value(d, NFTA_CMP_DATA))?.to_vec();
    if data.is_empty() || !register_load_valid(sreg, data.len()) {
        return Err(ParseError::Malformed);
    }
    Ok(Expr::Cmp { sreg, op, data })
}

/// # C: O(len(d))
pub fn immediate(d: &[u8]) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_IMMEDIATE_DREG))?;
    let data = need(find_bytes(d, NFTA_IMMEDIATE_DATA))?;
    let verdict_attr = find_bytes(data, NFTA_DATA_VERDICT);
    let verdict = verdict_attr.and_then(|v| find_u32_be(v, NFTA_VERDICT_CODE)).map(|c| c as i32);
    let chain = verdict_attr.and_then(|v| find_str(v, NFTA_VERDICT_CHAIN)).map(String::from);
    let value = find_bytes(data, NFTA_DATA_VALUE).map(<[u8]>::to_vec).unwrap_or_default();
    if dreg == NFT_REG_VERDICT {
        if verdict.is_none() { return Err(ParseError::Malformed); }
    } else if !register_load_valid(dreg, value.len()) {
        return Err(ParseError::Malformed);
    }
    Ok(Expr::Immediate { dreg, verdict, chain, value })
}

/// # C: O(len(d))
pub fn bitwise(d: &[u8]) -> Parsed {
    let sreg = need(find_u32_be(d, NFTA_BITWISE_SREG))?;
    let dreg = need(find_u32_be(d, NFTA_BITWISE_DREG))?;
    let len = need(find_u32_be(d, NFTA_BITWISE_LEN))? as usize;
    let mask = need(find_data_value(d, NFTA_BITWISE_MASK))?.to_vec();
    let xor = need(find_data_value(d, NFTA_BITWISE_XOR))?.to_vec();
    if mask.len() != xor.len() || mask.len() != len { return Err(ParseError::Malformed); }
    if !register_load_valid(sreg, len) || !register_load_valid(dreg, len) {
        return Err(ParseError::Malformed);
    }
    Ok(Expr::Bitwise { sreg, dreg, mask, xor })
}

/// # C: O(len(d))
pub fn byteorder(d: &[u8]) -> Parsed {
    let sreg = need(find_u32_be(d, NFTA_BYTEORDER_SREG))?;
    let dreg = need(find_u32_be(d, NFTA_BYTEORDER_DREG))?;
    let op = find_u32_be(d, NFTA_BYTEORDER_OP).unwrap_or(NFT_BYTEORDER_NTOH);
    if op > NFT_BYTEORDER_HTON { return Err(ParseError::Malformed); }
    let len = need(find_u32_be(d, NFTA_BYTEORDER_LEN))?;
    let size = need(find_u32_be(d, NFTA_BYTEORDER_SIZE))?;
    if !matches!(size, 2 | 4 | 8) || len == 0 || len % size != 0 {
        return Err(ParseError::Malformed);
    }
    if !register_load_valid(sreg, len as usize) || !register_load_valid(dreg, len as usize) {
        return Err(ParseError::Malformed);
    }
    Ok(Expr::Byteorder { sreg, dreg, op, len, size })
}

/// # C: O(len(d))
pub fn lookup(d: &[u8]) -> Parsed {
    let set = need(find_str(d, NFTA_LOOKUP_SET))?;
    let sreg = need(find_u32_be(d, NFTA_LOOKUP_SREG))?;
    let dreg = find_u32_be(d, NFTA_LOOKUP_DREG);
    let flags = find_u32_be(d, NFTA_LOOKUP_FLAGS).unwrap_or(0);
    if flags & !NFT_LOOKUP_F_INV != 0 { return Err(ParseError::Unsupported); }
    let invert = flags & NFT_LOOKUP_F_INV != 0;
    // An inverted lookup answers membership only; it has no data to store.
    if invert && dreg.is_some() { return Err(ParseError::Malformed); }
    Ok(Expr::Lookup { sreg, dreg, set: String::from(set), set_id: None, invert })
}

/// Keys a `meta` expression may write back onto the packet. # C: O(1)
pub fn meta_settable(key: u32) -> bool {
    matches!(key, NFT_META_MARK | NFT_META_PRIORITY | NFT_META_SECMARK | NFT_META_NFTRACE
                  | NFT_META_PKTTYPE)
}

/// Byte width one meta key reads or writes; `None` for a key with no width,
/// which is a key this kernel does not serve. # C: O(1)
pub fn meta_width(key: u32) -> Option<usize> {
    use crate::nft_expr::limits::{ETH_ALEN, IFNAMSIZ};
    Some(match key {
        NFT_META_LEN | NFT_META_PRIORITY | NFT_META_MARK | NFT_META_IIF | NFT_META_OIF
        | NFT_META_SKUID | NFT_META_SKGID | NFT_META_RTCLASSID | NFT_META_SECMARK
        | NFT_META_CPU | NFT_META_IIFGROUP | NFT_META_OIFGROUP | NFT_META_CGROUP
        | NFT_META_PRANDOM | NFT_META_TIME_HOUR | NFT_META_SDIF => 4,
        NFT_META_PROTOCOL | NFT_META_IIFTYPE | NFT_META_OIFTYPE | NFT_META_BRI_IIFPVID
        | NFT_META_BRI_IIFVPROTO => 2,
        NFT_META_NFPROTO | NFT_META_L4PROTO | NFT_META_PKTTYPE | NFT_META_SECPATH
        | NFT_META_NFTRACE | NFT_META_TIME_DAY | NFT_META_BRI_BROUTE => 1,
        NFT_META_TIME_NS => 8,
        NFT_META_IIFNAME | NFT_META_OIFNAME | NFT_META_IIFKIND | NFT_META_OIFKIND
        | NFT_META_SDIFNAME | NFT_META_BRI_IIFNAME | NFT_META_BRI_OIFNAME => IFNAMSIZ,
        NFT_META_BRI_IIFHWADDR => ETH_ALEN,
        _ => return None,
    })
}

/// # C: O(len(d))
pub fn meta(d: &[u8]) -> Parsed {
    let key = need(find_u32_be(d, NFTA_META_KEY))?;
    let dreg = find_u32_be(d, NFTA_META_DREG);
    let sreg = find_u32_be(d, NFTA_META_SREG);
    if dreg.is_some() == sreg.is_some() { return Err(ParseError::Malformed); }
    let width = meta_width(key).ok_or(ParseError::Unsupported)?;
    if let Some(sreg) = sreg {
        if !meta_settable(key) { return Err(ParseError::Unsupported); }
        if !register_load_valid(sreg, width) { return Err(ParseError::Malformed); }
    }
    if let Some(dreg) = dreg {
        if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Meta { dreg, sreg, key })
}

/// # C: O(len(d))
pub fn range(d: &[u8]) -> Parsed {
    let sreg = need(find_u32_be(d, NFTA_RANGE_SREG))?;
    let op = need(find_u32_be(d, NFTA_RANGE_OP))?;
    if op > NFT_RANGE_NEQ { return Err(ParseError::Malformed); }
    let from = need(find_data_value(d, NFTA_RANGE_FROM_DATA))?.to_vec();
    let to = need(find_data_value(d, NFTA_RANGE_TO_DATA))?.to_vec();
    if from.len() != to.len() || from.is_empty() { return Err(ParseError::Malformed); }
    if !register_load_valid(sreg, from.len()) { return Err(ParseError::Malformed); }
    Ok(Expr::Range { sreg, op, from, to })
}

/// # C: O(len(d))
pub fn hash(d: &[u8]) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_HASH_DREG))?;
    let hash_type = find_u32_be(d, NFTA_HASH_TYPE).unwrap_or(NFT_HASH_JENKINS);
    if hash_type > NFT_HASH_SYM { return Err(ParseError::Unsupported); }
    let modulus = need(find_u32_be(d, NFTA_HASH_MODULUS))?;
    if modulus < 1 { return Err(ParseError::OutOfRange); }
    let offset = find_u32_be(d, NFTA_HASH_OFFSET).unwrap_or(0);
    if offset.checked_add(modulus - 1).is_none() { return Err(ParseError::Overflow); }
    if !register_load_valid(dreg, 4) { return Err(ParseError::Malformed); }
    let (sreg, len) = if hash_type == NFT_HASH_SYM {
        (0, 0)
    } else {
        let sreg = need(find_u32_be(d, NFTA_HASH_SREG))?;
        let len = need(find_u32_be(d, NFTA_HASH_LEN))?;
        if len == 0 || !register_load_valid(sreg, len as usize) {
            return Err(ParseError::Malformed);
        }
        (sreg, len)
    };
    let seed = find_u32_be(d, NFTA_HASH_SEED).unwrap_or(0);
    Ok(Expr::Hash { sreg, dreg, len, modulus, seed, offset, hash_type })
}

/// # C: O(len(d))
pub fn numgen(d: &[u8], alloc: &mut StateAlloc) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_NG_DREG))?;
    let ng_type = need(find_u32_be(d, NFTA_NG_TYPE))?;
    if ng_type > NFT_NG_RANDOM { return Err(ParseError::Unsupported); }
    let modulus = need(find_u32_be(d, NFTA_NG_MODULUS))?;
    if modulus == 0 { return Err(ParseError::OutOfRange); }
    let offset = find_u32_be(d, NFTA_NG_OFFSET).unwrap_or(0);
    if offset.checked_add(modulus - 1).is_none() { return Err(ParseError::Overflow); }
    if !register_load_valid(dreg, 4) { return Err(ParseError::Malformed); }
    let index = alloc.take_numgen();
    Ok(Expr::Numgen { index, dreg, modulus, offset, ng_type })
}

/// # C: O(len(d))
pub fn objref(d: &[u8]) -> Parsed {
    let sreg = find_u32_be(d, NFTA_OBJREF_SET_SREG);
    let set = find_str(d, NFTA_OBJREF_SET_NAME).map(String::from);
    let set_id = find_u32_be(d, NFTA_OBJREF_SET_ID).map(|id| id as usize);
    if sreg.is_some() && (set.is_some() || set_id.is_some()) {
        return Ok(Expr::Objref { obj_type: None, name: None, sreg, set, set_id });
    }
    let name = find_str(d, NFTA_OBJREF_IMM_NAME).map(String::from);
    let obj_type = find_u32_be(d, NFTA_OBJREF_IMM_TYPE);
    if name.is_some() && obj_type.is_some() {
        return Ok(Expr::Objref { obj_type, name, sreg: None, set: None, set_id: None });
    }
    Err(ParseError::Unsupported)
}

/// A counter carries its totals in the rule, not in the expression, so the
/// wire attributes are a starting value the store already keeps. # C: O(1)
pub fn counter(_d: &[u8]) -> Parsed { Ok(Expr::Counter) }

/// Registers a compiled expression reads, for the store's set-width check.
/// # C: O(1)
pub fn source_registers(expr: &Expr, out: &mut Vec<u32>) {
    if let Expr::Lookup { sreg, .. } = expr { out.push(*sreg); }
}

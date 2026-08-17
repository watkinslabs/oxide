//! Parsers for the rate, accounting, logging, header-option and lookup
//! expressions.

extern crate alloc;
use alloc::string::String;

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::flags::*;
use crate::nft_expr::limits::*;
use crate::nft_expr::nla::{find_str, find_u16_be, find_u32_be, find_u64_be, find_u8};
use crate::nft_expr::parse::StateAlloc;
use crate::nft_expr::regs::register_load_valid;
use crate::nft_expr::uapi::*;

type Parsed = Result<Expr, ParseError>;

/// # C: O(1)
fn need<T>(v: Option<T>) -> Result<T, ParseError> { v.ok_or(ParseError::Malformed) }

/// # C: O(1)
fn mul(a: u64, b: u64) -> Result<u64, ParseError> {
    a.checked_mul(b).ok_or(ParseError::Overflow)
}

/// Bucket depth for one configured rate: how far ahead of the rate a burst
/// may run before packets are refused. # C: O(1)
pub fn limit_tokens_max(pkts: bool, nsecs: u64, rate: u64, burst: u32)
    -> Result<u64, ParseError>
{
    let rate_with_burst = rate.checked_add(burst as u64).ok_or(ParseError::Overflow)?;
    if pkts { mul(nsecs / rate, burst as u64) } else { Ok(mul(nsecs, rate_with_burst)? / rate) }
}

/// # C: O(len(d))
pub fn limit(d: &[u8], alloc: &mut StateAlloc) -> Parsed {
    let limit_type = find_u32_be(d, NFTA_LIMIT_TYPE).unwrap_or(NFT_LIMIT_PKTS);
    if limit_type > NFT_LIMIT_PKT_BYTES { return Err(ParseError::Unsupported); }
    let pkts = limit_type == NFT_LIMIT_PKTS;
    let rate = need(find_u64_be(d, NFTA_LIMIT_RATE))?;
    let unit = need(find_u64_be(d, NFTA_LIMIT_UNIT))?;
    if rate == 0 { return Err(ParseError::Malformed); }
    let nsecs = mul(unit, NSEC_PER_SEC)?;
    let mut burst = find_u32_be(d, NFTA_LIMIT_BURST).unwrap_or(0);
    if pkts && burst == 0 { burst = NFT_LIMIT_PKT_BURST_DEFAULT; }
    let tokens_max = limit_tokens_max(pkts, nsecs, rate, burst)?;
    let flags = find_u32_be(d, NFTA_LIMIT_FLAGS).unwrap_or(0);
    if flags & !NFT_LIMIT_F_INV != 0 { return Err(ParseError::Unsupported); }
    Ok(Expr::Limit { index: alloc.take_limit(), limit_type, rate, nsecs, burst, tokens_max,
                     invert: flags & NFT_LIMIT_F_INV != 0 })
}

/// # C: O(len(d))
pub fn log(d: &[u8]) -> Parsed {
    let group = find_u16_be(d, NFTA_LOG_GROUP);
    let level_attr = find_u32_be(d, NFTA_LOG_LEVEL);
    if group.is_some() && level_attr.is_some() { return Err(ParseError::Malformed); }
    let flags = find_u32_be(d, NFTA_LOG_FLAGS).unwrap_or(0);
    if group.is_some() && find_u32_be(d, NFTA_LOG_FLAGS).is_some() {
        return Err(ParseError::Malformed);
    }
    if flags & !NF_LOG_MASK != 0 { return Err(ParseError::Unsupported); }
    let level = level_attr.unwrap_or(LOGLEVEL_WARNING);
    if group.is_none() && level >= LOGLEVEL_AUDIT { return Err(ParseError::Malformed); }
    let prefix = find_str(d, NFTA_LOG_PREFIX).unwrap_or("");
    if prefix.len() >= NFT_NAME_MAXLEN { return Err(ParseError::Malformed); }
    Ok(Expr::Log { group, prefix: String::from(prefix),
                   snaplen: find_u32_be(d, NFTA_LOG_SNAPLEN).unwrap_or(0),
                   qthreshold: find_u16_be(d, NFTA_LOG_QTHRESHOLD).unwrap_or(0),
                   level, flags })
}

/// # C: O(len(d))
pub fn queue(d: &[u8]) -> Parsed {
    let num = find_u16_be(d, NFTA_QUEUE_NUM);
    let sreg_qnum = find_u32_be(d, NFTA_QUEUE_SREG_QNUM);
    if num.is_some() == sreg_qnum.is_some() { return Err(ParseError::Malformed); }
    let flags = find_u32_be(d, NFTA_QUEUE_FLAGS).unwrap_or(0);
    if flags & !NFT_QUEUE_FLAG_MASK != 0 { return Err(ParseError::Unsupported); }
    if let Some(sreg) = sreg_qnum {
        // A register-selected queue is already per-flow; fanning it out over
        // processors as well would send one flow to several queues.
        if flags & NFT_QUEUE_FLAG_CPU_FANOUT != 0 { return Err(ParseError::Unsupported); }
        if !register_load_valid(sreg, 4) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Queue { num: num.unwrap_or(0),
                     total: find_u16_be(d, NFTA_QUEUE_TOTAL).unwrap_or(1), flags, sreg_qnum })
}

/// # C: O(len(d))
pub fn quota(d: &[u8], alloc: &mut StateAlloc) -> Parsed {
    let quota = need(find_u64_be(d, NFTA_QUOTA_BYTES))?;
    if quota > i64::MAX as u64 { return Err(ParseError::Overflow); }
    let flags = find_u32_be(d, NFTA_QUOTA_FLAGS).unwrap_or(0);
    if flags & NFT_QUOTA_F_DEPLETED != 0 { return Err(ParseError::Unsupported); }
    if flags & !NFT_QUOTA_F_INV != 0 { return Err(ParseError::Malformed); }
    let consumed = find_u64_be(d, NFTA_QUOTA_CONSUMED).unwrap_or(0);
    if consumed > quota { return Err(ParseError::Malformed); }
    let index = alloc.take_quota();
    Ok(Expr::Quota { index, quota, consumed, invert: flags & NFT_QUOTA_F_INV != 0 })
}

/// # C: O(len(d))
pub fn reject(d: &[u8]) -> Parsed {
    let reject_type = need(find_u32_be(d, NFTA_REJECT_TYPE))?;
    let icmp_code = match reject_type {
        NFT_REJECT_ICMP_UNREACH => need(find_u8(d, NFTA_REJECT_ICMP_CODE))?,
        NFT_REJECT_ICMPX_UNREACH => {
            let code = need(find_u8(d, NFTA_REJECT_ICMP_CODE))?;
            if code > NFT_REJECT_ICMPX_MAX { return Err(ParseError::Malformed); }
            code
        }
        NFT_REJECT_TCP_RST => 0,
        _ => return Err(ParseError::Malformed),
    };
    Ok(Expr::Reject { reject_type, icmp_code })
}

/// # C: O(len(d))
pub fn exthdr(d: &[u8]) -> Parsed {
    let op = find_u32_be(d, NFTA_EXTHDR_OP).unwrap_or(NFT_EXTHDR_OP_IPV6);
    if op > NFT_EXTHDR_OP_MAX { return Err(ParseError::Unsupported); }
    let flags = find_u32_be(d, NFTA_EXTHDR_FLAGS).unwrap_or(0);
    if flags & !NFT_EXTHDR_F_PRESENT != 0 { return Err(ParseError::Malformed); }
    let htype = need(find_u8(d, NFTA_EXTHDR_TYPE))?;
    let dreg = find_u32_be(d, NFTA_EXTHDR_DREG);
    let sreg = find_u32_be(d, NFTA_EXTHDR_SREG);
    if dreg.is_some() && sreg.is_some() { return Err(ParseError::Malformed); }
    if sreg.is_some() && op != NFT_EXTHDR_OP_TCPOPT { return Err(ParseError::Unsupported); }
    if dreg.is_none() && sreg.is_none() {
        // Neither register: the option is removed rather than read or written.
        if op != NFT_EXTHDR_OP_TCPOPT { return Err(ParseError::Malformed); }
        return Ok(Expr::Exthdr { dreg: None, sreg: None, op, htype, offset: 0, len: 0, flags });
    }
    let offset = need(find_u32_be(d, NFTA_EXTHDR_OFFSET))?;
    let len = need(find_u32_be(d, NFTA_EXTHDR_LEN))?;
    if len == 0 || len as usize > NFT_DATA_VALUE_MAXLEN { return Err(ParseError::Malformed); }
    if let Some(sreg) = sreg {
        if flags & NFT_EXTHDR_F_PRESENT != 0 { return Err(ParseError::Malformed); }
        if len != 2 && len != 4 { return Err(ParseError::Unsupported); }
        if !register_load_valid(sreg, len as usize) { return Err(ParseError::Malformed); }
    }
    if let Some(dreg) = dreg {
        let width = if flags & NFT_EXTHDR_F_PRESENT != 0 { 1 } else { len as usize };
        if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    }
    Ok(Expr::Exthdr { dreg, sreg, op, htype, offset, len, flags })
}

/// Byte width one route key writes. # C: O(1)
pub fn rt_width(key: u32) -> Option<usize> {
    Some(match key {
        NFT_RT_CLASSID | NFT_RT_NEXTHOP4 => 4,
        NFT_RT_NEXTHOP6 => 16,
        NFT_RT_TCPMSS => 2,
        NFT_RT_XFRM => 1,
        _ => return None,
    })
}

/// # C: O(len(d))
pub fn rt(d: &[u8]) -> Parsed {
    let key = need(find_u32_be(d, NFTA_RT_KEY))?;
    let dreg = need(find_u32_be(d, NFTA_RT_DREG))?;
    let width = rt_width(key).ok_or(ParseError::Malformed)?;
    if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    Ok(Expr::Rt { dreg, key })
}

/// # C: O(len(d))
pub fn fib(d: &[u8]) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_FIB_DREG))?;
    let result = need(find_u32_be(d, NFTA_FIB_RESULT))?;
    let flags = need(find_u32_be(d, NFTA_FIB_FLAGS))?;
    if flags == 0 || flags & !NFTA_FIB_F_ALL != 0 { return Err(ParseError::Malformed); }
    let addr_sel = flags & (NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR);
    if addr_sel == 0 || addr_sel == (NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR) {
        return Err(ParseError::Malformed);
    }
    if flags & (NFTA_FIB_F_IIF | NFTA_FIB_F_OIF) == (NFTA_FIB_F_IIF | NFTA_FIB_F_OIF) {
        return Err(ParseError::Malformed);
    }
    let mut width = match result {
        NFT_FIB_RESULT_OIF => {
            if flags & NFTA_FIB_F_OIF != 0 { return Err(ParseError::Malformed); }
            4
        }
        NFT_FIB_RESULT_OIFNAME => {
            if flags & NFTA_FIB_F_OIF != 0 { return Err(ParseError::Malformed); }
            IFNAMSIZ
        }
        NFT_FIB_RESULT_ADDRTYPE => 4,
        _ => return Err(ParseError::Malformed),
    };
    if flags & NFTA_FIB_F_PRESENT != 0 {
        if result != NFT_FIB_RESULT_OIF { return Err(ParseError::Malformed); }
        width = 1;
    }
    if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    Ok(Expr::Fib { dreg, result, flags })
}

/// Byte width one socket key writes. # C: O(1)
pub fn socket_width(key: u32) -> Option<usize> {
    Some(match key {
        NFT_SOCKET_TRANSPARENT | NFT_SOCKET_WILDCARD => 1,
        NFT_SOCKET_MARK => 4,
        NFT_SOCKET_CGROUPV2 => 8,
        _ => return None,
    })
}

/// # C: O(len(d))
pub fn socket(d: &[u8]) -> Parsed {
    let key = need(find_u32_be(d, NFTA_SOCKET_KEY))?;
    let dreg = need(find_u32_be(d, NFTA_SOCKET_DREG))?;
    let width = socket_width(key).ok_or(ParseError::Unsupported)?;
    let level = match key {
        NFT_SOCKET_CGROUPV2 => need(find_u32_be(d, NFTA_SOCKET_LEVEL))?,
        _ => {
            if find_u32_be(d, NFTA_SOCKET_LEVEL).is_some() {
                return Err(ParseError::Malformed);
            }
            0
        }
    };
    if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    Ok(Expr::Socket { dreg, key, level })
}

/// # C: O(len(d))
pub fn osf(d: &[u8]) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_OSF_DREG))?;
    let ttl = find_u8(d, NFTA_OSF_TTL).unwrap_or(NF_OSF_TTL_TRUE);
    if ttl > NF_OSF_TTL_NOCHECK { return Err(ParseError::Malformed); }
    let flags = find_u32_be(d, NFTA_OSF_FLAGS).unwrap_or(0);
    if flags & !NFT_OSF_F_VERSION != 0 { return Err(ParseError::Malformed); }
    if !register_load_valid(dreg, NFT_OSF_MAXGENRELEN) { return Err(ParseError::Malformed); }
    Ok(Expr::Osf { dreg, ttl, flags })
}

/// Deepest transform an `xfrm` expression may index.
const XFRM_MAX_DEPTH: u32 = 6;

/// Byte width one transform key writes. # C: O(1)
pub fn xfrm_width(key: u32) -> Option<usize> {
    Some(match key {
        NFT_XFRM_KEY_DADDR_IP4 | NFT_XFRM_KEY_SADDR_IP4 | NFT_XFRM_KEY_REQID
        | NFT_XFRM_KEY_SPI => 4,
        NFT_XFRM_KEY_DADDR_IP6 | NFT_XFRM_KEY_SADDR_IP6 => 16,
        _ => return None,
    })
}

/// # C: O(len(d))
pub fn xfrm(d: &[u8]) -> Parsed {
    let dreg = need(find_u32_be(d, NFTA_XFRM_DREG))?;
    let key = need(find_u32_be(d, NFTA_XFRM_KEY))?;
    let dir = need(find_u32_be(d, NFTA_XFRM_DIR))? ;
    if dir > XFRM_POLICY_OUT { return Err(ParseError::Malformed); }
    let spnum = find_u32_be(d, NFTA_XFRM_SPNUM).unwrap_or(0);
    if spnum >= XFRM_MAX_DEPTH { return Err(ParseError::OutOfRange); }
    let width = xfrm_width(key).ok_or(ParseError::Malformed)?;
    if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    Ok(Expr::Xfrm { dreg, key, dir, spnum })
}

/// # C: O(len(d))
pub fn last(d: &[u8], alloc: &mut StateAlloc) -> Parsed {
    let set = find_u32_be(d, NFTA_LAST_SET).unwrap_or(0) != 0;
    let msecs = find_u64_be(d, NFTA_LAST_MSECS).unwrap_or(0);
    Ok(Expr::Last { index: alloc.take_last(), set, msecs })
}

/// Byte width one tunnel key writes. # C: O(1)
pub fn tunnel_width(key: u32) -> Option<usize> {
    Some(match key { NFT_TUNNEL_PATH => 1, NFT_TUNNEL_ID => 4, _ => return None })
}

/// # C: O(len(d))
pub fn tunnel(d: &[u8]) -> Parsed {
    let key = need(find_u32_be(d, NFTA_TUNNEL_KEY))?;
    let dreg = need(find_u32_be(d, NFTA_TUNNEL_DREG))?;
    let mode = find_u32_be(d, NFTA_TUNNEL_MODE).unwrap_or(NFT_TUNNEL_MODE_NONE);
    if mode > NFT_TUNNEL_MODE_MAX { return Err(ParseError::Unsupported); }
    let width = tunnel_width(key).ok_or(ParseError::Unsupported)?;
    if !register_load_valid(dreg, width) { return Err(ParseError::Malformed); }
    Ok(Expr::Tunnel { dreg, key, mode })
}

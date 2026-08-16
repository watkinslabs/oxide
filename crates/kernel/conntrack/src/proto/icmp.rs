//! ICMP / ICMPv6 tracker and the generic fallback. An ICMP flow is a
//! request/reply pair keyed on the id; only the request types that have a
//! reply form may open one, and an error message is never tracked as a flow
//! of its own — it is related to the flow it quotes.

use crate::tuple::{Tuple, icmp_valid_new};
use crate::uapi::NFPROTO_IPV6;

/// Default ICMP/ICMPv6 timeout, seconds.
pub const ICMP_TIMEOUT: u32 = 30;
/// Default timeout for protocols with no tracker of their own, seconds.
pub const GENERIC_TIMEOUT: u32 = 600;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IcmpSysctl { pub timeout: u32 }
impl Default for IcmpSysctl { fn default() -> Self { Self { timeout: ICMP_TIMEOUT } } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GenericSysctl { pub timeout: u32 }
impl Default for GenericSysctl { fn default() -> Self { Self { timeout: GENERIC_TIMEOUT } } }

/// ICMPv4 error types that quote an inner packet.
const ICMP_ERROR_TYPES: &[u8] = &[3, 4, 5, 11, 12];
/// ICMPv6 error types that quote an inner packet.
const ICMPV6_ERROR_TYPES: &[u8] = &[1, 2, 3, 4];

/// Whether this message quotes another packet, making it RELATED to that
/// packet's flow rather than a flow of its own. # C: O(1)
pub fn is_error(l3num: u8, icmp_type: u8) -> bool {
    let set = if l3num == NFPROTO_IPV6 { ICMPV6_ERROR_TYPES } else { ICMP_ERROR_TYPES };
    set.contains(&icmp_type)
}

/// Track one ICMP packet. `None` means the message cannot open a flow: the
/// packet must be treated as invalid rather than tracked, or an unsolicited
/// echo *reply* would create an entry that a later real request would match.
/// # C: O(1)
pub fn packet(tuple: &Tuple, confirmed: bool, sysctl: &IcmpSysctl) -> Option<u32> {
    if !confirmed && !icmp_valid_new(tuple.l3num, tuple.dst.proto.icmp_type) {
        return None;
    }
    Some(sysctl.timeout)
}

/// Track one packet of a protocol with no dedicated tracker. # C: O(1)
pub fn generic_packet(sysctl: &GenericSysctl) -> u32 { sysctl.timeout }

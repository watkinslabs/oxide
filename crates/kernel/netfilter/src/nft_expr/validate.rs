//! Load-time refusal of rules that could never fire.
//!
//! An expression attached to a hook that runs after the decision it wants to
//! influence, or to a family whose packets it cannot read, is a silent
//! no-op. The reference rejects those at configuration time and so do we.

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::flags::{NFTA_FIB_F_IIF, NFTA_FIB_F_OIF};
use crate::nft_expr::uapi::*;

/// Hook bitmask helper — hooks are small dense numbers. # C: O(1)
const fn bit(hook: u8) -> u32 { 1u32 << hook }

const HOOKS_NAT_SNAT: u32 = bit(NF_INET_POST_ROUTING) | bit(NF_INET_LOCAL_IN);
const HOOKS_NAT_DNAT: u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_OUT);
const HOOKS_MASQ:     u32 = bit(NF_INET_POST_ROUTING);
const HOOKS_REDIR:    u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_OUT);
const HOOKS_REJECT:   u32 = bit(NF_INET_LOCAL_IN) | bit(NF_INET_FORWARD)
    | bit(NF_INET_LOCAL_OUT) | bit(NF_INET_PRE_ROUTING);
const HOOKS_REJECT_INET: u32 = HOOKS_REJECT | bit(NF_INET_INGRESS);
const HOOKS_QUEUE: u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_IN)
    | bit(NF_INET_FORWARD) | bit(NF_INET_LOCAL_OUT) | bit(NF_INET_POST_ROUTING);
const HOOKS_FWD_NETDEV: u32 = bit(NF_NETDEV_INGRESS) | bit(NF_NETDEV_EGRESS);
const HOOKS_FLOW:    u32 = bit(NF_INET_FORWARD);
const HOOKS_TCPMSS:  u32 = bit(NF_INET_FORWARD) | bit(NF_INET_LOCAL_OUT)
    | bit(NF_INET_POST_ROUTING);
const HOOKS_SOCKET:  u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_IN)
    | bit(NF_INET_LOCAL_OUT);
const HOOKS_TPROXY:   u32 = bit(NF_INET_PRE_ROUTING);
const HOOKS_NOTRACK:  u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_OUT);
const HOOKS_SYNPROXY: u32 = bit(NF_INET_LOCAL_IN) | bit(NF_INET_FORWARD);
const HOOKS_XFRM_IN:  u32 = bit(NF_INET_FORWARD) | bit(NF_INET_LOCAL_IN)
    | bit(NF_INET_PRE_ROUTING);
const HOOKS_XFRM_OUT: u32 = bit(NF_INET_FORWARD) | bit(NF_INET_LOCAL_OUT)
    | bit(NF_INET_POST_ROUTING);
const HOOKS_FIB_IN:   u32 = bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_IN)
    | bit(NF_INET_FORWARD);
const HOOKS_FIB_OUT:  u32 = bit(NF_INET_LOCAL_OUT) | bit(NF_INET_POST_ROUTING)
    | bit(NF_INET_FORWARD);
const HOOKS_FIB_ANY:  u32 = HOOKS_FIB_IN | HOOKS_FIB_OUT;

/// Whether a family carries routable inet packets. # C: O(1)
fn inet_family(family: u8) -> bool {
    matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET)
}

/// Whether a family reaches a queue — a netdev chain has no continuation to
/// return the packet to. # C: O(1)
fn queue_family(family: u8) -> bool {
    matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET | NFPROTO_BRIDGE)
}

/// # C: O(1)
fn hooks_allow(hook: u8, mask: u32) -> Result<(), ParseError> {
    if hook >= u32::BITS as u8 || mask & bit(hook) == 0 { return Err(ParseError::WrongHook); }
    Ok(())
}

/// # C: O(1)
fn family_allows(ok: bool) -> Result<(), ParseError> {
    if ok { Ok(()) } else { Err(ParseError::Unsupported) }
}

/// Refuse one expression on a chain it can never act from. # C: O(1)
pub fn validate_expr(expr: &Expr, family: u8, hook: u8) -> Result<(), ParseError> {
    match expr {
        Expr::Nat { nat_type, .. } => hooks_allow(hook, match *nat_type {
            NFT_NAT_SNAT => HOOKS_NAT_SNAT,
            NFT_NAT_DNAT => HOOKS_NAT_DNAT,
            _ => return Err(ParseError::Malformed),
        }),
        Expr::Masq { .. }  => hooks_allow(hook, HOOKS_MASQ),
        Expr::Redir { .. } => hooks_allow(hook, HOOKS_REDIR),
        Expr::Reject { .. } => hooks_allow(hook, if family == NFPROTO_INET {
            HOOKS_REJECT_INET
        } else {
            HOOKS_REJECT
        }),
        Expr::Queue { .. } => {
            family_allows(queue_family(family))?;
            hooks_allow(hook, HOOKS_QUEUE)
        }
        Expr::Fwd { .. } => {
            family_allows(family == NFPROTO_NETDEV)?;
            hooks_allow(hook, HOOKS_FWD_NETDEV)
        }
        Expr::FlowOffload { .. } => {
            family_allows(inet_family(family))?;
            hooks_allow(hook, HOOKS_FLOW)
        }
        Expr::Rt { key, .. } => {
            family_allows(inet_family(family))?;
            match *key {
                NFT_RT_CLASSID | NFT_RT_NEXTHOP4 | NFT_RT_NEXTHOP6 | NFT_RT_XFRM => Ok(()),
                NFT_RT_TCPMSS => hooks_allow(hook, HOOKS_TCPMSS),
                _ => Err(ParseError::Malformed),
            }
        }
        Expr::Socket { .. } => hooks_allow(hook, HOOKS_SOCKET),
        Expr::Notrack => hooks_allow(hook, HOOKS_NOTRACK),
        Expr::Tproxy { .. } => {
            family_allows(inet_family(family))?;
            hooks_allow(hook, HOOKS_TPROXY)
        }
        Expr::Synproxy { .. } => hooks_allow(hook, HOOKS_SYNPROXY),
        Expr::Xfrm { dir, .. } => {
            family_allows(inet_family(family))?;
            hooks_allow(hook, match *dir {
                XFRM_POLICY_IN  => HOOKS_XFRM_IN,
                XFRM_POLICY_OUT => HOOKS_XFRM_OUT,
                _ => return Err(ParseError::Malformed),
            })
        }
        Expr::Fib { result, flags, .. } => {
            family_allows(inet_family(family))?;
            hooks_allow(hook, match *result {
                NFT_FIB_RESULT_OIF | NFT_FIB_RESULT_OIFNAME => HOOKS_FIB_IN,
                NFT_FIB_RESULT_ADDRTYPE => {
                    if flags & NFTA_FIB_F_IIF != 0 { HOOKS_FIB_IN }
                    else if flags & NFTA_FIB_F_OIF != 0 { HOOKS_FIB_OUT }
                    else { HOOKS_FIB_ANY }
                }
                _ => return Err(ParseError::Malformed),
            })
        }
        _ => Ok(()),
    }
}

/// Refuse a whole rule that carries an expression its chain cannot run.
/// # C: O(N exprs)
pub fn validate_exprs(exprs: &[Expr], family: u8, hook: u8) -> Result<(), ParseError> {
    for expr in exprs { validate_expr(expr, family, hook)?; }
    Ok(())
}

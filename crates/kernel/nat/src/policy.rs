//! Masquerade and redirect: the two bindings whose range is not supplied by
//! the rule but computed from the routing decision. Both reduce to an ordinary
//! single-address range once the address is known, so the interesting part is
//! how that address is chosen and when the choice goes stale.

use conntrack::tuple::InetAddr;

use crate::range::NatRange;
use crate::uapi::*;

/// Why masquerade could not pick an address.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// The egress interface has no address of the right family.
    NoAddress,
    /// The rule is attached to a hook where the manipulation makes no sense.
    WrongHook,
}

/// Build the masquerade range for a flow leaving on an interface whose chosen
/// source address is `src`. The requested port range, if any, is preserved:
/// a rule may masquerade into a specific port window.
///
/// Masquerade is a source translation and only makes sense after routing has
/// chosen the egress interface, so it is refused at any other hook.
/// # C: O(1)
pub fn masquerade_range(hook: u8, src: Option<InetAddr>, requested: &NatRange)
    -> Result<NatRange, PolicyError>
{
    if hook != NF_INET_POST_ROUTING { return Err(PolicyError::WrongHook); }
    let Some(src) = src else { return Err(PolicyError::NoAddress); };
    Ok(NatRange {
        flags: requested.flags | NF_NAT_RANGE_MAP_IPS,
        min_addr: src, max_addr: src,
        min_proto: requested.min_proto, max_proto: requested.max_proto,
        base_proto: requested.base_proto,
    })
}

/// Address a redirect sends a packet to. On the output path the destination
/// becomes loopback, because the packet has not left the host and the socket
/// it is being handed to is local. On the input path it becomes the primary
/// address of the receiving interface — the address the client could plausibly
/// have been talking to.
/// # C: O(1)
pub fn redirect_addr(hook: u8, l3num: u8, iface_addr: Option<InetAddr>)
    -> Result<InetAddr, PolicyError>
{
    use conntrack::uapi::NFPROTO_IPV6;
    match hook {
        NF_INET_LOCAL_OUT => Ok(if l3num == NFPROTO_IPV6 {
            let mut a = [0u8; 16]; a[15] = 1; InetAddr::v6(a)
        } else {
            InetAddr::v4([127, 0, 0, 1])
        }),
        NF_INET_PRE_ROUTING => iface_addr.ok_or(PolicyError::NoAddress),
        _ => Err(PolicyError::WrongHook),
    }
}

/// Build the redirect range. # C: O(1)
pub fn redirect_range(hook: u8, l3num: u8, iface_addr: Option<InetAddr>,
                      requested: &NatRange) -> Result<NatRange, PolicyError>
{
    let dst = redirect_addr(hook, l3num, iface_addr)?;
    Ok(NatRange {
        flags: requested.flags | NF_NAT_RANGE_MAP_IPS,
        min_addr: dst, max_addr: dst,
        min_proto: requested.min_proto, max_proto: requested.max_proto,
        base_proto: requested.base_proto,
    })
}

/// Validation for a rule attaching one manipulation to one hook. A source
/// translation at pre-routing, or a destination translation at post-routing,
/// runs after the decision it is trying to influence and silently does
/// nothing — so it is refused at configuration time rather than at runtime.
/// # C: O(1)
pub fn hook_allows_manip(hook: u8, manip: u8) -> bool {
    match manip {
        NF_NAT_MANIP_SRC => hook == NF_INET_POST_ROUTING || hook == NF_INET_LOCAL_IN,
        _ => hook == NF_INET_PRE_ROUTING || hook == NF_INET_LOCAL_OUT,
    }
}

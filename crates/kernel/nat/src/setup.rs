//! Establishing a binding on a flow, and replaying it on every later packet.
//! The decision happens exactly once, on the first packet; re-deciding later
//! would let a ruleset edit split one conversation across two translations.

extern crate alloc;
use alloc::sync::Arc;

use conntrack::entry::Conn;
use conntrack::tuple::Tuple;
use conntrack::uapi::*;

use crate::range::NatRange;
use crate::unique::{NatEnv, get_unique_tuple};
use crate::uapi::*;

/// Result of establishing a binding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetupResult {
    /// Binding recorded (or already present); let the packet through.
    Accept,
    /// No free tuple could be found; the flow cannot be translated.
    Drop,
}

/// Whether a manipulation has already been decided for this flow. # C: O(1)
pub fn initialized(status: u32, manip: u8) -> bool {
    let bit = if manip == NF_NAT_MANIP_SRC { IPS_SRC_NAT_DONE } else { IPS_DST_NAT_DONE };
    status & bit != 0
}

/// Status bit set once a manipulation is decided. # C: O(1)
pub fn done_bit(manip: u8) -> u32 {
    if manip == NF_NAT_MANIP_SRC { IPS_SRC_NAT_DONE } else { IPS_DST_NAT_DONE }
}

/// Status bit recording that a manipulation actually changes something. # C: O(1)
pub fn manip_bit(manip: u8) -> u32 {
    if manip == NF_NAT_MANIP_SRC { IPS_SRC_NAT } else { IPS_DST_NAT }
}

/// Establish a binding. The entry must not be confirmed yet: the table is
/// keyed on both tuples, so the reply half can only be rewritten before it is
/// published.
/// # C: O(NAT_MAX_ATTEMPTS · bucket length)
pub fn setup_info<E: NatEnv>(conn: &Conn, r: &NatRange, manip: u8, env: &E)
    -> SetupResult
{
    if conn.confirmed() { return SetupResult::Accept; }
    if initialized(conn.status(), manip) { return SetupResult::Drop; }

    // What the flow currently looks like in the manipulated direction is the
    // inverse of its reply half, not its stored original — a previous
    // manipulation may already have moved it.
    let Some(current) = conn.reply_tuple().invert() else { return SetupResult::Drop; };
    let Some(chosen) = get_unique_tuple(&current, r, manip, env) else {
        return SetupResult::Drop;
    };

    if chosen != current {
        let Some(reply) = chosen.invert() else { return SetupResult::Drop; };
        if !conn.alter_reply(reply) { return SetupResult::Drop; }
        conn.set_status_bits(manip_bit(manip));
    }
    conn.set_status_bits(done_bit(manip));
    SetupResult::Accept
}

/// The identity binding installed when a NAT chain ran and decided nothing.
/// It pins the flow's addresses to what conntrack already computed while
/// still letting the allocator resolve a port collision — which is why it is
/// not simply "do nothing": two clients behind one address can pick the same
/// source port, and without a binding the second flow is unroutable.
/// # C: O(NAT_MAX_ATTEMPTS · bucket length)
pub fn alloc_null_binding<E: NatEnv>(conn: &Conn, manip: u8, env: &E) -> SetupResult {
    let reply = conn.reply_tuple();
    let addr = if manip == NF_NAT_MANIP_SRC { reply.dst.addr } else { reply.src.addr };
    let r = NatRange::single_addr(addr, 0);
    setup_info(conn, &r, manip, env)
}

/// Which manipulation a packet needs, given the hook it is at and the
/// direction it is flowing.
///
/// A reply is translated by the OPPOSITE manipulation to the one the flow was
/// bound with: a source-translated flow's replies have their DESTINATION put
/// back. Getting this inversion wrong applies the original translation to the
/// reply, which sends it to the wrong host.
/// # C: O(1)
pub fn packet_manip_bit(hook: u8, dir: u8) -> u32 {
    let manip = hook_to_manip(hook);
    let mut bit = manip_bit(manip);
    if dir == IP_CT_DIR_REPLY { bit ^= IPS_NAT_MASK; }
    bit
}

/// Whether this packet gets translated at all at this hook. # C: O(1)
pub fn packet_needs_manip(status: u32, hook: u8, dir: u8) -> bool {
    status & packet_manip_bit(hook, dir) != 0
}

/// The tuple a packet must be rewritten to present.
///
/// It is the inverse of the OTHER direction's tuple: whatever the peer on the
/// far side expects to see. Deriving it from this direction's own tuple
/// instead is a no-op that quietly disables translation.
/// # C: O(1)
pub fn target_tuple(conn: &Conn, dir: u8) -> Option<Tuple> {
    let other = if dir == IP_CT_DIR_REPLY { conn.orig } else { conn.reply_tuple() };
    other.invert()
}

/// Whether a masquerade binding is still valid. The chosen source address
/// belongs to one egress interface; once the route moves, the binding is
/// wrong and the flow must be rebuilt rather than translated to an address
/// that no longer belongs to us.
/// # C: O(1)
pub fn masq_still_valid(conn: &Arc<Conn>, out_ifindex: u32) -> bool {
    let recorded = conn.nat.lock().masq_index;
    recorded == 0 || recorded == out_ifindex
}

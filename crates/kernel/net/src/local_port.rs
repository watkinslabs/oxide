// The two local-port decisions a bind makes, in one owner: which ephemeral
// window is in effect for this socket, and whether the bind allocates a port
// at all.
//
// No target gate: the decision logic must run under hosted `cargo test`.

use crate::ephemeral::Range;

/// The packed `IP_LOCAL_PORT_RANGE` word of a socket that named no window of
/// its own, and so allocates from the namespace's. # C: O(1)
pub const NAMESPACE_WINDOW: u32 = 0;

/// The ephemeral window in effect: the socket's own `IP_LOCAL_PORT_RANGE` when
/// it named one, the namespace's `ip_local_port_range` otherwise. A half-open
/// request keeps the namespace bound on the side the caller left zero. An
/// inverted or degenerate result falls back to the namespace window, which is
/// the only one the namespace guarantees valid. # C: O(1)
pub fn effective_range(packed: u32, ns: Range) -> Range {
    let (lo, hi) = effective_bounds(packed, (ns.start, ns.end));
    Range::new(lo, hi).unwrap_or(ns)
}

/// The two bounds `effective_range` resolves, as the option's own packed word
/// exposes them. # C: O(1)
pub fn effective_bounds(packed: u32, ns: (u16, u16)) -> (u16, u16) {
    let (lo, hi) = (packed as u16, (packed >> 16) as u16);
    if lo == 0 && hi == 0 { return ns; }
    (if lo == 0 { ns.0 } else { lo }, if hi == 0 { ns.1 } else { hi })
}

/// Whether a bind defers its port allocation to connect time. Linux allocates
/// unless the caller both left the port unnamed and asked for
/// `IP_BIND_ADDRESS_NO_PORT`; naming a port always allocates it. # C: O(1)
pub fn defers_port(requested_port: u16, bind_address_no_port: bool) -> bool {
    requested_port == 0 && bind_address_no_port
}

/// The window in effect for a live namespace and a socket's packed request.
/// # C: O(log N)
pub fn range_in(ns: u64, packed: u32) -> Option<Range> {
    Some(effective_range(packed, crate::ephemeral::range_in(ns)?))
}

#[cfg(test)]
mod tests;

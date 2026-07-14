use crate::addr::{Ipv6Addr, NetIfaceId};

use super::types::{Raw6Address, Raw6State};

pub(super) struct MatchInput {
    pub net_ns: u64,
    pub protocol: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub iface: NetIfaceId,
}

pub(super) fn tuple_matches(endpoint_ns: u64, endpoint_protocol: u8,
                            state: &Raw6State, input: &MatchInput) -> bool {
    if !state.accepting || endpoint_ns != input.net_ns || endpoint_protocol != input.protocol {
        return false;
    }
    if state.bound_iface.is_some_and(|iface| iface != input.iface) { return false; }
    if !address_matches(state.local, input.dst, input.iface) { return false; }
    if state.peer.is_some_and(|peer| !address_matches(peer, input.src, input.iface)) {
        return false;
    }
    true
}

fn address_matches(bound: Raw6Address, packet: Ipv6Addr, iface: NetIfaceId) -> bool {
    if !bound.addr.is_unspecified() && bound.addr != packet { return false; }
    bound.scope_id == 0 || bound.scope_id == iface.raw()
}

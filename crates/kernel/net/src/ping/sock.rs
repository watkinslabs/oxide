// Endpoint lifecycle for ICMP datagram sockets: creation admission, identifier
// acquisition at bind and at first transmit, and identifier release at close.

use alloc::sync::Arc;
use network_namespace::NetworkNamespaceRef;

use crate::netdev::NetError;
use crate::stack::NetStack;

use super::group::{self, CallerGroups};
use super::ident::{PingIdent, PingSock, PingTable};
use super::validate::PingFamily;

/// Snapshot the group window one namespace publishes. # C: O(log N)
pub fn group_range_for(namespace: &NetworkNamespaceRef) -> Option<(u32, u32)> {
    crate::net_ns::state_for(namespace).map(|state| state.ping_group.get())
}

/// Replace the group window one namespace publishes. # C: O(log N)
pub fn set_group_range_for(namespace: &NetworkNamespaceRef, low: u32, high: u32)
    -> Result<(), ()>
{
    let state = crate::net_ns::state_for(namespace).ok_or(())?;
    state.ping_group.set(low, high);
    Ok(())
}

/// Whether this caller may create an ICMP datagram endpoint in `namespace`.
/// Membership of the window is the only admission: the endpoint class exists so
/// that unprivileged callers can send echo probes without the raw-socket
/// capability, and holding that capability does not substitute for membership.
/// # C: O(ngroups)
pub fn admits(namespace: &NetworkNamespaceRef, caller: CallerGroups<'_>) -> bool {
    let range = crate::net_ns::materialize_state(namespace).ping_group.get();
    group::admits(range, caller)
}

impl NetStack {
    /// Resolve the identifier table owning one namespace. # C: O(log N)
    pub fn ping_table(&self, net_ns: u64) -> Option<Arc<PingTable>> {
        self.try_inet_tables(net_ns).map(|tables| Arc::clone(&tables.ping))
    }
}

/// Acquire `requested` for one IPv4 endpoint, allocating when it is zero.
/// # C: O(N)
pub fn bind_v4(endpoint: &Arc<crate::raw4::Raw4Endpoint>, requested: u16) -> Result<u16, NetError> {
    let owner = endpoint.ping.as_ref().ok_or(NetError::Einval)?;
    let table = crate::global_stack().ping_table(endpoint.net_ns()).ok_or(NetError::Enodev)?;
    table.bind(owner, PingSock::V4(Arc::downgrade(endpoint)), requested)
}

/// Acquire `requested` for one IPv6 endpoint, allocating when it is zero.
/// # C: O(N)
pub fn bind_v6(endpoint: &Arc<crate::raw6::Raw6Endpoint>, requested: u16) -> Result<u16, NetError> {
    let owner = endpoint.ping.as_ref().ok_or(NetError::Einval)?;
    let table = crate::global_stack().ping_table(endpoint.net_ns()).ok_or(NetError::Enodev)?;
    table.bind(owner, PingSock::V6(Arc::downgrade(endpoint)), requested)
}

/// Identifier already owned, or one freshly allocated for this transmit.
/// # C: O(N)
pub fn autobind_v4(endpoint: &Arc<crate::raw4::Raw4Endpoint>) -> Result<u16, NetError> {
    let owner = endpoint.ping.as_ref().ok_or(NetError::Einval)?;
    match owner.ident() {
        super::ident::UNBOUND => bind_v4(endpoint, super::ident::UNBOUND),
        ident => Ok(ident),
    }
}

/// Identifier already owned, or one freshly allocated for this transmit.
/// # C: O(N)
pub fn autobind_v6(endpoint: &Arc<crate::raw6::Raw6Endpoint>) -> Result<u16, NetError> {
    let owner = endpoint.ping.as_ref().ok_or(NetError::Einval)?;
    match owner.ident() {
        super::ident::UNBOUND => bind_v6(endpoint, super::ident::UNBOUND),
        ident => Ok(ident),
    }
}

/// Release the identifier one endpoint owns. # C: O(N)
pub fn release(owner: &Arc<PingIdent>, net_ns: u64) {
    if let Some(table) = crate::global_stack().ping_table(net_ns) { table.unbind(owner); }
}

/// Build the kernel-owned identifier state for a new endpoint. # C: O(1)
pub fn new_ident(family: PingFamily, reuse: Arc<core::sync::atomic::AtomicI32>)
    -> Arc<PingIdent>
{
    PingIdent::new(family, reuse)
}

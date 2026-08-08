extern crate alloc;

#[cfg(test)]
use alloc::sync::Arc;

use network_namespace::NetworkNamespaceRef;

#[cfg(test)]
use crate::LoopbackDev;
use crate::NetStack;

use super::materialize_state;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CreateError {
    /// A different subsystem attempted to own final-drop notification.
    CallbackConflict,
    /// Boot could not start the process-context namespace teardown worker.
    ReaperUnavailable,
    /// Canonical namespace identity allocation failed.
    Allocation(network_namespace::AllocError),
}

/// Clone the calling task's concrete network namespace owner. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn current_namespace() -> NetworkNamespaceRef {
    sched::live::current().and_then(|task| task.network_namespace_snapshot())
        .unwrap_or_else(network_namespace::initial)
}

/// Hosted callers execute in the initial network namespace. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_namespace() -> NetworkNamespaceRef {
    network_namespace::initial()
}

/// Derive the short-lived table key for a retained namespace owner. # C: O(1)
pub fn namespace_id(namespace: &NetworkNamespaceRef) -> u64 { namespace.id().as_u64() }

/// `net_cookie`: the namespace's global namespace-tree identity, which is what
/// `SO_NETNS_COOKIE` reports. It is NOT the stack-internal namespace index —
/// that one is zero for the initial namespace, and the reference's cookie is
/// never zero for any namespace. # C: O(1)
pub fn namespace_cookie(namespace: &NetworkNamespaceRef) -> u64 { namespace.ns_id() }

/// Clone the immortal initial network namespace owner. # C: O(log N)
pub fn initial_namespace() -> NetworkNamespaceRef { network_namespace::initial() }

/// Register `lo` (UP, 127.0.0.1/8) into `ifaces` under `ns` — the ONLY
/// iface a `CLONE_NEWNET` task sees, matching Linux's empty-but-for-lo
/// fresh netns. Idempotent; a no-op for id 0. Target-agnostic seam so
/// hosted tests can drive every address and route owner in a private stack.
/// # C: O(N ifaces)
pub fn materialize_loopback_into(stack: &NetStack, namespace: &NetworkNamespaceRef) {
    let ns = namespace_id(namespace);
    if ns == 0 { return; }
    let state = materialize_state(namespace);
    let rtnl = stack.rtnl_lock();
    if state.loopback.lock().is_some() { return; }
    let (id, lo, ticket) = stack.register_loopback_in_rtnl(&rtnl, namespace);
    *state.loopback.lock() = Some((id, lo));
    drop(rtnl);
    crate::control_event::publish(ticket);
}

/// Give a freshly-created non-zero net_ns its loopback interface in the
/// global `NetStack`'s (ns-keyed) iface registry. Kernel-side wrapper
/// over `materialize_loopback_into`. # C: O(N ifaces)
#[cfg(target_os = "oxide-kernel")]
pub fn materialize_loopback(namespace: &NetworkNamespaceRef) {
    materialize_loopback_into(crate::global_stack(), namespace);
}

/// Create a fully materialized namespace before task publication. # C: O(N ifaces)
#[cfg(target_os = "oxide-kernel")]
pub fn create_namespace(owner_user_namespace: namespace_identity::NamespacePin)
    -> Result<NetworkNamespaceRef, CreateError>
{
    if !super::teardown::reaper_ready() { return Err(CreateError::ReaperUnavailable); }
    super::install_final_drop_pending_notifier().map_err(|_| CreateError::CallbackConflict)?;
    let namespace = network_namespace::allocate(owner_user_namespace)
        .map_err(CreateError::Allocation)?;
    materialize_loopback(&namespace);
    Ok(namespace)
}

/// One private-loopback drain paired with the concrete namespace owner.
///
/// Test support only. Receive delivery reaches a namespace loopback through
/// this stack's NET_RX poll list now (`stack::rx_backlog`), registered when the
/// device is created; walking the namespace registry from the bottom half to
/// rediscover the same devices would be a second, disagreeing source of truth
/// for "what has frames waiting". What the remaining users cover is the
/// lease-retention contract during namespace teardown, which is unchanged.
#[cfg(test)]
pub(crate) struct PrivateLoopback {
    lease: crate::IngressLease,
    dev: Arc<LoopbackDev>,
}

#[cfg(test)]
impl PrivateLoopback {
    /// Dispatch the snapshotted queue while retaining its namespace owner. # C: O(N pending)
    pub(crate) fn drain_into(self, stack: &NetStack) {
        stack.drain_loopback_in(&self.lease, &self.dev);
    }

    #[cfg(test)]
    pub(crate) fn namespace(&self) -> NetworkNamespaceRef { self.lease.namespace() }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 { self.lease.generation() }
}

/// Snapshot owner-retained private loopback queues. Test support only; see
/// [`PrivateLoopback`]. # C: O(N_ns)
#[cfg(test)]
pub(crate) fn private_loopbacks(stack: &NetStack) -> alloc::vec::Vec<PrivateLoopback> {
    namespace_identity::active_kind_page(namespace_identity::NamespaceKind::Net,
        namespace_identity::NsId::from_u64(0), usize::MAX).into_iter().filter_map(|identity| {
        let owner = network_namespace::lookup_u64(identity.id().as_u64())?;
        let state = super::state_for(&owner)?;
        let (iface, dev) = state.loopback.lock().clone()?;
        let lease = stack.ifaces.acquire_ingress(iface)?;
        if lease.net_ns() != owner.id().as_u64() { return None; }
        Some(PrivateLoopback { lease, dev })
    }).collect()
}

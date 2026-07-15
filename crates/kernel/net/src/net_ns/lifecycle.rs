extern crate alloc;

use alloc::sync::Arc;

use network_namespace::NetworkNamespaceRef;

use crate::{LoopbackDev, NetStack};

use super::{NET_NS, materialize_state};

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
pub fn create_namespace(owner_user_ns: u64) -> Result<NetworkNamespaceRef, CreateError> {
    if !super::teardown::reaper_ready() { return Err(CreateError::ReaperUnavailable); }
    super::install_final_drop_pending_notifier().map_err(|_| CreateError::CallbackConflict)?;
    let namespace = network_namespace::allocate(owner_user_ns).map_err(CreateError::Allocation)?;
    materialize_loopback(&namespace);
    Ok(namespace)
}

/// Snapshot retained private loopback queues for network RX draining. # C: O(N_ns)
pub(crate) fn private_loopbacks() -> alloc::vec::Vec<(crate::NetIfaceId, Arc<LoopbackDev>)> {
    NET_NS.lock().values().filter_map(|state| state.loopback.lock().clone()).collect()
}

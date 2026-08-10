// The namespace-facing half of the metrics cache. A destination is only
// reachable through the namespace that routed to it, so what this host learned
// about one is namespace state.

use network_namespace::NetworkNamespaceRef;

use crate::addr::IpAddr;

/// What this namespace remembers about one destination's path. # C: O(log N)
pub fn cached(namespace: &NetworkNamespaceRef, src: IpAddr, dst: IpAddr) -> super::init::CachedMetrics {
    crate::net_ns::materialize_state(namespace).metrics_cache.cached(src, dst)
}

/// Whether a previous connection from this namespace proved the destination
/// reachable. A namespace that has never spoken to it vouches for nobody,
/// which is the answer the reference gives for a peer its own cache has never
/// held. # C: O(log N)
pub fn peer_is_proven(net_ns: u64, src: IpAddr, dst: IpAddr) -> bool {
    crate::net_ns::state_by_id(net_ns)
        .is_some_and(|state| state.metrics_cache.peer_is_proven(src, dst))
}

/// What a live namespace remembers about one destination's path, without
/// creating namespace state for a namespace that has none. # C: O(log N)
pub fn cached_in(net_ns: u64, src: IpAddr, dst: IpAddr) -> super::init::CachedMetrics {
    crate::net_ns::state_by_id(net_ns)
        .map(|state| state.metrics_cache.cached(src, dst))
        .unwrap_or_default()
}

/// Fold one closing connection's measurements into a live namespace's row.
/// # C: O(log N)
pub fn record_in(net_ns: u64, src: IpAddr, dst: IpAddr, now_ns: u64,
                 conn: super::update::Closing)
{
    if let Some(state) = crate::net_ns::state_by_id(net_ns) {
        state.metrics_cache.record(src, dst, now_ns, conn);
    }
}

/// Fold one closing connection's measurements into its destination's row.
/// # C: O(log N)
pub fn record(namespace: &NetworkNamespaceRef, src: IpAddr, dst: IpAddr, now_ns: u64,
              conn: super::update::Closing)
{
    crate::net_ns::materialize_state(namespace).metrics_cache.record(src, dst, now_ns, conn);
}

/// Administrative write of one destination's metrics in a live namespace.
/// # C: O(log N)
pub fn pin_in(net_ns: u64, src: IpAddr, dst: IpAddr, now_ns: u64,
              vals: [Option<u32>; super::ids::COUNT])
{
    if let Some(state) = crate::net_ns::state_by_id(net_ns) {
        state.metrics_cache.pin(src, dst, now_ns, vals);
    }
}

/// Drop every row a live namespace holds. # C: O(log N)
pub fn forget_all_in(net_ns: u64) {
    if let Some(state) = crate::net_ns::state_by_id(net_ns) { state.metrics_cache.forget_all(); }
}

/// Administrative write of one destination's metrics. # C: O(log N)
pub fn pin(namespace: &NetworkNamespaceRef, src: IpAddr, dst: IpAddr, now_ns: u64,
           vals: [Option<u32>; super::ids::COUNT])
{
    crate::net_ns::materialize_state(namespace).metrics_cache.pin(src, dst, now_ns, vals);
}

/// The live metrics row for one destination. # C: O(log N)
pub fn row(namespace: &NetworkNamespaceRef, src: Option<IpAddr>, dst: IpAddr, now_ns: u64)
    -> Option<super::store::Metrics>
{
    crate::net_ns::materialize_state(namespace).metrics_cache.metrics(src, dst, now_ns)
}

/// Drop one destination's row. Reports whether anything was held. # C: O(log N)
pub fn forget(namespace: &NetworkNamespaceRef, src: Option<IpAddr>, dst: IpAddr) -> bool {
    crate::net_ns::materialize_state(namespace).metrics_cache.forget(src, dst)
}

/// Drop every row this namespace holds. # C: O(log N)
pub fn forget_all(namespace: &NetworkNamespaceRef) {
    crate::net_ns::materialize_state(namespace).metrics_cache.forget_all();
}

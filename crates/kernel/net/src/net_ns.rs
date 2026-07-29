// Per-net_ns (CLONE_NEWNET) isolated network-stack overlay.
//
// Module manifest:
// - lifecycle: current namespace, creation, and loopback materialization.
// - reaper_protocol: final-drop publication and sleep-race transitions.
// - state: namespace overlay state and AF_UNIX registry resolution.
// - teardown: final-drop notification and process-context destruction.
// - test_support: hosted lifecycle-test serialization.
// - tests: namespace state, AF_UNIX isolation, and teardown coverage.
// - lifetime_tests: retained-owner lifetime coverage.

mod lifecycle;
mod reaper_protocol;
mod state;
mod teardown;

pub use lifecycle::{
    CreateError, current_namespace, initial_namespace, materialize_loopback_into, namespace_id,
};
#[cfg(target_os = "oxide-kernel")]
pub use lifecycle::{create_namespace, materialize_loopback};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub(crate) use lifecycle::private_loopbacks;
pub use state::{
    Ipv4ConfDev, Ipv4ConfKey, NetSysctlKey, NsNet, NsNetRef, materialize_state,
    state_by_id, state_for, try_ns_net, unix_path_is_global,
};
#[cfg(target_os = "oxide-kernel")]
pub use state::{
    UnixRegRef, current_unix_registry, ns_unix_registry, unix_ns_for_addr,
    unix_ns_for_addr_in, unix_ns_for_path, unix_registry_for_addr,
    unix_registry_for_addr_in, unix_registry_for_path,
};
#[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
pub use state::unix_registry_for_addr_in;
use state::NET_NS;
pub use teardown::{install_final_drop_pending_notifier, take_final_drop_pending};
#[cfg(test)]
pub(crate) use teardown::destroy_namespace_into;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(target_os = "oxide-kernel")]
pub use teardown::spawn_namespace_reaper;

#[cfg(test)]
#[path = "net_ns/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "net_ns/lifetime_tests.rs"]
mod lifetime_tests;

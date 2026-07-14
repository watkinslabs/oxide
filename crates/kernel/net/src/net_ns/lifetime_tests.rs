use alloc::sync::Arc;

use super::*;
use network_namespace::NetworkNamespaceRef;

fn namespace() -> NetworkNamespaceRef {
    install_final_drop_pending_notifier().expect("install final-drop pending notifier");
    network_namespace::allocate(0).expect("allocate test network namespace")
}

#[test]
fn final_drop_notifier_only_sets_pending_signal() {
    while take_final_drop_pending() {}
    let owner = namespace();
    let id = owner.id();
    drop(owner);
    assert!(take_final_drop_pending());
    assert!(network_namespace::lookup(id).is_none(), "notifier does not retain or reconstruct owner");
}

#[test]
fn hosted_current_namespace_is_the_concrete_initial_owner() {
    let current = current_namespace();
    assert!(Arc::ptr_eq(&current, &network_namespace::initial()));
}

#[test]
fn retained_state_pins_owner_and_dead_id_never_rematerializes() {
    let owner = namespace();
    let id = owner.id();
    let state = materialize_state(&owner);
    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "state reference retains owner");
    drop(state);

    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    assert!(try_ns_net(id.as_u64()).is_none(), "claimed ID cannot rematerialize state");
    NET_NS.lock().remove(&id.as_u64());
    assert!(network_namespace::finish_teardown(id));
    assert!(try_ns_net(id.as_u64()).is_none(), "finished ID cannot rematerialize state");
}

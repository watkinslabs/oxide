use alloc::sync::Arc;

use super::*;

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
